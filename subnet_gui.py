#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Curso: 220259989038A
Grupo: Walter Rene Rosales / Luis Contreras
Subnet Calculator GUI for Windows (Tkinter)
- Enter a CIDR (e.g., 181.79.223.18/16)
- Optionally choose a target prefix (e.g., /24) OR enter desired hosts per subred
- Shows basic network info and a table of generated subnets
- Export table to CSV
"""
import math
import sys
from ipaddress import IPv4Interface, IPv4Network
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_TITLE = "Calculadora de Subneteo - GUI"
APP_SIZE  = "980x650"

def to_hex(ip: str) -> str:
    return ".".join(f"{int(o):02X}" for o in ip.split("."))

def to_bin(ip: str) -> str:
    return ".".join(f"{int(o):08b}" for o in ip.split("."))

def ip_class(first_octet: int) -> str:
    if 1 <= first_octet <= 126:
        return "A"
    if 128 <= first_octet <= 191:
        return "B"
    if 192 <= first_octet <= 223:
        return "C"
    if 224 <= first_octet <= 239:
        return "D (multicast)"
    if 240 <= first_octet <= 255:
        return "E (reservada)"
    return "Desconocida"

def ip_type(ip) -> str:
    if ip.is_private:
        return "IP PRIVADA"
    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_link_local:
        return "LINK-LOCAL"
    if ip.is_multicast:
        return "MULTICAST"
    if ip.is_reserved:
        return "RESERVADA"
    return "IP PÚBLICA"

def usable_host_range(net: IPv4Network):
    hosts = list(net.hosts())
    if not hosts:
        return "-", "-"
    return str(hosts[0]), str(hosts[-1])

def usable_host_count(net: IPv4Network) -> int:
    if net.prefixlen >= 31:
        return net.num_addresses
    return max(0, net.num_addresses - 2)

def prefix_from_hosts(hosts: int) -> int:
    """
    Given desired usable hosts per subnet, approximate the minimal prefix.
    For traditional subnets (>= /30), we need 2 addresses for network/broadcast.
    Special cases: /31 (2 hosts utilizables) and /32 (1 host).
    """
    if hosts <= 0:
        raise ValueError("Hosts por subred debe ser mayor que 0")
    # Try to fit into /31 or /32 first
    if hosts == 1:
        return 32
    if hosts == 2:
        return 31
    # Otherwise include network + broadcast
    total = hosts + 2
    bits = math.ceil(math.log2(total))
    return 32 - bits

class SubnetGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(APP_SIZE)
        self.minsize(900, 600)

        self._build_form()
        self._build_info()
        self._build_table()
        self.subnet_rows = []

    def _build_form(self):
        frm = ttk.LabelFrame(self, text="Parámetros")
        frm.pack(fill="x", padx=10, pady=8)

        ttk.Label(frm, text="CIDR (ej. 192.168.1.10/24):").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.cidr_var = tk.StringVar(value="181.79.223.18/16")
        ttk.Entry(frm, textvariable=self.cidr_var, width=28).grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(frm, text="Prefijo destino (opcional):").grid(row=0, column=2, sticky="w", padx=8)
        self.prefix_var = tk.StringVar()
        self.prefix_combo = ttk.Combobox(frm, textvariable=self.prefix_var, width=8, state="readonly",
                                         values=[str(p) for p in range(0, 33)])
        self.prefix_combo.grid(row=0, column=3, sticky="w", padx=8)
        self.prefix_combo.set("")

        ttk.Label(frm, text="Hosts por subred (opcional):").grid(row=0, column=4, sticky="w", padx=8)
        self.hosts_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.hosts_var, width=12).grid(row=0, column=5, sticky="w", padx=8)

        # Buttons
        ttk.Button(frm, text="Calcular", command=self.on_calc).grid(row=0, column=6, padx=10)
        ttk.Button(frm, text="Exportar CSV", command=self.on_export).grid(row=0, column=7, padx=6)

        # helper text
        ttk.Label(frm, text="* Use prefijo O hosts. Si ambos se llenan, tendrá prioridad 'prefijo'.").grid(
            row=1, column=0, columnspan=8, sticky="w", padx=8, pady=(0,6)
        )

    def _build_info(self):
        self.info = ttk.LabelFrame(self, text="Información de la red")
        self.info.pack(fill="x", padx=10, pady=8)

        labels = [
            "IP", "Prefijo", "Máscara decimal", "Máscara hex", "Máscara binaria",
            "Red", "Primer host", "Último host", "Broadcast",
            "Hosts utilizables", "Tipo", "Clase", "IP hex", "IP binario"
        ]
        self.info_vars = {k: tk.StringVar(value="-") for k in labels}

        # Display grid 2 columns of key/value pairs
        left = ["IP", "Prefijo", "Máscara decimal", "Máscara hex", "Máscara binaria", "Red", "Primer host"]
        right = ["Último host", "Broadcast", "Hosts utilizables", "Tipo", "Clase", "IP hex", "IP binario"]

        for i, key in enumerate(left):
            ttk.Label(self.info, text=f"{key}:").grid(row=i, column=0, sticky="e", padx=8, pady=2)
            ttk.Label(self.info, textvariable=self.info_vars[key]).grid(row=i, column=1, sticky="w", padx=8, pady=2)

        for i, key in enumerate(right):
            ttk.Label(self.info, text=f"{key}:").grid(row=i, column=2, sticky="e", padx=8, pady=2)
            ttk.Label(self.info, textvariable=self.info_vars[key]).grid(row=i, column=3, sticky="w", padx=8, pady=2)

    def _build_table(self):
        tbl_frame = ttk.LabelFrame(self, text="Subredes generadas")
        tbl_frame.pack(fill="both", expand=True, padx=10, pady=8)

        cols = ("#", "Subred", "Primer host", "Último host", "Broadcast", "Hosts utilizables")
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=15)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140 if c != "#" else 60, anchor="center")
        self.tree.pack(fill="both", expand=True, side="left")

        # add scrollbar
        scroll_y = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side="right", fill="y")

    def on_calc(self):
        try:
            cidr = self.cidr_var.get().strip()
            if not cidr:
                raise ValueError("Ingrese una dirección en formato CIDR")

            iface = IPv4Interface(cidr)
            base = iface.network

            # Determine target prefix
            new_prefix_str = self.prefix_var.get().strip()
            hosts_str = self.hosts_var.get().strip()

            if new_prefix_str:
                new_prefix = int(new_prefix_str)
            elif hosts_str:
                hosts = int(hosts_str)
                new_prefix = prefix_from_hosts(hosts)
            else:
                # No subdivision requested -> just show base network
                new_prefix = base.prefixlen

            if new_prefix < base.prefixlen or new_prefix > 32:
                raise ValueError(f"Prefijo destino inválido. Debe ser entre {base.prefixlen} y 32.")

            # Fill info panel
            first_octet = int(str(iface.ip).split(".")[0])
            mask_dec = str(base.netmask)
            first_host, last_host = usable_host_range(base)
            self.info_vars["IP"].set(str(iface.ip))
            self.info_vars["Prefijo"].set(f"/{base.prefixlen}")
            self.info_vars["Máscara decimal"].set(mask_dec)
            self.info_vars["Máscara hex"].set(to_hex(mask_dec))
            self.info_vars["Máscara binaria"].set(to_bin(mask_dec))
            self.info_vars["Red"].set(f"{base.network_address}/{base.prefixlen}")
            self.info_vars["Primer host"].set(first_host)
            self.info_vars["Último host"].set(last_host)
            self.info_vars["Broadcast"].set(str(base.broadcast_address))
            self.info_vars["Hosts utilizables"].set(str(usable_host_count(base)))
            self.info_vars["Tipo"].set(ip_type(iface.ip))
            self.info_vars["Clase"].set(f"Clase {ip_class(first_octet)}")
            self.info_vars["IP hex"].set(to_hex(str(iface.ip)))
            self.info_vars["IP binario"].set(to_bin(str(iface.ip)))

            # Build subnets
            subnets = list(base.subnets(new_prefix=new_prefix)) if new_prefix != base.prefixlen else [base]

            self.subnet_rows = []
            for i, net in enumerate(subnets):
                hosts = list(net.hosts())
                first = str(hosts[0]) if hosts else "-"
                last  = str(hosts[-1]) if hosts else "-"
                usable = usable_host_count(net)
                self.subnet_rows.append((i, f"{net.network_address}/{net.prefixlen}", first, last, str(net.broadcast_address), usable))

            # refresh table
            for row in self.tree.get_children():
                self.tree.delete(row)
            for r in self.subnet_rows:
                self.tree.insert("", "end", values=r)

            messagebox.showinfo("Listo", f"Se generaron {len(self.subnet_rows)} subred(es) con prefijo /{new_prefix}.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_export(self):
        if not self.subnet_rows:
            messagebox.showwarning("Sin datos", "No hay subredes para exportar. Primero presiona 'Calcular'.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Guardar listado de subredes"
        )
        if not path:
            return
        try:
            import csv
            header = ["#", "Subred", "Primer host", "Último host", "Broadcast", "Hosts utilizables"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(header)
                for r in self.subnet_rows:
                    w.writerow(r)
            messagebox.showinfo("Exportado", f"CSV guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error al exportar", str(e))

def main():
    app = SubnetGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
