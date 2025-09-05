#!/usr/bin/env python3
from ipaddress import IPv4Interface, IPv4Network
from typing import Tuple
import argparse
import csv
import sys

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
    if net.prefixlen >= 31:
        hosts = list(net.hosts())
        if not hosts:
            return "-", "-"
        return str(hosts[0]), str(hosts[-1])
    hosts = list(net.hosts())
    return (str(hosts[0]), str(hosts[-1])) if hosts else ("-", "-")

def usable_host_count(net: IPv4Network) -> int:
    if net.prefixlen >= 31:
        return net.num_addresses
    return max(0, net.num_addresses - 2)

def print_table(rows):
    maxk = max(len(k) for k,_ in rows)
    print("\nCALCULADORA DE SUBNETEO\n" + "="*(22))
    for k,v in rows:
        print(f"{k:<{maxk}} : {v}")

def calc_basic(cidr: str):
    iface = IPv4Interface(cidr)
    net = iface.network
    first_octet = int(str(iface.ip).split(".")[0])
    mask_dec = str(net.netmask)
    first_host, last_host = usable_host_range(net)
    rows = [
        ("IP", str(iface.ip)),
        ("Prefijo", f"/{net.prefixlen}"),
        ("Máscara decimal", mask_dec),
        ("Máscara /bits", net.prefixlen),
        ("Máscara hex", to_hex(mask_dec)),
        ("Red", f"{net.network_address}/{net.prefixlen}"),
        ("Primer host", first_host),
        ("Último host", last_host),
        ("Broadcast", str(net.broadcast_address)),
        ("Hosts utilizables", usable_host_count(net)),
        ("Tipo", ip_type(iface.ip)),
        ("Clase", f"Clase {ip_class(first_octet)}"),
        ("IP hex", to_hex(str(iface.ip))),
        ("IP binario", to_bin(str(iface.ip))),
        ("Máscara binaria", to_bin(mask_dec)),
    ]
    print_table(rows)

def list_subnets(cidr: str, new_prefix: int, csv_out: str = None):
    iface = IPv4Interface(cidr)
    base = iface.network
    if new_prefix < base.prefixlen or new_prefix > 32:
        print("ERROR: --new-prefix debe ser >= al prefijo de entrada y <= 32", file=sys.stderr)
        sys.exit(2)
    subnets = list(base.subnets(new_prefix=new_prefix)) if new_prefix != base.prefixlen else [base]
    header = ["#", "Subred", "Primer host", "Último host", "Broadcast", "Hosts utilizables"]
    rows = []
    for i,net in enumerate(subnets):
        hosts = list(net.hosts())
        first_host = str(hosts[0]) if hosts else "-"
        last_host = str(hosts[-1]) if hosts else "-"
        rows.append([i, f"{net.network_address}/{net.prefixlen}", first_host, last_host, str(net.broadcast_address), (net.num_addresses if net.prefixlen >= 31 else max(0, net.num_addresses - 2))])
    # Pretty print
    print(f"\nLISTA DE SUBREDES de {base.with_prefixlen} -> /{new_prefix} (total: {len(rows)})")
    widths = [max(len(str(col)) for col in col_vals) for col_vals in zip(*([header] + rows))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*header))
    for r in rows:
        print(fmt.format(*r))
    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        print(f"\nCSV guardado en: {csv_out}")

def main():
    p = argparse.ArgumentParser(description="Calculadora de subneteo con listado de subredes")
    p.add_argument("cidr", help="Dirección en formato CIDR, ej: 181.79.223.18/16 o 192.168.1.10/24")
    p.add_argument("--new-prefix", type=int, help="Prefijo destino para dividir la red (ej. 24 para generar /24)")
    p.add_argument("--csv", help="Ruta de salida CSV para el listado de subredes")
    args = p.parse_args()
    calc_basic(args.cidr)
    if args.new_prefix is not None:
        list_subnets(args.cidr, args.new_prefix, args.csv)

if __name__ == "__main__":
    main()
