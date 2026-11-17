"""netinventory command line."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time

from . import __version__
from .discovery import COMMON_PORTS, discover, local_network
from .inventory import Inventory
from .vendors import VendorDB

RISKY = {21, 23, 445, 3389, 5900}


def show(devices, inventory, new_keys, color: bool) -> None:
    g, y, r, reset = ("\033[92m", "\033[93m", "\033[91m", "\033[0m") if color else ("", "", "", "")
    print(f"{'':2}{'IP':<16}{'MAC':<19}{'VENDOR':<24}{'NAME / HOSTNAME':<28}OPEN PORTS")
    for d in devices:
        flag = f"{y}*{reset} " if d.ip in new_keys else "  "
        label = inventory.name_of(d) or d.hostname
        ports = ", ".join(
            (f"{r}{p}/{COMMON_PORTS.get(p, '?')}{reset}" if p in RISKY else f"{p}/{COMMON_PORTS.get(p, '?')}")
            for p in d.ports)
        print(f"{flag}{d.ip:<16}{d.mac or '-':<19}{(d.vendor or '-')[:23]:<24}{(label or '-')[:27]:<28}{ports}")
    print(f"\n{g}{len(devices)} device(s){reset}" + (f", {y}{len(new_keys)} new (*){reset}" if new_keys else ""))


def run_scan(args, vendors: VendorDB, inventory: Inventory):
    net = ipaddress.ip_network(args.network, strict=False) if args.network else local_network()
    if net.num_addresses > 1024 and not args.force:
        raise SystemExit(f"{net} is big ({net.num_addresses} addresses). Use --force if you really want it.")
    devices = discover(net, scan_ports=not args.no_ports)
    for d in devices:
        d.vendor = vendors.lookup(d.mac)
    new = inventory.update(devices)
    inventory.save()
    return net, devices, new


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netinventory", description="Inventory the devices on your local network.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-n", "--network", help="network to scan, e.g. 192.168.1.0/24 (default: auto-detect)")
    p.add_argument("--db", default="inventory.json", help="file where known devices are stored")
    p.add_argument("--oui-file", help="IEEE oui.txt or Wireshark manuf file for vendor names")
    p.add_argument("--no-ports", action="store_true", help="skip the TCP port check (faster)")
    p.add_argument("--watch", type=int, metavar="SECONDS", help="rescan every N seconds and alert on new devices")
    p.add_argument("--name", nargs=2, metavar=("IP_OR_MAC", "NAME"), help="give a friendly name to a device")
    p.add_argument("--json", action="store_true")
    p.add_argument("--force", action="store_true", help="allow scanning networks larger than /22")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    inventory = Inventory(args.db)
    if args.name:
        if inventory.set_name(*args.name):
            inventory.save()
            print(f"Named {args.name[0]} -> {args.name[1]}")
            return 0
        print("Device not found in the inventory. Run a scan first.", file=sys.stderr)
        return 1

    vendors = VendorDB(args.oui_file)
    color = not args.no_color and sys.stdout.isatty()
    first = not inventory.data

    if args.watch:
        print(f"Watching the network every {args.watch}s (Ctrl+C to stop)...")
        try:
            while True:
                net, devices, new = run_scan(args, vendors, inventory)
                stamp = time.strftime("%H:%M:%S")
                if first:
                    print(f"[{stamp}] baseline: {len(devices)} devices on {net}", flush=True)
                    first = False
                else:
                    for d in new:
                        print(f"[{stamp}] NEW DEVICE: {d.ip} {d.mac} {d.vendor} {d.hostname}", flush=True)
                time.sleep(args.watch)
        except KeyboardInterrupt:
            return 0

    print("Scanning... (this takes about 10-30 seconds)", file=sys.stderr)
    net, devices, new = run_scan(args, vendors, inventory)
    if args.json:
        print(json.dumps({"network": str(net), "devices": [
            {**d.__dict__, "new": d in new, "name": inventory.name_of(d)} for d in devices]}, indent=2))
    else:
        print(f"Network {net} - vendor data: {vendors.source}\n")
        show(devices, inventory, set() if first else {d.ip for d in new}, color)
        if first:
            print("First scan: every device was saved as known. Next scans will highlight new ones.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
