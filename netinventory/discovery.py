"""Find devices on the local network: ping sweep + ARP table + TCP port check."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 139: "netbios", 443: "https",
    445: "smb", 554: "rtsp", 631: "ipp", 1883: "mqtt", 3306: "mysql", 3389: "rdp",
    5000: "upnp/dev", 5353: "mdns", 5900: "vnc", 8008: "chromecast", 8080: "http-alt",
    8443: "https-alt", 9100: "printer",
}


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list[int] = field(default_factory=list)

    @property
    def random_mac(self) -> bool:
        """Phones randomise their MAC for privacy; the 'locally administered' bit is then set."""
        try:
            return bool(int(self.mac.split(":")[0], 16) & 0x02)
        except (ValueError, IndexError):
            return False


def local_network() -> ipaddress.IPv4Network:
    """Guess the LAN as <local IP>/24. No packet is actually sent by connect() on UDP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def ping(ip: str, timeout: float = 1.0) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout + 2).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def normalize_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac.strip().lower())
    if len(parts) != 6:
        return ""
    return ":".join(p.zfill(2) for p in parts)


def parse_proc_arp(text: str) -> dict[str, str]:
    table = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
            table[cols[0]] = normalize_mac(cols[3])
    return table


def parse_arp_a(text: str) -> dict[str, str]:
    """Works with 'arp -a' output on Windows, macOS and Linux (net-tools)."""
    table = {}
    for line in text.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ip and mac:
            m = normalize_mac(mac.group(1))
            if m and m not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[ip.group(1)] = m
    return table


def arp_table() -> dict[str, str]:
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            return parse_proc_arp(fh.read())
    except OSError:
        pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
        return parse_arp_a(out)
    except (OSError, subprocess.TimeoutExpired):
        return {}


def open_ports(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    found = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
    return found


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def discover(network: ipaddress.IPv4Network, scan_ports: bool = True, workers: int = 64,
             ports: list[int] | None = None) -> list[Device]:
    hosts = [str(h) for h in network.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        alive = {ip for ip, up in zip(hosts, pool.map(ping, hosts)) if up}
    arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in network}
    ips = sorted(alive | set(arp), key=lambda x: ipaddress.ip_address(x))
    devices = [Device(ip=ip, mac=arp.get(ip, "")) for ip in ips]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for dev, name in zip(devices, pool.map(reverse_dns, ips)):
            dev.hostname = name
        if scan_ports:
            port_list = ports or list(COMMON_PORTS)
            for dev, found in zip(devices, pool.map(lambda ip: open_ports(ip, port_list), ips)):
                dev.ports = found
    return devices
