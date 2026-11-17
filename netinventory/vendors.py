"""MAC address -> manufacturer.

A small built-in list covers common home/office brands. For the full IEEE list:
  - Debian/Ubuntu/Kali: sudo apt install ieee-data   (used automatically)
  - or download https://standards-oui.ieee.org/oui/oui.txt and pass --oui-file
"""

from __future__ import annotations

import re
from pathlib import Path

BUILTIN = {
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
    # Virtual machines and containers
    "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Microsoft Hyper-V", "02:42:ac": "Docker container",
    "bc:24:11": "Proxmox",
    # IoT / NAS
    "00:17:88": "Philips Hue", "00:11:32": "Synology", "24:0a:c4": "Espressif (IoT)", "30:ae:a4": "Espressif (IoT)",
}

SYSTEM_OUI_FILES = ["/usr/share/ieee-data/oui.txt", "/usr/share/misc/oui.txt", "/usr/share/wireshark/manuf"]


class VendorDB:
    def __init__(self, oui_file: str | None = None):
        self.table = dict(BUILTIN)
        candidates = [oui_file] if oui_file else SYSTEM_OUI_FILES
        for path in candidates:
            if path and Path(path).exists():
                self.table.update(self._load(Path(path)))
                self.source = path
                break
        else:
            self.source = "built-in list"

    @staticmethod
    def _load(path: Path) -> dict[str, str]:
        table = {}
        text = path.read_text(encoding="utf-8", errors="replace")
        # IEEE format: "00-1A-11   (hex)		Google, Inc."
        for m in re.finditer(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$", text, re.M):
            table[f"{m.group(1)}:{m.group(2)}:{m.group(3)}".lower()] = m.group(4).strip()
        # Wireshark manuf format: "00:1A:11\tGoogle\tGoogle, Inc."
        for m in re.finditer(r"^([0-9A-F]{2}):([0-9A-F]{2}):([0-9A-F]{2})\t(\S+)(?:\t(.+))?$", text, re.M):
            table[f"{m.group(1)}:{m.group(2)}:{m.group(3)}".lower()] = (m.group(5) or m.group(4)).strip()
        return table

    def lookup(self, mac: str) -> str:
        if not mac:
            return ""
        try:
            if int(mac[:2], 16) & 0x02 and mac[:8] not in self.table:
                return "(random / private MAC)"
        except ValueError:
            return ""
        return self.table.get(mac[:8].lower(), "unknown")
