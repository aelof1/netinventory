"""Remember known devices between scans and flag new ones."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .discovery import Device


def device_key(dev: Device) -> str:
    # MAC is the most stable identifier; fall back to IP when we don't have it
    return dev.mac or f"ip:{dev.ip}"


class Inventory:
    def __init__(self, path: str):
        self.path = Path(path)
        self.data: dict[str, dict] = {}
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def update(self, devices: list[Device]) -> list[Device]:
        """Store the scan and return the devices never seen before."""
        now = datetime.now().isoformat(timespec="seconds")
        new = []
        for dev in devices:
            key = device_key(dev)
            entry = self.data.get(key)
            if entry is None:
                new.append(dev)
                entry = {"first_seen": now, "name": ""}
                self.data[key] = entry
            entry.update({"ip": dev.ip, "mac": dev.mac, "vendor": dev.vendor, "hostname": dev.hostname,
                          "ports": dev.ports, "last_seen": now})
        return new

    def name_of(self, dev: Device) -> str:
        return self.data.get(device_key(dev), {}).get("name", "")

    def set_name(self, key: str, name: str) -> bool:
        for k, entry in self.data.items():
            if key in (k, entry.get("ip"), entry.get("mac")):
                entry["name"] = name
                return True
        return False

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
