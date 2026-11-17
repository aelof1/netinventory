import socket
import threading

from netinventory.discovery import Device, open_ports, parse_arp_a, parse_proc_arp
from netinventory.inventory import Inventory
from netinventory.vendors import VendorDB

PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         f4:ca:e5:11:22:33     *        eth0
192.168.1.20     0x1         0x2         b8:27:eb:aa:bb:cc     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
"""

WINDOWS_ARP = """
Interface: 192.168.1.10 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           f4-ca-e5-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""

MAC_ARP = "? (192.168.1.20) at b8:27:eb:a:b:c on en0 ifscope [ethernet]\n"


def test_parse_proc_arp():
    assert parse_proc_arp(PROC_ARP) == {"192.168.1.1": "f4:ca:e5:11:22:33", "192.168.1.20": "b8:27:eb:aa:bb:cc"}


def test_parse_windows_and_macos_arp():
    assert parse_arp_a(WINDOWS_ARP) == {"192.168.1.1": "f4:ca:e5:11:22:33"}
    assert parse_arp_a(MAC_ARP) == {"192.168.1.20": "b8:27:eb:0a:0b:0c"}


def test_vendor_lookup(tmp_path):
    db = VendorDB(oui_file=str(tmp_path / "missing.txt"))
    assert db.lookup("b8:27:eb:aa:bb:cc") == "Raspberry Pi"
    assert db.lookup("da:11:22:33:44:55") == "(random / private MAC)"
    oui = tmp_path / "oui.txt"
    oui.write_text("AB-CD-EF   (hex)\t\tAcme Corp\n")
    assert VendorDB(str(oui)).lookup("ab:cd:ef:00:00:01") == "Acme Corp"


def test_random_mac_flag():
    assert Device("1.1.1.1", mac="da:00:00:00:00:00").random_mac
    assert not Device("1.1.1.1", mac="b8:27:eb:00:00:00").random_mac


def test_inventory_new_devices(tmp_path):
    db = tmp_path / "inv.json"
    inv = Inventory(str(db))
    a, b = Device("192.168.1.1", "aa:aa:aa:aa:aa:aa"), Device("192.168.1.2", "bb:bb:bb:bb:bb:bb")
    assert inv.update([a]) == [a]
    inv.set_name("192.168.1.1", "router")
    inv.save()
    inv2 = Inventory(str(db))
    assert inv2.update([a, b]) == [b]
    assert inv2.name_of(a) == "router"


def test_open_ports_on_localhost():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    try:
        assert open_ports("127.0.0.1", [port]) == [port]
    finally:
        srv.close()
