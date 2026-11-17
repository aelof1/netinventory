# netinventory

Local network inventory: the tool finds every connected device (IP, MAC address, manufacturer, hostname, open ports), saves them, and **flags every new device** that shows up.

> ⚠️ Only use it on **your own network**, or on a network you have permission to scan. Scanning someone else's network without consent is illegal in most countries.

## Why I built this

"You can't protect what you don't know about": asset inventory is the first security control in most frameworks (CIS Control 1). At home I found several connected devices I had forgotten about. I wanted a simple, dependency-free tool that runs on Linux, Windows and macOS, and tells me when an unknown device connects.

## How it works

1. **Network detection**: from the machine's IP (e.g. `192.168.1.0/24`), or given with `-n`.
2. **Ping sweep**: a `ping` to every address, in parallel (64 at a time).
3. **ARP table**: gets the MAC address of the devices found. It also finds devices that don't answer ping, like many phones.
4. **Manufacturer**: the first 3 bytes of the MAC identify the vendor (OUI).
5. **Hostname**: reverse DNS lookup.
6. **Ports**: TCP connection test on 20 common ports (SSH, HTTP, SMB, RDP, printer…). Risky ports (Telnet, FTP, SMB, RDP, VNC) are shown in red.
7. **Memory**: everything is saved in `inventory.json`. On the next scan, new devices are marked with a star `*`.

"Random" MAC addresses (the iPhone/Android privacy feature) are recognised and labelled as such.

## Compatibility

| System | Works? | Note |
|---|---|---|
| Linux (Ubuntu, Debian, Kali, Fedora, Arch…) | Yes | reads `/proc/net/arp` |
| macOS | Yes | uses `arp -a` |
| Windows 10 / 11 | Yes | uses Windows `ping` and `arp -a` |

**No root/administrator rights needed**: the tool uses the system's `ping` and `arp` commands.

## Requirements

- **Python 3.9 or newer**
- The `ping` command (present everywhere; on some minimal Docker images: `sudo apt install iputils-ping`)
- No external Python libraries
- **Recommended on Linux**: the `ieee-data` package, which contains the official list of manufacturers. It's used automatically when installed. Without it, the tool only has a small built-in list (Raspberry Pi, VMware, VirtualBox…).

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git iputils-ping ieee-data
git clone https://github.com/aelof1/netinventory.git
cd netinventory
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git iputils
```

For manufacturer names, download the IEEE file and pass it with `--oui-file` (see below).

### Arch

```bash
sudo pacman -S python python-pipx git iputils
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

If Windows Firewall asks for permission, allow it for private networks.

### Full manufacturer list (all systems)

Download `https://standards-oui.ieee.org/oui/oui.txt`, then:

```bash
netinventory --oui-file oui.txt
```

## Usage

```bash
netinventory                              # scan the auto-detected network
netinventory -n 192.168.1.0/24            # specific network
netinventory --no-ports                   # faster, no port test
netinventory --name 192.168.1.1 "Home router"   # give a device a name
netinventory --watch 300                  # rescan every 5 min, alert on new devices
netinventory --json                       # JSON output
netinventory --db ~/home.json             # another inventory file
```

### Example

```
Network 192.168.1.0/24 - vendor data: /usr/share/ieee-data/oui.txt

  IP              MAC                VENDOR                  NAME / HOSTNAME             OPEN PORTS
  192.168.1.1     xx:xx:xx:11:22:33  (router vendor)         Home router                 53/dns, 80/http, 443/https
  192.168.1.20    b8:27:eb:aa:bb:cc  Raspberry Pi            pi-hole                     22/ssh, 80/http
  192.168.1.34    da:4f:1c:9e:00:12  (random / private MAC)  -
* 192.168.1.57    xx:xx:xx:44:55:66  (vendor)                -                           23/telnet

4 device(s), 1 new (*)
```

Here an unknown device with **Telnet open** has just appeared: exactly what the tool is meant to point out.

## Project layout

```
netinventory/
├── netinventory/
│   ├── discovery.py   # ping, ARP table, ports, reverse DNS
│   ├── vendors.py     # MAC -> manufacturer
│   ├── inventory.py   # memory of known devices
│   └── cli.py
└── tests/
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

The tests check ARP table parsing in Linux, Windows and macOS formats, new device detection, and the port test against a tiny local server.

## Limitations

- Only sees the local network (same segment): ARP doesn't cross routers.
- A device with a strict firewall that answers nothing may not show up.
- Phones with random MACs may appear as "new" if they change their MAC.
- No OS detection (for that: `nmap -O`).

## Ideas for later

- Discord / email alerts in `--watch` mode
- HTML page with the device history
- mDNS / SSDP discovery to get the names of smart devices

## License

MIT
