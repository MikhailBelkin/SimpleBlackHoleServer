# 🕳 BlackHole — TCP Honeypot Server

A lightweight, zero-dependency* Python honeypot that listens on common attack ports, fingerprints incoming connections by protocol, and streams everything live to a built-in web dashboard.

No database. No config files. Single Python script — just run it.

 

***

## What it does

- Opens TCP listeners on **10 ports** covering the most-attacked services
- **Fingerprints each connection payload** by matching protocol signatures:
  `SSH`, `TLS/SSL`, `RDP`, `HTTP`, `HTTP CONNECT`, `SMB`, `SMBv2`, `Telnet`, `FTP`, `SMTP`, `NTLM`, `VNC`, `Redis`, `Windows PE/Binary`, `Text`, `Binary`
- Detects **TCP-only port scans** (connect with no payload) and labels them separately
- Records: timestamp, source IP, source port, destination port, protocol, payload length, payload snippet, hex dump, per-IP hit count
- **Live web dashboard** served on port `8181` — updates in real time via WebSocket
- Shows counters: total attempts, unique IPs, top targeted port, top attacking IP
- Filter the connection table by IP, protocol, or any keyword
- **Export logs** as JSON or CSV with one click
- Keeps last **2000 entries** in memory (configurable)
- Auto-installs the only dependency (`websockets`) on first run

***

## Requirements

- Python 3.8+
- `websockets` (auto-installed if missing)

***

## Quick start

```bash
git clone https://github.com/MikhailBelkin/SimpleBlackHoleServer.git
cd blackhole-server

# Ports below 1024 require root
sudo python3 blackhole_server.py
```

Open the dashboard: **http://localhost:8181** or **http://yourseverip:8081**

Forward the monitored ports from your router or firewall to this machine — connections will appear in the table in real time.

> **Run without root** — grant low-port binding to Python instead:
> ```bash
> sudo setcap 'cap_net_bind_service=+ep' $(which python3)
> python3 blackhole_server.py
> ```

***

## Ports monitored by default

| Port | Service |
|------|---------|
| 22 | SSH |
| 23 | Telnet |
| 445 | SMB |
| 1723 | PPTP VPN |
| 2222–2225 | SSH (alt) |
| 3389 | RDP |
| 8080 | HTTP-Alt |

Edit `HONEYPOT_PORTS` at the top of the script to add or remove any ports.

***

## Dashboard

| | |
|---|---|
| URL | `http://<host>:8181` |
| WebSocket (internal) | port `8182` |
| Export JSON | `http://<host>:8181/api/export.json` |
| Export CSV | `http://<host>:8181/api/export.csv` |
| Max buffered entries | 2000 |

> Do **not** expose port `8181` to the public internet — the dashboard has no authentication.

***

## Install as a systemd service (Ubuntu)

Run BlackHole automatically on boot and restart it if it crashes.

**1. Copy the script**

```bash
sudo cp blackhole_server.py /opt/blackhole_server.py
```

**2. Create the unit file**

```bash
sudo nano /etc/systemd/system/blackhole.service
```

```ini
[Unit]
Description=BlackHole TCP Honeypot Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/blackhole_server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**3. Enable and start**

```bash
sudo systemctl daemon-reload
sudo systemctl enable blackhole
sudo systemctl start blackhole
```

**4. View live logs**

```bash
sudo journalctl -u blackhole -f
```

**5. Stop / disable**

```bash
sudo systemctl stop blackhole
sudo systemctl disable blackhole
```

***

## Protocol detection

The fingerprinter checks the first bytes of each payload against a signature table.
If no signature matches it tries to decode the payload as UTF-8 text; otherwise it returns a hex dump labeled `Binary`.
Connections that complete the TCP handshake but send no data are labeled `TCP handshake only`.

Recognized signatures:

| Bytes | Protocol |
|-------|----------|
| `SSH-` | SSH |
| `\x16\x03` | TLS/SSL |
| `\x03\x00` | RDP |
| `GET / POST / HEAD …` | HTTP |
| `CONNECT` | HTTP CONNECT |
| `\xff\xfb/\xfd/\xfa` | Telnet |
| `\xffSMB` | SMB |
| `\xfeSMB` | SMBv2 |
| `USER ` | FTP |
| `EHLO / HELO` | SMTP |
| `NTLMSSP` | NTLM |
| `RFB ` | VNC |
| `*1/*2/*3\r\n` | Redis |
| `MZ` | Windows PE / Binary |

***

## Security note

This tool runs on your own infrastructure and only accepts inbound connections initiated by remote hosts. It does not scan, probe, or interact with any external systems.

***

## License

MIT
