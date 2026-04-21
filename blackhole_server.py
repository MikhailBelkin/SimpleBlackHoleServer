#!/usr/bin/env python3
"""
BlackHole Honeypot Server v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forward firewall ports to this server.
It logs every connection attempt and streams them live to the web dashboard.

Usage:
  python3 blackhole_server.py

Dashboard opens at: http://localhost:8181
"""

import asyncio, json, os, sys, threading, http.server
from datetime import datetime
from collections import defaultdict, deque
from typing import Set

# Auto-install websockets
try:
    import websockets
    from websockets.server import serve as ws_serve
except ImportError:
    print("[*] Installing websockets...")
    os.system(f"{sys.executable} -m pip install websockets")
    import websockets
    from websockets.server import serve as ws_serve

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# Ports to listen on (forward these from your Cisco RV345 to this machine)
HONEYPOT_PORTS = [22, 2222, 2223, 2224, 2225, 1723, 3389, 445, 8080, 23]

WEB_PORT       = 8181   # Dashboard URL: http://<server-ip>:8181
WS_PORT        = 8182   # WebSocket (internal, dashboard connects here)
MAX_RECV_BYTES = 512    # Max bytes to read from each connection
MAX_LOG_ENTRIES = 2000  # Max log entries kept in memory
# ──────────────────────────────────────────────────────────────────────────────

log_entries: deque = deque(maxlen=MAX_LOG_ENTRIES)
ws_clients: Set    = set()
_counter           = 0
stats = {
    "total":   0,
    "by_port": defaultdict(int),
    "by_ip":   defaultdict(int),
    "by_proto": defaultdict(int),
}

# Protocol fingerprint signatures
SIGS = [
    (b"SSH-",       "SSH"),
    (b"\x16\x03",   "TLS/SSL"),
    (b"\x03\x00",   "RDP"),
    (b"GET ",       "HTTP"),
    (b"POST ",      "HTTP"),
    (b"HEAD ",      "HTTP"),
    (b"PUT ",       "HTTP"),
    (b"DELETE ",    "HTTP"),
    (b"CONNECT ",   "HTTP CONNECT"),
    (b"\xff\xfb",   "Telnet"),
    (b"\xff\xfd",   "Telnet"),
    (b"\xff\xfa",   "Telnet"),
    (b"\xffSMB",    "SMB"),
    (b"\xfeSMB",    "SMBv2"),
    (b"USER ",      "FTP"),
    (b"EHLO",       "SMTP"),
    (b"HELO",       "SMTP"),
    (b"NTLMSSP",    "NTLM"),
    (b"RFB ",       "VNC"),
    (b"*1\r\n",     "Redis"),
    (b"*2\r\n",     "Redis"),
    (b"*3\r\n",     "Redis"),
    (b"\x4d\x5a",   "Windows PE/Binary"),
]

PORT_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def fingerprint(data: bytes, port: int):
    """Returns (protocol, snippet_text)"""
    if not data:
        hint = PORT_HINTS.get(port, f"Port {port}")
        return hint, "TCP handshake only — no payload data sent"

    for sig, name in SIGS:
        if data.startswith(sig):
            try:
                snip = data[:300].decode("utf-8", "replace").strip()
            except Exception:
                snip = data[:32].hex(" ")
            return name, snip[:500]

    # Try decode as UTF-8 text
    try:
        t = data[:300].decode("utf-8", "strict").strip()
        if len(t) > 2:
            return "Text", t[:500]
    except Exception:
        pass

    return "Binary", data[:32].hex(" ")


async def broadcast(msg: dict):
    if not ws_clients:
        return
    payload = json.dumps(msg)
    dead = set()
    for c in list(ws_clients):
        try:
            await c.send(payload)
        except Exception:
            dead.add(c)
    ws_clients.difference_update(dead)


async def handle_conn(reader, writer, port: int):
    global _counter
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip, sport = peer[0], peer[1]

    data = b""
    try:
        data = await asyncio.wait_for(reader.read(MAX_RECV_BYTES), timeout=4.0)
    except Exception:
        pass

    proto, snip = fingerprint(data, port)
    _counter += 1
    stats["total"]         += 1
    stats["by_port"][port] += 1
    stats["by_ip"][ip]     += 1
    stats["by_proto"][proto] += 1

    now = datetime.now()
    entry = {
        "id":    _counter,
        "ts":    now.strftime("%H:%M:%S"),
        "date":  now.strftime("%Y-%m-%d"),
        "ip":    ip,
        "sport": sport,
        "dport": port,
        "proto": proto,
        "len":   len(data),
        "snip":  snip,
        "hex":   data[:48].hex(" ") if data else "",
        "cnt":   stats["by_ip"][ip],  # how many times this IP has connected
    }

    log_entries.appendleft(entry)

    tp = max(stats["by_port"], key=stats["by_port"].get) if stats["by_port"] else "-"
    ti = max(stats["by_ip"],   key=stats["by_ip"].get)   if stats["by_ip"]   else "-"

    print(f"  [{entry['ts']}] {ip}:{sport} → :{port} [{proto}] {snip[:55]}")

    await broadcast({
        "type":  "entry",
        "entry": entry,
        "stats": {
            "total": stats["total"],
            "uniq":  len(stats["by_ip"]),
            "tp":    tp,
            "tpc":   stats["by_port"].get(tp, 0),
            "ti":    ti,
            "tic":   stats["by_ip"].get(ti, 0),
        },
    })

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def ws_handler(ws):
    ws_clients.add(ws)
    try:
        tp = max(stats["by_port"], key=stats["by_port"].get) if stats["by_port"] else "-"
        ti = max(stats["by_ip"],   key=stats["by_ip"].get)   if stats["by_ip"]   else "-"
        await ws.send(json.dumps({
            "type":    "init",
            "entries": list(log_entries)[:200],
            "stats": {
                "total":    stats["total"],
                "uniq":     len(stats["by_ip"]),
                "tp":       tp,
                "tpc":      stats["by_port"].get(tp, 0),
                "ti":       ti,
                "tic":      stats["by_ip"].get(ti, 0),
                "by_port":  {str(k): v for k, v in stats["by_port"].items()},
                "by_proto": dict(stats["by_proto"]),
                "top_ips":  dict(sorted(stats["by_ip"].items(), key=lambda x: -x[1])[:10]),
            },
            "ports": HONEYPOT_PORTS,
        }))
        await ws.wait_closed()
    finally:
        ws_clients.discard(ws)


# ── HTTP Handler (serves the dashboard HTML) ──────────────────────────────────
class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/export.json":
            body = json.dumps(list(log_entries), indent=2, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="blackhole_logs.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/export.csv":
            rows = ["id,timestamp,date,src_ip,src_port,dst_port,protocol,data_len,snippet"]
            for e in log_entries:
                s = e["snip"][:120].replace('"', "'").replace("\n", " ").replace("\r", "")
                rows.append(f'{e["id"]},{e["ts"]},{e["date"]},{e["ip"]},{e["sport"]},{e["dport"]},{e["proto"]},{e["len"]},"{s}"')
            body = "\n".join(rows).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", 'attachment; filename="blackhole_logs.csv"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, *a):
        pass  # suppress HTTP access log


# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    print("\n" + "═" * 62)
    print("  🕳  BlackHole Honeypot Server v1.0")
    print("═" * 62)

    servers, failed = [], []
    for port in HONEYPOT_PORTS:
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port: handle_conn(r, w, p),
                "0.0.0.0", port
            )
            servers.append(srv)
            print(f"  [+] Honeypot :{port:>5}  ({PORT_HINTS.get(port, 'custom')})")
        except OSError as e:
            failed.append(port)
            print(f"  [!] Port {port}: {e.strerror} (try sudo or setcap)")

    ws_server = await ws_serve(ws_handler, "0.0.0.0", WS_PORT)
    print(f"\n  [+] WebSocket   :{WS_PORT}")

    httpd = http.server.HTTPServer(("0.0.0.0", WEB_PORT), DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"  [+] Dashboard   http://0.0.0.0:{WEB_PORT}")
    print("═" * 62)
    print(f"  Monitoring {len(servers)} port(s). Waiting for connections...\n")

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        ws_server.close()
        for s in servers:
            s.close()
        httpd.shutdown()


# ── Embedded Dashboard HTML ───────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlackHole — Honeypot Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #0a0d12;
  --surf:      #0f1318;
  --surf2:     #141920;
  --surf3:     #1a2030;
  --border:    oklch(0.7 0.02 210 / 0.12);
  --border2:   oklch(0.7 0.02 210 / 0.20);
  --text:      #c4cdd8;
  --muted:     #5a6a80;
  --faint:     #2d3a4a;
  --accent:    #00cfb4;
  --accent-d:  #009985;
  --red:       #ff3d5a;
  --orange:    #ff8c3d;
  --yellow:    #ffc53d;
  --green:     #3dcc7a;
  --blue:      #3d9bff;
  --purple:    #a07cff;
  --mono:      'JetBrains Mono', 'Consolas', monospace;
  --sans:      'Inter', system-ui, sans-serif;
  --r-sm: 0.25rem; --r-md: 0.375rem; --r-lg: 0.5rem;
  --trans: 160ms cubic-bezier(0.16,1,0.3,1);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{font-family:var(--sans);font-size:13px;color:var(--text);background:var(--bg);min-height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── HEADER ── */
header{display:flex;align-items:center;gap:12px;padding:0 16px;height:48px;background:var(--surf);border-bottom:1px solid var(--border);flex-shrink:0;z-index:10}
.logo{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:14px;font-weight:600;color:#fff;letter-spacing:-0.02em}
.logo svg{flex-shrink:0}
.dot{width:7px;height:7px;border-radius:50%;background:var(--red);animation:pulse-dot 2s ease-in-out infinite;flex-shrink:0}
@keyframes pulse-dot{0%,100%{opacity:1;box-shadow:0 0 0 0 color-mix(in oklch,var(--red) 40%,transparent)}50%{opacity:.7;box-shadow:0 0 0 4px transparent}}
.ws-status{font-family:var(--mono);font-size:11px;display:flex;align-items:center;gap:5px}
.ws-status .ind{width:6px;height:6px;border-radius:50%;background:var(--muted);transition:background var(--trans)}
.ws-status.connected .ind{background:var(--green)}
.ws-status.connecting .ind{background:var(--yellow);animation:pulse-dot 1s infinite}
.ws-status.error .ind{background:var(--red)}
.port-tags{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
.port-tag{font-family:var(--mono);font-size:10px;padding:1px 5px;border-radius:var(--r-sm);background:var(--surf3);color:var(--muted);border:1px solid var(--border)}
.header-right{margin-left:auto;display:flex;align-items:center;gap:8px}
.btn{font-family:var(--sans);font-size:12px;padding:5px 10px;border-radius:var(--r-md);border:1px solid var(--border2);background:var(--surf2);color:var(--text);cursor:pointer;transition:background var(--trans),color var(--trans),border-color var(--trans);white-space:nowrap}
.btn:hover{background:var(--surf3);color:#fff;border-color:var(--border2)}
.btn:active{background:var(--faint)}
.btn-danger{border-color:oklch(from var(--red) l c h / 0.3);color:var(--red)}
.btn-danger:hover{background:oklch(from var(--red) l c h / 0.1);color:var(--red);border-color:oklch(from var(--red) l c h / 0.5)}
.btn-accent{border-color:oklch(from var(--accent) l c h / 0.3);color:var(--accent)}
.btn-accent:hover{background:oklch(from var(--accent) l c h / 0.1);border-color:oklch(from var(--accent) l c h / 0.5)}

/* ── STATS BAR ── */
.stats-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border);flex-shrink:0}
.stat-card{background:var(--surf);padding:10px 16px;display:flex;flex-direction:column;gap:2px}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.stat-value{font-family:var(--mono);font-size:20px;font-weight:600;color:#fff;line-height:1;font-variant-numeric:tabular-nums;transition:color .3s}
.stat-sub{font-family:var(--mono);font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stat-value.flash{animation:val-flash .4s ease-out}
@keyframes val-flash{0%{color:var(--accent)}100%{color:#fff}}

/* ── LAYOUT ── */
.workspace{display:flex;flex:1;overflow:hidden;min-height:0}

/* ── LOG PANEL ── */
.log-panel{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}
.log-toolbar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surf);border-bottom:1px solid var(--border);flex-shrink:0}
.log-toolbar label{font-size:11px;color:var(--muted);white-space:nowrap}
.filter-input{flex:1;max-width:240px;font-family:var(--mono);font-size:12px;padding:4px 8px;background:var(--surf2);border:1px solid var(--border2);border-radius:var(--r-md);color:var(--text);outline:none;transition:border-color var(--trans)}
.filter-input:focus{border-color:var(--accent)}
.filter-input::placeholder{color:var(--faint)}
.autoscroll-btn{display:flex;align-items:center;gap:5px;font-size:12px;cursor:pointer;padding:4px 8px;border-radius:var(--r-md);color:var(--muted);transition:color var(--trans)}
.autoscroll-btn:hover{color:var(--text)}
.autoscroll-btn.on{color:var(--accent)}
.autoscroll-btn svg{transition:transform var(--trans)}
.log-wrap{flex:1;overflow-y:auto;overflow-x:hidden;min-height:0}
.log-wrap::-webkit-scrollbar{width:5px}
.log-wrap::-webkit-scrollbar-track{background:transparent}
.log-wrap::-webkit-scrollbar-thumb{background:var(--faint);border-radius:3px}
table.log-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
.log-table th{position:sticky;top:0;background:var(--surf2);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em;padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);font-weight:500;white-space:nowrap;z-index:5}
.log-table td{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.log-table tr.new-row{animation:row-in .5s ease-out}
@keyframes row-in{0%{background:oklch(from var(--accent) l c h / 0.15)}100%{background:transparent}}
.log-table tr:hover td{background:var(--surf2);cursor:pointer}
.log-table tr.expanded td{background:var(--surf2)}
.col-time{width:72px;color:var(--muted)}
.col-ip{width:130px;color:#fff;font-weight:500}
.col-ip .repeat{font-size:10px;color:var(--orange);margin-left:4px}
.col-sport{width:52px;color:var(--faint)}
.col-dport{width:52px}
.col-proto{width:90px}
.col-len{width:48px;color:var(--muted);text-align:right}
.col-snip{color:var(--muted);max-width:320px}

/* Proto badges */
.badge{display:inline-block;font-size:10px;padding:1px 6px;border-radius:var(--r-sm);font-weight:500}
.badge-ssh{background:oklch(from var(--blue) l c h / 0.15);color:var(--blue)}
.badge-tls{background:oklch(from var(--purple) l c h / 0.15);color:var(--purple)}
.badge-rdp{background:oklch(from var(--orange) l c h / 0.15);color:var(--orange)}
.badge-http{background:oklch(from var(--green) l c h / 0.15);color:var(--green)}
.badge-smb{background:oklch(from var(--red) l c h / 0.15);color:var(--red)}
.badge-telnet{background:oklch(from var(--orange) l c h / 0.12);color:#ff9966}
.badge-ftp{background:oklch(from var(--blue) l c h / 0.10);color:#66aaff}
.badge-ntlm{background:oklch(from var(--red) l c h / 0.12);color:#ff6688}
.badge-default{background:oklch(from var(--muted) l c h / 0.15);color:var(--muted)}

/* ── DETAIL ROW ── */
.detail-row td{padding:0;border:none}
.detail-body{padding:10px 16px;background:var(--surf);border-bottom:1px solid var(--border);display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:11px}
.detail-body dt{color:var(--muted);white-space:nowrap}
.detail-body dd{font-family:var(--mono);color:var(--text);word-break:break-all}
.detail-body .hex-dump{color:var(--accent);font-size:11px;opacity:.8}

/* ── SIDEBAR ── */
.sidebar{width:240px;flex-shrink:0;border-left:1px solid var(--border);background:var(--surf);overflow-y:auto;overflow-x:hidden}
.sidebar::-webkit-scrollbar{width:4px}
.sidebar::-webkit-scrollbar-thumb{background:var(--faint);border-radius:3px}
.sb-section{padding:12px}
.sb-title{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px;font-weight:600}
.sb-sep{height:1px;background:var(--border);margin:0}
.ip-row{display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid oklch(0.7 0.02 210 / 0.06)}
.ip-row:last-child{border:none}
.ip-row .ip-addr{flex:1;font-family:var(--mono);font-size:11px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ip-row .ip-bar{height:3px;border-radius:2px;background:var(--accent);transition:width .5s ease}
.ip-row .ip-cnt{font-family:var(--mono);font-size:11px;color:var(--muted);min-width:24px;text-align:right}
.proto-row{display:flex;align-items:center;gap:6px;padding:3px 0}
.proto-row .proto-name{flex:1;font-family:var(--mono);font-size:11px;color:var(--text)}
.proto-row .proto-cnt{font-family:var(--mono);font-size:11px;color:var(--muted)}
.port-grid{display:flex;flex-direction:column;gap:3px}
.port-item{display:flex;align-items:center;gap:6px}
.port-item .pnum{font-family:var(--mono);font-size:11px;color:var(--text);min-width:40px}
.port-item .pbar-wrap{flex:1;height:3px;background:var(--faint);border-radius:2px;overflow:hidden}
.port-item .pbar{height:3px;background:var(--accent);border-radius:2px;transition:width .5s ease}
.port-item .pcnt{font-family:var(--mono);font-size:11px;color:var(--muted);min-width:24px;text-align:right}

/* ── EMPTY STATE ── */
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--muted);padding:32px}
.empty-state svg{color:var(--faint);opacity:.5}
.empty-state p{font-size:12px;text-align:center;max-width:24ch;line-height:1.5}

/* ── BOTTOM BAR ── */
.bottom-bar{display:flex;align-items:center;gap:8px;padding:4px 12px;background:var(--surf);border-top:1px solid var(--border);font-family:var(--mono);font-size:11px;color:var(--muted);flex-shrink:0}
.bottom-bar .bsep{width:1px;height:14px;background:var(--border);margin:0 2px}

@media(max-width:768px){
  .stats-bar{grid-template-columns:repeat(2,1fr)}
  .sidebar{display:none}
  .col-sport,.col-len{display:none}
}
</style>
</head>
<body>
<header>
  <div class="logo">
    <svg aria-label="BlackHole" width="22" height="22" viewBox="0 0 22 22" fill="none">
      <circle cx="11" cy="11" r="9" stroke="currentColor" stroke-width="1.5" opacity=".3"/>
      <circle cx="11" cy="11" r="5" stroke="currentColor" stroke-width="1.5" opacity=".6"/>
      <circle cx="11" cy="11" r="2" fill="currentColor"/>
    </svg>
    BlackHole
  </div>
  <div class="dot" title="Monitoring active"></div>
  <div id="ws-status" class="ws-status connecting">
    <div class="ind"></div>
    <span id="ws-label">connecting…</span>
  </div>
  <div class="port-tags" id="port-tags"></div>
  <div class="header-right">
    <a href="/api/export.csv" class="btn btn-accent" download>Export CSV</a>
    <a href="/api/export.json" class="btn" download>Export JSON</a>
    <button class="btn btn-danger" onclick="clearLogs()">Clear</button>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card">
    <div class="stat-label">Total Attempts</div>
    <div class="stat-value" id="s-total">0</div>
    <div class="stat-sub" id="s-rate">waiting…</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Unique IPs</div>
    <div class="stat-value" id="s-uniq">0</div>
    <div class="stat-sub" id="s-top-ip">—</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Top Port</div>
    <div class="stat-value" id="s-tp">—</div>
    <div class="stat-sub" id="s-tpc">—</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Last Seen</div>
    <div class="stat-value" id="s-last" style="font-size:15px;padding-top:4px">—</div>
    <div class="stat-sub" id="s-last-proto">—</div>
  </div>
</div>

<div class="workspace">
  <div class="log-panel">
    <div class="log-toolbar">
      <label for="filter-in">Filter:</label>
      <input id="filter-in" class="filter-input" type="text" placeholder="IP, port, protocol…" oninput="applyFilter()">
      <button class="autoscroll-btn on" id="scroll-btn" onclick="toggleScroll(this)" title="Toggle auto-scroll">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="7 13 12 18 17 13"/><polyline points="7 6 12 11 17 6"/>
        </svg>
        Auto-scroll
      </button>
      <span style="margin-left:auto;font-size:11px;color:var(--muted)">
        <span id="row-count">0</span> entries
      </span>
    </div>
    <div class="log-wrap" id="log-wrap">
      <table class="log-table" id="log-table" aria-label="Connection log">
        <thead>
          <tr>
            <th class="col-time">Time</th>
            <th class="col-ip">Source IP</th>
            <th class="col-sport">S.Port</th>
            <th class="col-dport">→ Port</th>
            <th class="col-proto">Protocol</th>
            <th class="col-len">Bytes</th>
            <th class="col-snip">Payload / Info</th>
          </tr>
        </thead>
        <tbody id="log-body"></tbody>
      </table>
      <div class="empty-state" id="empty-state">
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
          <circle cx="20" cy="20" r="16" stroke="currentColor" stroke-width="1.5" opacity=".4"/>
          <circle cx="20" cy="20" r="8"  stroke="currentColor" stroke-width="1.5" opacity=".7"/>
          <circle cx="20" cy="20" r="3"  fill="currentColor"/>
        </svg>
        <p>Waiting for connections.<br>Forward ports to this server to start capturing.</p>
      </div>
    </div>
  </div>

  <aside class="sidebar" aria-label="Statistics">
    <div class="sb-section">
      <div class="sb-title">Top Attackers</div>
      <div id="sb-top-ips"><div style="font-size:11px;color:var(--muted)">No data yet</div></div>
    </div>
    <div class="sb-sep"></div>
    <div class="sb-section">
      <div class="sb-title">By Protocol</div>
      <div id="sb-proto"><div style="font-size:11px;color:var(--muted)">No data yet</div></div>
    </div>
    <div class="sb-sep"></div>
    <div class="sb-section">
      <div class="sb-title">Port Hits</div>
      <div class="port-grid" id="sb-ports"><div style="font-size:11px;color:var(--muted)">No data yet</div></div>
    </div>
  </aside>
</div>

<div class="bottom-bar">
  <span id="b-server">Server: <span style="color:var(--accent)" id="b-host">localhost:8182</span></span>
  <div class="bsep"></div>
  <span id="b-time">—</span>
  <div class="bsep"></div>
  <span id="b-mem">Buffer: 0 / 2000</span>
</div>

<script>
const WS_HOST = location.hostname || 'localhost';
const WS_PORT = 8182;

let ws = null, autoScroll = true, filter = '', allEntries = [], expandedId = null;
let lastTotal = 0, rateTimer = null, rateCount = 0;

const PROTO_CLASS = {
  'SSH':'ssh','TLS/SSL':'tls','RDP':'rdp',
  'HTTP':'http','HTTP CONNECT':'http',
  'SMB':'smb','SMBv2':'smb',
  'Telnet':'telnet','FTP':'ftp',
  'NTLM':'ntlm',
};
function badgeClass(p) {
  for (const [k,v] of Object.entries(PROTO_CLASS)) if (p.startsWith(k)) return v;
  return 'default';
}
function badge(p) {
  return `<span class="badge badge-${badgeClass(p)}">${p}</span>`;
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildRow(e, isNew = false) {
  const cls = isNew ? ' class="new-row"' : '';
  const repeat = e.cnt > 1 ? `<span class="repeat">&times;${e.cnt}</span>` : '';
  return `<tr${cls} data-id="${e.id}" onclick="toggleDetail(${e.id})">
    <td class="col-time">${escHtml(e.ts)}</td>
    <td class="col-ip">${escHtml(e.ip)}${repeat}</td>
    <td class="col-sport">${e.sport}</td>
    <td class="col-dport"><strong style="color:#fff">${e.dport}</strong></td>
    <td class="col-proto">${badge(e.proto)}</td>
    <td class="col-len" style="text-align:right">${e.len > 0 ? e.len : '—'}</td>
    <td class="col-snip">${escHtml(e.snip.slice(0,80))}</td>
  </tr>`;
}

function buildDetail(e) {
  const hex = e.hex ? `<dt>Hex dump</dt><dd class="hex-dump">${escHtml(e.hex)}</dd>` : '';
  return `<tr class="detail-row" data-detail="${e.id}">
    <td colspan="7">
      <dl class="detail-body">
        <dt>Source</dt><dd>${escHtml(e.ip)}:${e.sport}</dd>
        <dt>Target port</dt><dd>${e.dport}</dd>
        <dt>Protocol</dt><dd>${escHtml(e.proto)}</dd>
        <dt>Date</dt><dd>${escHtml(e.date)} ${escHtml(e.ts)}</dd>
        <dt>Payload bytes</dt><dd>${e.len}</dd>
        <dt>Data / Snippet</dt><dd>${escHtml(e.snip)}</dd>
        ${hex}
        <dt>Connections from IP</dt><dd>${e.cnt}</dd>
      </dl>
    </td>
  </tr>`;
}

function toggleDetail(id) {
  const existing = document.querySelector(`[data-detail="${id}"]`);
  if (existing) { existing.remove(); expandedId = null; return; }
  if (expandedId !== null) {
    const old = document.querySelector(`[data-detail="${expandedId}"]`);
    if (old) old.remove();
  }
  const row = document.querySelector(`[data-id="${id}"]`);
  if (!row) return;
  const entry = allEntries.find(e => e.id === id);
  if (!entry) return;
  row.insertAdjacentHTML('afterend', buildDetail(entry));
  expandedId = id;
}

function renderAll() {
  const tbody = document.getElementById('log-body');
  const q = filter.toLowerCase();
  const visible = q
    ? allEntries.filter(e => e.ip.includes(q) || String(e.dport).includes(q) || e.proto.toLowerCase().includes(q) || e.snip.toLowerCase().includes(q))
    : allEntries;
  document.getElementById('row-count').textContent = visible.length;
  tbody.innerHTML = visible.slice(0, 500).map(e => buildRow(e, false)).join('');
  document.getElementById('empty-state').style.display = visible.length ? 'none' : 'flex';
}

function prependEntry(e) {
  allEntries.unshift(e);
  if (allEntries.length > 2000) allEntries.pop();

  const q = filter.toLowerCase();
  const show = !q || e.ip.includes(q) || String(e.dport).includes(q)
    || e.proto.toLowerCase().includes(q) || e.snip.toLowerCase().includes(q);

  const tbody = document.getElementById('log-body');
  const rowCount = tbody.querySelectorAll('tr:not(.detail-row)').length;
  if (rowCount >= 500) {
    const last = tbody.querySelector('tr:not(.detail-row):last-of-type');
    if (last) last.remove();
  }

  if (show) {
    tbody.insertAdjacentHTML('afterbegin', buildRow(e, true));
    document.getElementById('empty-state').style.display = 'none';
  }
  document.getElementById('row-count').textContent = allEntries.length;

  if (autoScroll) document.getElementById('log-wrap').scrollTop = 0;
}

function updateStats(s) {
  const flash = (id, val) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.textContent !== String(val)) {
      el.textContent = val;
      el.classList.remove('flash');
      void el.offsetWidth;
      el.classList.add('flash');
    }
  };
  flash('s-total', s.total);
  flash('s-uniq', s.uniq);
  document.getElementById('s-tp').textContent = s.tp !== '-' ? `:${s.tp}` : '—';
  document.getElementById('s-tpc').textContent = s.tpc ? `${s.tpc} hits` : '';
  document.getElementById('s-top-ip').textContent = s.ti !== '-' ? `Top: ${s.ti} (${s.tic})` : '';

  rateCount++;
}

function updateSidebar(data) {
  // Top IPs
  if (data.top_ips) {
    const ips = Object.entries(data.top_ips).sort((a,b) => b[1]-a[1]).slice(0,8);
    const max = ips[0]?.[1] || 1;
    document.getElementById('sb-top-ips').innerHTML = ips.length
      ? ips.map(([ip,n]) => `<div class="ip-row">
          <div class="ip-addr">${escHtml(ip)}</div>
          <div class="ip-cnt">${n}</div>
        </div>`).join('')
      : '<div style="font-size:11px;color:var(--muted)">No data yet</div>';
  }
  // Protocols
  if (data.by_proto) {
    const protos = Object.entries(data.by_proto).sort((a,b) => b[1]-a[1]).slice(0,8);
    document.getElementById('sb-proto').innerHTML = protos.length
      ? protos.map(([p,n]) => `<div class="proto-row">
          <div class="proto-name">${badge(p)}</div>
          <div class="proto-cnt">${n}</div>
        </div>`).join('')
      : '<div style="font-size:11px;color:var(--muted)">No data yet</div>';
  }
  // Ports
  if (data.by_port) {
    const ports = Object.entries(data.by_port).sort((a,b) => b[1]-a[1]).slice(0,10);
    const max = ports[0]?.[1] || 1;
    document.getElementById('sb-ports').innerHTML = ports.length
      ? ports.map(([p,n]) => `<div class="port-item">
          <div class="pnum">:${p}</div>
          <div class="pbar-wrap"><div class="pbar" style="width:${Math.round(n/max*100)}%"></div></div>
          <div class="pcnt">${n}</div>
        </div>`).join('')
      : '<div style="font-size:11px;color:var(--muted)">No data yet</div>';
  }
}

function setWsStatus(state, label) {
  const el = document.getElementById('ws-status');
  el.className = `ws-status ${state}`;
  document.getElementById('ws-label').textContent = label;
}

function connect() {
  setWsStatus('connecting', 'connecting…');
  ws = new WebSocket(`ws://${WS_HOST}:${WS_PORT}`);

  ws.onopen = () => {
    setWsStatus('connected', 'connected');
    document.getElementById('b-host').textContent = `${WS_HOST}:${WS_PORT}`;
  };

  ws.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'init') {
      allEntries = msg.entries || [];
      renderAll();
      updateStats(msg.stats);
      updateSidebar(msg.stats);
      // Port tags
      const tags = document.getElementById('port-tags');
      tags.innerHTML = (msg.ports || []).slice(0, 10).map(p => `<span class="port-tag">:${p}</span>`).join('');
      document.getElementById('b-mem').textContent = `Buffer: ${allEntries.length} / 2000`;
    } else if (msg.type === 'entry') {
      prependEntry(msg.entry);
      updateStats(msg.stats);
      document.getElementById('s-last').textContent = msg.entry.ts;
      document.getElementById('s-last-proto').textContent = `${msg.entry.ip} → :${msg.entry.dport}`;
      document.getElementById('b-mem').textContent = `Buffer: ${allEntries.length} / 2000`;

      // Rebuild sidebar occasionally (every 5 entries)
      if (msg.stats.total % 5 === 0) {
        // request full sidebar data — we build from allEntries locally
        const byProto = {}, byPort = {}, topIps = {};
        for (const e of allEntries) {
          byProto[e.proto] = (byProto[e.proto]||0)+1;
          byPort[e.dport]  = (byPort[e.dport]||0)+1;
          topIps[e.ip]     = (topIps[e.ip]||0)+1;
        }
        updateSidebar({ by_proto: byProto, by_port: byPort, top_ips: topIps });
      }
    }
  };

  ws.onerror = () => setWsStatus('error', 'error');
  ws.onclose = () => {
    setWsStatus('error', 'disconnected — reconnecting…');
    setTimeout(connect, 3000);
  };
}

function applyFilter() {
  filter = document.getElementById('filter-in').value.trim();
  renderAll();
}

function toggleScroll(btn) {
  autoScroll = !autoScroll;
  btn.classList.toggle('on', autoScroll);
}

function clearLogs() {
  if (!confirm('Clear all log entries from view?')) return;
  allEntries = [];
  document.getElementById('log-body').innerHTML = '';
  document.getElementById('empty-state').style.display = 'flex';
  document.getElementById('row-count').textContent = '0';
  document.getElementById('b-mem').textContent = 'Buffer: 0 / 2000';
}

// Clock
setInterval(() => {
  document.getElementById('b-time').textContent = new Date().toLocaleTimeString();
}, 1000);

connect();
</script>
</body>
</html>"""


if __name__ == "__main__":
    asyncio.run(main())
