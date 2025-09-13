# network_monitor.py
import os
import re
import sys
import json
import time
import queue
import threading
import subprocess
import platform
import ipaddress
from datetime import datetime

from flask import Flask, request, jsonify, send_file, Response, redirect, url_for, make_response
from jinja2 import DictLoader, Environment, select_autoescape

# Optional deps for exports
import pandas as pd
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import cm

APP_TITLE = "Home Router IP Tracker"

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# -------------------- In-memory state --------------------
scan_config = {
    "gateway": None,
    "mask": None,
    "network": None,   # ipaddress.IPv4Network
    "running": False
}

devices_lock = threading.Lock()
# devices: { ip: { "ip": str, "mac": str|None, "online": bool, "latency_ms": float|None, "last_seen": ts } }
devices = {}

stop_event = threading.Event()

# -------------------- Utilities --------------------
IS_WINDOWS = platform.system().lower().startswith("win")

def ping_ip(ip: str, timeout_ms: int = 1000):
    """
    Returns (online: bool, latency_ms: float|None).
    Uses system ping for portability.
    """
    if IS_WINDOWS:
        # -n 1 (send 1), -w timeout in ms
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # -c 1 (send 1), -W timeout in seconds (rounded up)
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout_ms/1000.0 + 1))
        output = proc.stdout + "\n" + proc.stderr
        online = proc.returncode == 0

        latency = None
        # Extract latency like time=23ms / time=23.2 ms
        m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", output, re.IGNORECASE)
        if m:
            latency = float(m.group(1))
        else:
            # Some platforms use "Average = Xms" or "avg = X"
            m2 = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.IGNORECASE)
            if m2:
                latency = float(m2.group(1))
        return online, latency
    except Exception:
        return False, None

def get_mac_for_ip(ip: str):
    """
    Try to fetch MAC address from ARP/neighbor table after at least one ping.
    Works on Windows and most Linux; returns None if not found.
    """
    try:
        if IS_WINDOWS:
            # "arp -a ip"
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            out = proc.stdout
            # Lines look like:  192.168.1.23         34-12-98-aa-bb-cc     dynamic
            for line in out.splitlines():
                if ip in line:
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 2 and re.match(r"^[0-9a-f]{2}([-:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$", parts[1], re.IGNORECASE):
                        return parts[1].replace("-", ":").lower()
        else:
            # Prefer "ip neigh show <ip>"
            proc = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2)
            out = proc.stdout
            # e.g.: "192.168.1.10 dev wlan0 lladdr a4:xx:xx:xx:xx:2a REACHABLE"
            m = re.search(r"lladdr\s+([0-9a-f:]{17})", out, re.IGNORECASE)
            if m:
                return m.group(1).lower()
            # Fallback to arp -n
            proc2 = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            out2 = proc2.stdout
            m2 = re.search(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", out2, re.IGNORECASE)
            if m2:
                return m2.group(1).lower()
    except Exception:
        pass
    return None

def calc_network(gateway: str, mask: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network((gateway, mask), strict=False)

def host_ips_in_network(net: ipaddress.IPv4Network):
    # Return iterable of usable hosts (skip network/broadcast)
    return [str(ip) for ip in net.hosts()]

# -------------------- Scanner thread --------------------
def scanner_loop():
    while not stop_event.is_set():
        if not scan_config["running"] or not scan_config["network"]:
            time.sleep(0.5)
            continue

        ips = host_ips_in_network(scan_config["network"])
        # Scan in small thread pool
        q = queue.Queue()
        for ip in ips:
            q.put(ip)

        results = []

        def worker():
            while not q.empty():
                try:
                    ip = q.get_nowait()
                except queue.Empty:
                    return
                online, latency = ping_ip(ip, timeout_ms=800)
                mac = None
                if online:
                    mac = get_mac_for_ip(ip)
                results.append((ip, online, latency, mac))
                q.task_done()

        threads = []
        max_threads = min(64, max(8, os.cpu_count() or 8))
        for _ in range(max_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=5)

        now = time.time()
        with devices_lock:
            for ip, online, latency, mac in results:
                d = devices.get(ip, {"ip": ip, "mac": None, "online": False, "latency_ms": None, "last_seen": None})
                d["online"] = bool(online)
                d["latency_ms"] = float(latency) if latency is not None else None
                if mac:
                    d["mac"] = mac
                if online:
                    d["last_seen"] = now
                devices[ip] = d

        # Pace scans (adjust interval to be friendly)
        time.sleep(3)

# Start background scanner
threading.Thread(target=scanner_loop, daemon=True).start()

# -------------------- Templates --------------------
TEMPLATES = {
"base.html": r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{{ title }}</title>
  <style>
    :root {
      --bg: #0b1220;
      --card: #111a2b;
      --muted: #8aa0c7;
      --text: #e6eefc;
      --green: #2ecc71;
      --red: #e74c3c;
      --accent: #5b8cff;
      --ring: rgba(91,140,255,0.3);
    }
    body.light {
      --bg: #f5f7fb;
      --card: #ffffff;
      --muted: #606b85;
      --text: #1a1d29;
      --green: #27ae60;
      --red: #c0392b;
      --accent: #3366ff;
      --ring: rgba(51,102,255,0.25);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial;
      background: var(--bg);
      color: var(--text);
      transition: background 0.3s, color 0.3s;
    }
    header {
      padding: 18px 16px; border-bottom: 1px solid #1c2840; position: sticky; top: 0; backdrop-filter: blur(8px);
      background: rgba(11,18,32,0.7);
      z-index: 10; display: flex; justify-content: space-between; align-items: center;
    }
    body.light header { background: rgba(255,255,255,0.8); border-bottom: 1px solid #ddd; }
    .container { max-width: 1200px; margin: 0 auto; padding: 16px; }
    h1 { font-size: 20px; margin: 0; letter-spacing: 0.3px; }
    .theme-toggle {
      border: 1px solid #334973; background: var(--card); padding: 6px 12px; border-radius: 8px;
      cursor: pointer; font-size: 12px; color: var(--text);
    }
    .row { display: grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 640px) { .row { grid-template-columns: repeat(2, minmax(0,1fr)); } }
    @media (min-width: 1024px) { .row { grid-template-columns: repeat(4, minmax(0,1fr)); } }
    .panel {
      background: var(--card); border: 1px solid #1b2a45; border-radius: 16px; padding: 14px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }
    body.light .panel { border: 1px solid #ddd; }
    .panel h2 { margin: 0 0 10px; font-size: 16px; color: var(--text); }
    .form-grid { display: grid; gap: 10px; grid-template-columns: 1fr; }
    @media (min-width: 640px) { .form-grid { grid-template-columns: 1fr 1fr 120px; align-items: end; } }
    label { font-size: 12px; color: var(--muted); display: block; margin-bottom: 6px; }
    input[type=text] {
      width: 100%; padding: 10px 12px; border-radius: 12px; border: 1px solid #213252; background: #0c1424; color: var(--text);
      outline: none; transition: box-shadow .2s, border-color .2s, background .2s;
    }
    body.light input[type=text] { background: #fff; border: 1px solid #ccc; }
    input[type=text]:focus { border-color: var(--accent); box-shadow: 0 0 0 6px var(--ring); }
    button, .btn {
      border: 1px solid #334973; background: #16233b; color: var(--text); padding: 10px 12px; border-radius: 12px; cursor: pointer;
      transition: background .2s, border-color .2s, box-shadow .2s;
      text-decoration: none; display: inline-flex; align-items: center; gap: 8px; justify-content: center;
    }
    body.light button, body.light .btn { background: #f5f7fb; border: 1px solid #ccc; }
    button:hover, .btn:hover { background: #1a2a47; }
    body.light button:hover, body.light .btn:hover { background: #e9ecf5; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .cards { display: grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 640px) { .cards { grid-template-columns: repeat(2, minmax(0,1fr)); } }
    @media (min-width: 1024px) { .cards { grid-template-columns: repeat(4, minmax(0,1fr)); } }
    .card {
      background: var(--card); border: 1px solid #203457; border-radius: 16px; padding: 14px; min-height: 120px;
      display: flex; flex-direction: column; gap: 8px; transition: background 0.3s, border-color 0.3s;
    }
    body.light .card { border: 1px solid #ddd; }
    .rowline { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .muted { color: var(--muted); font-size: 12px; }
    .ip { font-weight: 700; letter-spacing: 0.2px; }
    .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; margin-right: 6px; }
    .online { background: var(--green); }
    footer { margin-top: 16px; }
    .small { font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>{{ title }}</h1>
    </div>
    <button class="theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
  </header>

  <main class="container">
    <!-- unchanged content -->
    <div class="panel">
      <h2>Scan Settings</h2>
      <div class="form-grid">
        <div>
          <label>Default Gateway (e.g., 192.168.1.1)</label>
          <input id="gateway" type="text" placeholder="192.168.1.1" />
        </div>
        <div>
          <label>Subnet Mask (e.g., 255.255.255.0)</label>
          <input id="mask" type="text" placeholder="255.255.255.0" />
        </div>
        <div>
          <button id="startBtn" onclick="startScan()">Start Scan</button>
        </div>
      </div>
      <div class="actions" style="margin-top:10px">
        <button onclick="stopScan()">Stop Scan</button>
        <a class="btn" href="/export/excel" target="_blank">Export to Excel</a>
        <a class="btn" href="/export/pdf" target="_blank">Export to PDF</a>
      </div>
    </div>

    <div style="margin-top:12px" class="panel">
      <h2>Online Devices</h2>
      <div id="cards" class="cards"></div>
      <div class="muted small" id="summary"></div>
    </div>

    <footer class="panel">
      <h2>Ping an external IP / Host</h2>
      <div class="grid-2">
        <input id="pingTarget" type="text" placeholder="8.8.8.8" />
        <button onclick="doPing()">Ping</button>
      </div>
      <div id="pingResult" class="small" style="margin-top:8px; white-space:pre-wrap"></div>
    </footer>
  </main>

  <script>
    // Theme handling
    function applyTheme(theme) {
      if (theme === "light") document.body.classList.add("light");
      else document.body.classList.remove("light");
      localStorage.setItem("theme", theme);
    }
    function toggleTheme() {
      const isLight = document.body.classList.contains("light");
      applyTheme(isLight ? "dark" : "light");
    }
    (function initTheme() {
      const saved = localStorage.getItem("theme") || "dark";
      applyTheme(saved);
    })();

    // Existing scan code...
    let polling = null;
    async function startScan() {
      const gateway = document.getElementById('gateway').value.trim();
      const mask = document.getElementById('mask').value.trim();
      if (!gateway || !mask) { alert("Please enter both."); return; }
      const res = await fetch('/scan/start', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ gateway, mask })
      });
      const data = await res.json();
      if (data.ok) { beginPolling(); }
      else alert(data.error || 'Failed');
    }
    async function stopScan() {
      await fetch('/scan/stop', { method: 'POST' });
      endPolling();
    }
    function beginPolling() {
      if (polling) return; polling = setInterval(fetchStatus, 2000); fetchStatus();
    }
    function endPolling() { if (polling) { clearInterval(polling); polling = null; } }
    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const onlineOnly = (data.devices || []).filter(d => d.online);
        renderCards(onlineOnly);
        document.getElementById('summary').textContent = 
          `Updated: ${new Date().toLocaleTimeString()} • Online devices: ${onlineOnly.length}`;
      } catch {}
    }
    function renderCards(items) {
      const parent = document.getElementById('cards');
      parent.innerHTML = '';
      items.sort((a,b) => (a.ip > b.ip ? 1 : -1));
      for (const d of items) {
        const el = document.createElement('div');
        el.className = 'card';
        el.innerHTML = `
          <div class="rowline">
            <div class="ip">${d.ip}</div>
            <div class="muted"><span class="dot online"></span>Online</div>
          </div>
          <div class="rowline small"><span class="muted">Latency</span><span>${d.latency_ms?.toFixed(1) || '—'} ms</span></div>
          <div class="rowline small"><span class="muted">MAC</span><span>${d.mac || '—'}</span></div>
        `;
        parent.appendChild(el);
      }
    }
    async function doPing() {
      const target = document.getElementById('pingTarget').value.trim();
      const out = document.getElementById('pingResult');
      out.textContent = 'Pinging…';
      const res = await fetch('/ping', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ target })
      });
      const data = await res.json();
      if (data.ok) {
        out.textContent = `Online: ${data.online ? 'yes' : 'no'}\nLatency: ${data.latency_ms?.toFixed(1) || '—'} ms`;
      } else {
        out.textContent = data.error || 'Ping failed';
      }
    }
  </script>
</body>
</html>

""",
}

env = Environment(
    loader=DictLoader(TEMPLATES),
    autoescape=select_autoescape(['html', 'xml'])
)

# -------------------- Routes --------------------
@app.route("/")
def index():
    tpl = env.get_template("base.html")
    return tpl.render(title=APP_TITLE)

@app.route("/scan/start", methods=["POST"])
def start_scan():
    try:
        payload = request.get_json(force=True)
        gw = payload.get("gateway", "").strip()
        mask = payload.get("mask", "").strip()

        # Basic validation of IPv4 dotted-quad
        def valid_ip(s): 
            try:
                ipaddress.IPv4Address(s); return True
            except: return False

        if not (valid_ip(gw) and valid_ip(mask)):
            return jsonify({"ok": False, "error": "Enter valid IPv4 gateway and subnet mask (xxx.xxx.xxx.xxx)."}), 400

        net = calc_network(gw, mask)
        with devices_lock:
            # Initialize device list for this network (keep history if previously scanned)
            for ip in host_ips_in_network(net):
                if ip not in devices:
                    devices[ip] = {"ip": ip, "mac": None, "online": False, "latency_ms": None, "last_seen": None}

        scan_config["gateway"] = gw
        scan_config["mask"] = mask
        scan_config["network"] = net
        scan_config["running"] = True
        return jsonify({"ok": True, "network": str(net)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/scan/stop", methods=["POST"])
def stop_scan():
    scan_config["running"] = False
    return jsonify({"ok": True})

@app.route("/api/status")
def api_status():
    with devices_lock:
        data = list(devices.values())
    # only include IPs that are within the active network (if set)
    if scan_config["network"]:
        net = scan_config["network"]
        data = [d for d in data if ipaddress.IPv4Address(d["ip"]) in net]
    # Return friendly JSON
    return jsonify({
        "devices": [
            {
                "ip": d["ip"],
                "mac": d.get("mac"),
                "online": bool(d.get("online")),
                "latency_ms": d.get("latency_ms"),
                "last_seen": d.get("last_seen")
            } for d in sorted(data, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
        ],
        "running": scan_config["running"],
        "network": str(scan_config["network"]) if scan_config["network"] else None,
        "timestamp": time.time()
    })

@app.route("/ping", methods=["POST"])
def ping_route():
    try:
        target = request.get_json(force=True).get("target", "").strip()
        if not target:
            return jsonify({"ok": False, "error": "Please provide a target (IP/hostname)."}), 400
        online, latency = ping_ip(target, timeout_ms=1500)
        return jsonify({"ok": True, "online": online, "latency_ms": latency})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------- Exports --------------------
def current_devices_dataframe():
    with devices_lock:
        data = list(devices.values())
    if scan_config["network"]:
        net = scan_config["network"]
        data = [d for d in data if ipaddress.IPv4Address(d["ip"]) in net]
    rows = []
    for d in sorted(data, key=lambda x: tuple(int(p) for p in x["ip"].split("."))):
        rows.append({
            "IP": d["ip"],
            "MAC": d.get("mac") or "",
            "Online": "Yes" if d.get("online") else "No",
            "Latency (ms)": d.get("latency_ms"),
            "Last Seen": datetime.fromtimestamp(d["last_seen"]).strftime("%Y-%m-%d %H:%M:%S") if d.get("last_seen") else ""
        })
    df = pd.DataFrame(rows, columns=["IP","MAC","Online","Latency (ms)","Last Seen"])
    return df

@app.route("/export/excel")
def export_excel():
    df = current_devices_dataframe()
    fname = f"network_scan_{int(time.time())}.xlsx"
    path = os.path.join(os.getcwd(), fname)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Devices")
    return send_file(path, as_attachment=True, download_name=fname)

@app.route("/export/pdf")
def export_pdf():
    df = current_devices_dataframe()
    fname = f"network_scan_{int(time.time())}.pdf"
    path = os.path.join(os.getcwd(), fname)

    # Landscape A4
    c = canvas.Canvas(path, pagesize=landscape(A4))
    width, height = landscape(A4)

    title = f"{APP_TITLE} — Export @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2*cm, height - 1.5*cm, title)

    # Table drawing
    cols = ["IP", "MAC", "Online", "Latency (ms)", "Last Seen"]
    x0 = 2*cm
    y0 = height - 3*cm
    row_h = 0.8*cm
    col_w = [5*cm, 7*cm, 3*cm, 4*cm, 7*cm]

    # Header
    c.setFont("Helvetica-Bold", 10)
    x = x0
    for i, col in enumerate(cols):
        c.drawString(x + 4, y0, col)
        x += col_w[i]
    c.line(x0, y0-3, x0+sum(col_w), y0-3)

    # Rows
    c.setFont("Helvetica", 10)
    y = y0 - row_h
    for _, r in df.iterrows():
        x = x0
        vals = [str(r[c]) if not pd.isna(r[c]) else "" for c in cols]
        # new page if needed
        if y < 2*cm:
            c.showPage()
            c.setFont("Helvetica-Bold", 14)
            c.drawString(2*cm, height - 1.5*cm, title + " (cont.)")
            c.setFont("Helvetica-Bold", 10)
            x = x0; y = height - 3*cm
            for i, col in enumerate(cols):
                c.drawString(x + 4, y, col); x += col_w[i]
            c.line(x0, y-3, x0+sum(col_w), y-3)
            c.setFont("Helvetica", 10)
            y -= row_h

        x = x0
        for i, val in enumerate(vals):
            c.drawString(x + 4, y, val)
            x += col_w[i]
        y -= row_h

    c.showPage()
    c.save()
    return send_file(path, as_attachment=True, download_name=fname)

# -------------------- Main --------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f" * Starting {APP_TITLE} at http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
