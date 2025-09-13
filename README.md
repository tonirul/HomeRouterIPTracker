# 🛰️ Home Router IP Tracker

A simple **web-based network scanner** built with **Flask** that helps you monitor devices on your local network.  
It pings all devices in your subnet, detects their **IP**, **MAC address**, **latency**, and whether they are **online**, and lets you **export results** to Excel or PDF.

---

## ✨ Features
- 🌐 Scan your local subnet (e.g., `192.168.1.1/255.255.255.0`)
- 📡 Detect **online devices** with IP, MAC, latency (ms), last seen
- 📊 Export scan results to **Excel (.xlsx)** and **PDF**
- 🌓 Toggle between **dark** and **light** mode
- ⚡ Built-in **ping tool** for testing external IP/hosts

---

## 📦 Requirements

### Python Version
- Python **3.8+** recommended

### Install dependencies
```bash
pip install -r requirements.txt
requirements.txt should contain:

Flask
pandas
reportlab
openpyxl
⚠️ ping, arp, or ip neigh commands must be available on your system.
Works on Windows, Linux, and macOS (tested on Linux/Windows).

🚀 Running the App
Clone or download this project.

Open a terminal in the project folder.

Start the app:

bash

python network_monitor.py
Open your browser and go to:

cpp

http://127.0.0.1:5000
🖥️ Usage
Enter your network details:

Default Gateway (e.g., 192.168.1.1)

Subnet Mask (e.g., 255.255.255.0)

Click Start Scan
The app will begin scanning all IPs in the subnet.

View results:

Online devices shown as cards with IP, MAC, latency

Status auto-updates every 2 seconds

Use Export to Excel/PDF buttons to save reports.

Use the Ping Tool at the bottom to test external hosts (e.g., 8.8.8.8).

📂 Project Structure
network_monitor.py    # Main Flask app
requirements.txt      # Python dependencies
🛠️ Notes
Scanning may take a few seconds depending on network size.

Export files will be created in the same folder where the script runs.

If MAC addresses do not appear, ensure you have permissions and try running as Administrator (Windows) or with sudo (Linux).

🧑‍💻 Example
Start Scan
Gateway: 192.168.0.1

Mask: 255.255.255.0

Result:

Device 192.168.0.10 → Online, MAC aa:bb:cc:dd:ee:ff, Latency 23ms

Device 192.168.0.15 → Offline

⚖️ License
This project is open-source. Feel free to modify and use it for personal or educational purposes.
