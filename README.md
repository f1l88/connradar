# ConnRadar

**ConnRadar** is a cross-platform network connection monitor that scans your system in real time, detecting every incoming and outgoing connection like a radar sweeps the sky. Lightweight, highly configurable, and built for system administrators, security researchers, and anyone who wants total visibility over their network.

## ✨ Key Features

- **🌍 Cross‑Platform** — Windows, Linux.
- **⚡ Real‑Time Detection** — spots new and disappeared connections at a configurable check interval
- **🎯 Smart Filtering** — allow/block lists for IPs, subnets, ports; ignore private and localhost traffic
- **🔍 Traffic Classification** — identifies direction (incoming/outgoing) and filters by traffic type
- **📝 Structured Logging** — all events are stored in JSONL format and a plain‑text log with automatic rotation
- **🚨 Instant Alerts** — console and file notifications when connections appear or vanish
- **📊 Periodic Reports** — exports a human‑readable summary of current statistics
- **⚙️ Single Configuration File** — every knob is controlled via a clean `config.toml`

## 📦 Installation

### From source (Rust required)
```bash
git clone https://github.com/f1l88/connradar.git
cd connradar
cargo build --release
```
The binary will be located at target/release/connradar (or connradar.exe on Windows).

## 🚀 Quick Start
Run ConnRadar for the first time to generate a default configuration file:

```bash
connradar --config my_config.toml
```

If the file doesn’t exist, it will be created with sensible defaults.

Edit my_config.toml to match your needs (see the configuration section below).

Start monitoring:

```bash
connradar --config my_config.toml
```
## Watch the radar in action:

```text
[INFO] Starting Connection Monitor
[INFO] Check interval: 10s, Alert interval: 5min, Traffic type: All
[INFO] Iteration 1: Active=12, New=3, Disappeared=1, History=15
```

## ⚙️ Configuration
All settings live in a single TOML file. Here is an annotated example:

```toml
[monitor]
alert_interval_minutes = 5        # how often to repeat alerts (minutes)
check_interval_seconds = 10       # connection poll interval (seconds)
max_history_age_days = 30         # remove entries older than this
export_report_interval = 300      # report export interval in seconds (0 to disable)
traffic_type = "all"              # "incoming", "outgoing", or "all"
debug = false                     # write detailed debug info to log file only

[filtering]
ignore_ips = ["192.168.1.100"]    # IPs to completely ignore
ignore_private_ips = true         # skip 10.x.x.x, 192.168.x.x, 172.16–31.x.x
ignore_localhost = true
ignore_ports = [5353, 1900]       # ports to ignore
monitor_only_ports = [443, 80]    # if set, only these ports are tracked
allowed_subnets = ["10.0.0.0/8"]  # optional: restrict monitoring to a subnet
ignore_ipv6 = true

[files]
data_file = "connections.jsonl"   # historical data in JSON Lines
log_file = "connradar.log"        # plain-text log
report_file = "report.txt"        # human-readable report
max_log_size_mb = 10              # maximum size of a single log file
max_log_files = 5                 # number of rotated log files to keep

[alerts]
enable_console_alerts = true
enable_log_alerts = true
alert_on_new_connection = false   # fire an alert for every new connection
alert_on_disconnection = true     # fire an alert when a connection disappears
alert_threshold_count = 100       # if set, alert when total connections exceed this
```

## 📊 Sample Report
When reports are enabled, ConnRadar produces a file like this:

```text
Connection Monitor Report
Generated: 2026-06-21 14:35:00

Statistics:
  - Total connections: 57
  - Incoming: 12
  - Outgoing: 45
  - Currently active: 18

Current Active Connections:
  - 93.184.216.34:80 [TCP] Direction: outgoing (Local: 192.168.1.5:54321)
  ...
```

## 🧪 Testing
Run the unit tests with:

```bash
cargo test
```

## 🛠 Technology Stack
Rust — speed and memory safety
TOML — configuration format
serde / serde_json — serialization
chrono — timestamps
tracing (optional) — structured logging

## 📄 License
This project is licensed under the MIT License. See LICENSE for details.

ConnRadar — know what’s happening on your network at every moment.
⭐ If you find this project useful, please consider giving it a star!