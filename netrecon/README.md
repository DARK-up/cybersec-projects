# NetRecon v2.0 — Advanced Network Reconnaissance Framework

A high-performance **asynchronous** network scanning framework built entirely on the
Python standard library (zero third-party dependencies).

## ✨ Features

- **Async port scanning** with high concurrency (up to 2,000 parallel connections)
- **CIDR / IP ranges / hostnames**: `192.168.1.0/24` or `10.0.0.1-50`
- **Accurate service fingerprinting**: banner grabbing + active probes
  (HTTP, SSH, FTP, SMTP, IMAP, MySQL, Redis, VNC, SIP, ...)
- **Software version extraction**: `OpenSSH_8.9p1`, `Apache/2.4.49`, `ProFTPD 1.3.5`, ...
- **OS hinting** from service banners (Linux/Ubuntu, Windows, Cisco, MikroTik, ...)
- **Host discovery** via TCP ping sweep (`--discover`)
- **Timing profiles**: `sneaky` / `normal` / `aggressive` / `insane`
- **Port randomization** (shuffling) to evade naive IDS heuristics
- **Reporting**: colored console + JSON + HTML

## 🚀 Usage

```bash
# Scan the top 100 ports across a subnet
python3 netrecon.py -t 192.168.1.0/24 -p top100

# Scan specific ports with service fingerprinting
python3 netrecon.py -t 10.0.0.5 -p 22,80,443,3306,8080

# Quiet and stealthy scan
python3 netrecon.py -t scanme.example.com -p 1-5000 -T sneaky

# Full port range with host discovery and reports
python3 netrecon.py -t 192.168.1.1-50 -p all --discover \
  --json reports/scan.json --html reports/scan.html

# Fast scan without fingerprinting
python3 netrecon.py -t 10.0.0.0/28 -p top:20 --no-probe
```

### Timing Profiles

| Profile | Concurrency | Timeout | Delay/request | Use case |
|---------|-------------|---------|---------------|----------|
| `sneaky` | 50 | 3.0s | 300ms | IDS evasion |
| `normal` | 300 | 1.2s | 50ms | default |
| `aggressive` | 800 | 0.8s | 0 | fast networks |
| `insane` | 2000 | 0.5s | 0 | lab use only |

## 📊 Sample Output

```
[+] 127.0.0.1:2222   open  SSH (2.0 OpenSSH_8.9p1) | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
[+] 127.0.0.1:8080   open  HTTP/HTTPS (Apache/2.4.49 (Unix))
[+] 127.0.0.1:2121   open  FTP (Pro) | 220 ProFTPD 1.3.5 Server (Debian)
[+] Host 127.0.0.1: 6 open port(s) in 0.81s (OS hint: Linux (Ubuntu/Debian))
```

## 🏗️ Architecture

```
NetRecon
├── parse_targets()       ← CIDR / ranges / hostnames
├── parse_ports()         ← 22,80 | 1-1024 | top100 | all
├── discover_host()       ← TCP ping sweep
├── scan_port()           ← async connect + banner
├── grab_banner()         ← fingerprint DB (25+ signatures)
├── os_hint_from_banner() ← OS estimation
└── save_json/html()      ← reporting
```

## ⚖️ Legal

Only scan networks you own or have explicit authorization to test.
