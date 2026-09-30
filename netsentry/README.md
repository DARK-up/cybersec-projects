# NetSentry v2.0 — Real-Time Network Threat Detection Engine

A Python + Scapy network monitoring and attack-detection engine — bridging
offense and defense (Purple Team style).

## ✨ Features

### 🕵️ ARP Spoofing / MITM Detection
- **Conflict detection**: one IP claimed by multiple MAC addresses
- **Gateway MAC change**: unexpected gateway hardware-address changes
- **ARP reply floods**: bursts of unsolicited ARP replies (bettercap / arpspoof style)

### 🔦 Port-Scan Detection
- **SYN scan detection**: high SYN rate to many distinct ports inside a sliding window
- **NULL / XMAS scans**: stealth scan signatures

### 🌐 DNS Monitoring
- **DNS tunneling**: unusually long / complex query names (iodine, dnscat2)
- **DGA detection**: algorithmically generated domains (malware C2)
- **Suspicious TLDs**: `.tk` / `.ml` / `.xyz` combined with numeric labels

### 🔑 Cleartext Credential Exposure
HTTP Basic Auth, FTP USER/PASS, POP3/IMAP auth, session cookies — anything
crossing the wire unencrypted.

### 📊 Traffic Statistics
- Protocol counters (TCP/UDP/ARP/ICMP)
- Top talkers
- TCP flag distribution

## 🚀 Usage

```bash
# Demo mode (no root — synthetic attack traffic)
python3 netsentry.py --demo

# Offline PCAP forensics
python3 netsentry.py --pcap capture.pcapng --report reports/summary.json

# Live capture (requires root)
sudo python3 netsentry.py --live -i eth0 --gateway 192.168.1.1

# With a BPF filter and JSONL alert logging
sudo python3 netsentry.py --live -i wlan0 --filter "arp or tcp" \
  --alert-log reports/alerts.jsonl

# More sensitive scan detection (10 SYNs = alert)
sudo python3 netsentry.py --live -i eth0 --syn-threshold 10
```

## 🧪 Demo Mode Results

```
[CRITICAL] ARP-SPOOF(CONFLICT)   aa:bb:cc:dd:ee:ff -> 192.168.1.1 |
           IP claimed by multiple MACs ['00:11:22:33:44:55', 'aa:bb:cc:dd:ee:ff']
[HIGH]     PORT-SCAN(SYN)        10.0.0.99 -> 192.168.1.10 |
           25 SYNs to 25 distinct ports in 3.0s
[MEDIUM]   PORT-SCAN(XMAS)       10.0.0.99 -> 192.168.1.10
[HIGH]     DNS-TUNNEL            192.168.1.10 -> xkq3j8v1n5m7... | long query name
[HIGH]     CLEARTEXT-CRED        192.168.1.10 -> 10.0.0.5 | FTP USER observed
```

## 🏗️ Architecture

```
NetSentry
├── ArpDetector        ← IP↔MAC binding tracking + conflict + gateway watch
├── PortScanDetector   ← SYN rate windows + NULL/XMAS signatures
├── DnsDetector        ← tunnel / DGA / suspicious-TLD heuristics
├── CredDetector       ← cleartext credential regex engine
├── Stats              ← protocol / talker / flag counters
└── AlertBus           ← console + JSONL logging
```

## 📁 Outputs

- **Console**: live color-coded alerts with timestamps
- **JSONL log** (`--alert-log`): one JSON object per alert — SIEM-ready
- **Summary JSON** (`--report`): statistics + alert breakdown

## ⚖️ Legal

Only monitor networks you own or are explicitly authorized to observe.
Unauthorized packet capture is illegal.
