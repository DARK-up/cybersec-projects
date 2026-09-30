# NetSentry v2.0 — محرك كشف تهديدات الشبكة في الوقت الحقيقي

محرك مراقبة وكشف هجمات بالـ Python + Scapy — يجمع بين جانب الهجوم والدفاع (Purple Team).

## ✨ المميزات

### 🕵️ كشف ARP Spoofing / MITM
- **Conflict detection**: نفس الـ IP يدعيه أكثر من MAC
- **Gateway MAC change**: تغيير MAC البوابة المفاجئ
- **ARP reply floods**: انفجارات ARP غير مطلوبة (أداة bettercap/arpspoof)

### 🔦 كشف Port Scanning
- **SYN scan detection**: معدل SYN مرتفع لمنافذ متعددة في نافذة زمنية
- **NULL / XMAS scans**: مسحات خفية (stealth)

### 🌐 مراقبة DNS
- **DNS tunneling**: أسماء domains طويلة/معقدة (iodine, dnscat2)
- **DGA detection**: domains مولّدة خوارزمياً (malware C2)
- **Suspicious TLDs**: .tk/.ml/.xyz مع أرقام

### 🔑 كشف كلمات السر النصية
HTTP Basic Auth, FTP USER/PASS, POP3/IMAP auth, session cookies — كلها في مرور غير مشفّر.

### 📊 الإحصائيات
- عدادات البروتوكولات (TCP/UDP/ARP/ICMP)
- أهم المتصلين (Top talkers)
- توزيع TCP flags

## 🚀 الاستخدام

```bash
# وضع التجربة (بدون Root — حركة مرور اصطناعية)
python3 netsentry.py --demo

# تحليل ملف PCAP (forensics)
python3 netsentry.py --pcap capture.pcapng --report reports/summary.json

# مراقبة حية (تحتاج Root)
sudo python3 netsentry.py --live -i eth0 --gateway 192.168.1.1

# مع BPF filter وحفظ الـ alerts
sudo python3 netsentry.py --live -i wlan0 --filter "arp or tcp" \
  --alert-log reports/alerts.jsonl

# حساسية أعلى لكشف المسحات (10 SYNs = تنبيه)
sudo python3 netsentry.py --live -i eth0 --syn-threshold 10
```

## 🧪 نتائج وضع Demo

```
[CRITICAL] ARP-SPOOF(CONFLICT)   aa:bb:cc:dd:ee:ff -> 192.168.1.1 |
           IP claimed by multiple MACs ['00:11:22:33:44:55', 'aa:bb:cc:dd:ee:ff']
[HIGH]     PORT-SCAN(SYN)        10.0.0.99 -> 192.168.1.10 |
           25 SYNs to 25 distinct ports in 3.0s
[MEDIUM]   PORT-SCAN(XMAS)       10.0.0.99 -> 192.168.1.10
[HIGH]     DNS-TUNNEL            192.168.1.10 -> xkq3j8v1n5m7... | long query name
[HIGH]     CLEARTEXT-CRED        192.168.1.10 -> 10.0.0.5 | FTP USER observed
```

## 🏗️ البنية

```
NetSentry
├── ArpDetector        ← IP↔MAC binding tracking + conflict + gateway watch
├── PortScanDetector   ← SYN rate windows + NULL/XMAS signatures
├── DnsDetector        ← tunnel/DGA/TLD heuristics
├── CredDetector       ← cleartext credential regex engine
├── Stats              ← protocol/talker/flag counters
└── AlertBus           ← console + JSONL logging
```

## 📁 المخرجات

- **Console**: تنبيهات ملونة فورية مع timestamps
- **JSONL log** (`--alert-log`): كل تنبيه في سطر JSON — جاهز للـ SIEM
- **Summary JSON** (`--report`): إحصائيات + ملخص تنبيهات

## ⚖️ قانوني

راقب فقط الشبكات التي تملكها أو مصرح لك بمراقبتها. الالتقاط غير المصرح به غير قانوني.
