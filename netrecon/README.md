# NetRecon v2.0 — إطار استطلاع الشبكات المتقدم

أداة مسح شبكات **asynchronous** عالية الأداء مبنية بالكامل على Python Standard Library (بدون أي مكتبات خارجية).

## ✨ المميزات

- **مسح منافذ async** بسرعة عالية (حتى 2000 اتصال متزامن)
- **دعم CIDR / IP ranges / Hostnames**: `192.168.1.0/24` أو `10.0.0.1-50`
- **بصمة خدمات دقيقة**: banner grabbing + probes نشطة (HTTP, SSH, FTP, SMTP, IMAP, MySQL, Redis, VNC, SIP...)
- **استخراج إصدارات البرامج**: `OpenSSH_8.9p1`, `Apache/2.4.49`, `ProFTPD 1.3.5` ...
- **تخمين نظام التشغيل** من البانرات (Linux/Ubuntu, Windows, Cisco, MikroTik...)
- **اكتشاف hosts** عبر TCP ping sweep (`--discover`)
- **ملفات توقيت**: `sneaky` / `normal` / `aggressive` / `insane`
- **عشوائية المنافذ** (shuffle) لتفادي كشف IDS البسيط
- **تقارير**: Console ملون + JSON + HTML

## 🚀 الاستخدام

```bash
# مسح top 100 منافذ لشبكة كاملة
python3 netrecon.py -t 192.168.1.0/24 -p top100

# مسح منافذ محددة مع بصمة خدمات
python3 netrecon.py -t 10.0.0.5 -p 22,80,443,3306,8080

# مسح سريع وخفية
python3 netrecon.py -t scanme.example.com -p 1-5000 -T sneaky

# كل المنافذ مع اكتشاف المضيفين وتقارير
python3 netrecon.py -t 192.168.1.1-50 -p all --discover \
  --json reports/scan.json --html reports/scan.html

# مسح بدون بصمة (أسرع)
python3 netrecon.py -t 10.0.0.0/28 -p top:20 --no-probe
```

### خيارات التوقيت

| Profile | التزامن | Timeout | المهلة بين الطلبات | الاستخدام |
|---------|---------|---------|-------------------|-----------|
| `sneaky` | 50 | 3.0s | 300ms | تهرب من IDS |
| `normal` | 300 | 1.2s | 50ms | افتراضي |
| `aggressive` | 800 | 0.8s | 0 | شبكات سريعة |
| `insane` | 2000 | 0.5s | 0 | lab فقط |

## 📊 مثال على الإخراج

```
[+] 127.0.0.1:2222   open  SSH (2.0 OpenSSH_8.9p1) | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
[+] 127.0.0.1:8080   open  HTTP/HTTPS (Apache/2.4.49 (Unix))
[+] 127.0.0.1:2121   open  FTP (Pro) | 220 ProFTPD 1.3.5 Server (Debian)
[+] Host 127.0.0.1: 6 open port(s) in 0.81s (OS hint: Linux (Ubuntu/Debian))
```

## 🏗️ البنية

```
NetRecon
├── parse_targets()      ← CIDR / ranges / hostnames
├── parse_ports()        ← 22,80 | 1-1024 | top100 | all
├── discover_host()      ← TCP ping sweep
├── scan_port()          ← async connect + banner
├── grab_banner()        ← fingerprint DB (25+ توقيع)
├── os_hint_from_banner()← OS estimation
└── save_json/html()     ← reporting
```

## ⚖️ قانوني

استخدم الأداة فقط على الشبكات التي تملكها أو لديك إذن باختبارها.
