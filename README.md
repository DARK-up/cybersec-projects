# 🛡️ CyberSec Projects — Red Team Portfolio

**4 مشاريع قوية في الأمن السيبراني (Offensive Security) + معمل تدريب آمن**

> ⚖️ **تنبيه قانوني مهم:** هذه الأدوات لأغراض التعليم واختبار الاختراق **القانوني فقط**.
> لا تستخدمها على أنظمة أو شبكات بدون إذن كتابي صريح من المالك. الاستخدام غير المصرح به جريمة.
> أنت المسؤول الوحيد عن طريقة استخدامك لهذه الأدوات.

---

## 📦 المشاريع

| # | المشروع | الوصف | التقنيات |
|---|---------|-------|----------|
| 1 | **[NetRecon](netrecon/)** | إطار استطلاع شبكات متقدم — مسح منافذ async بصمة خدمات، اكتشاف hosts، تقارير HTML/JSON | Python (asyncio) — بدون مكتبات خارجية |
| 2 | **[WebVulnX](webvulnx/)** | ماسح ثغرات تطبيقات ويب — SQLi (Error/Boolean/Time) + XSS + Crawler + DirBuster + Audit | Python (requests, HTMLParser) |
| 3 | **[HashBreaker](hashbreaker/)** | تحديد وكسر الهاشات — Dictionary + Rules + Mask + Multiprocessing + NTLM/MD4 أصلي | Python (multiprocessing) — بدون مكتبات خارجية |
| 4 | **[NetSentry](netsentry/)** | محرك كشف تهديدات الشبكة — ARP Spoof + Port Scan + DNS Tunneling + كشف كلمات السر | Python (scapy) |
| 5 | **[Demo Lab](demo-lab/)** | تطبيق ويب ضعيف عمداً + خدمات وهمية — لتجربة الأدوات بشكل قانوني على جهازك | Python (stdlib) |

---

## 🚀 البدء السريع

```bash
# المتطلبات (NetSentry وWebVulnX فقط)
pip install scapy requests

# 1) شغّل معمل التدريب المحلي
cd demo-lab
python3 vuln_app.py 8080 &        # تطبيق ويب ضعيف على http://127.0.0.1:8080
python3 fake_services.py &        # خدمات وهمية (SSH/FTP/SMTP/IMAP/Redis)

# 2) استكشف الشبكة
cd ../netrecon
python3 netrecon.py -t 127.0.0.1 -p top100 --json reports/scan.json --html reports/scan.html

# 3) امسح تطبيق الويب
cd ../webvulnx
python3 webvulnx.py -u http://127.0.0.1:8080 --full --html reports/web.html

# 4) اكسر هاشات (بيانات تجريبية)
cd ../hashbreaker
python3 hashbreaker.py identify -x 5f4dcc3b5aa765d61d8327deb882cf99
python3 hashbreaker.py crack -x 098f6bcd4621d373cade4e832627b4f6 -w wordlists/common-pass.txt --rules

# 5) راقب الشبكة (وضع التجربة بدون Root)
cd ../netsentry
python3 netsentry.py --demo --report reports/summary.json
# أو لقطة حية (تحتاج Root):
# sudo python3 netsentry.py --live -i eth0 --gateway 192.168.1.1
```

---

## 🎯 المهارات اللي تغطيها المشاريع

### Offensive / Red Team
- **Network Reconnaissance**: TCP scanning, banner grabbing, service fingerprinting, OS hinting
- **Web Application Security**: SQLi (Error / Boolean-Blind / Time-Blind), Reflected XSS, sensitive data exposure, misconfigurations
- **Password Security**: hash identification (25+ صيغة), dictionary/rules/mask attacks, NTLM/MD4 internals
- **Network Attacks Detection**: ARP poisoning, SYN/XMAS scans, DNS tunneling, cleartext credential leakage

### المهارات البرمجية
- Async programming (asyncio) وconcurrency عالي الأداء
- Multiprocessing cracking engine
- Custom protocol fingerprinting database
- Heuristic detection (similarity matching, entropy, rate analysis)
- Pure-Python MD4 implementation (RFC 1320) — fallback when OpenSSL lacks MD4
- Professional reporting (JSON / HTML / JSONL)
- Clean CLI design (argparse) مع timing profiles

---

## 📂 هيكل المشروع

```
cybersec-projects/
├── README.md                  ← أنت هنا
├── netrecon/                  ← مشروع 1: استطلاع الشبكات
│   ├── netrecon.py
│   ├── requirements.txt
│   └── reports/
├── webvulnx/                  ← مشروع 2: ماسح ثغرات الويب
│   ├── webvulnx.py
│   ├── wordlists/dirs.txt
│   └── reports/
├── hashbreaker/               ← مشروع 3: كسر الهاشات
│   ├── hashbreaker.py
│   ├── wordlists/common-pass.txt
│   └── reports/
├── netsentry/                 ← مشروع 4: كشف تهديدات الشبكة
│   ├── netsentry.py
│   └── reports/
└── demo-lab/                  ← معمل التدريب القانوني
    ├── vuln_app.py
    └── fake_services.py
```

---

## ✅ ما تم اختباره فعلياً

| الاختبار | النتيجة |
|----------|---------|
| NetRecon: بصمة SSH/FTP/SMTP/IMAP/Redis/HTTP مع الإصدارات | ✅ |
| NetRecon: OS hint من البانرات + تقارير JSON/HTML | ✅ |
| WebVulnX: SQLi Error-Based (Critical) على /page و/login | ✅ |
| WebVulnX: SQLi Boolean-Blind + Time-Blind على /news | ✅ |
| WebVulnX: Reflected XSS + DirBuster (.env, backup.sql, admin) | ✅ |
| HashBreaker: تحديد MD5/NTLM + كسر Dictionary/Rules/Mask | ✅ |
| HashBreaker: MD4 pure-Python عبر RFC 1320 test vectors كاملة | ✅ |
| NetSentry: كشف ARP Spoof + SYN Scan + DNS Tunnel + Cleartext Creds | ✅ |

---

## 📖 الشهادات والمسار المهني

هذه المشاريع تناسب التحضير لشهادات:
- **OSCP / eJPT / PNPT** (Offensive)
- **CEH / CompTIA Security+** (Foundations)
- **Blue Team Level 1 (BTL1)** (NetSentry يغطي جانب الدفاع)

كل مشروع مصمم كـ **portfolio project** يمكن عرضه في GitHub مع README مستقل ونتائج اختبار حقيقية.
