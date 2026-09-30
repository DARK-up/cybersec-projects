# WebVulnX v2.0 — ماسح ثغرات تطبيقات الويب المتقدم

ماسح ثغرات ويب متكامل: Crawler ذكي + محرك SQLi ثلاثي + XSS + DirBuster + فحص الإعدادات الخاطئة.

## ✨ المميزات

### 🔍 Crawler ذكي
- زحف بنفس النطاق مع تحكم بالعمق (`--depth`) وعدد الصفحات (`--max-urls`)
- استخراج Forms + Parameters تلقائياً
- تجاهل الملفات الثابتة (صور، CSS...)

### 💉 محرك SQL Injection (3 أنواع)
| النوع | الوصف |
|-------|-------|
| **Error-Based** | 30+ توقيع أخطاء DBMS (MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MSAccess, DB2...) |
| **Boolean-Based Blind** | مقارنة الاستجابات بـ `difflib` similarity ratio |
| **Time-Based Blind** | SLEEP / WAITFOR / pg_sleep / DBMS_PIPE مع قياس زمن الاستجابة |

- يختبر: Query params + Form fields + URL path segments الرقمية (`/item/123`)

### 🎯 محرك Reflected XSS
- 14 payload متعدد السياقات (polyglots) مع encoding bypasses
- يمييز بين **Executable XSS** (ينفذ فعلاً) و**Reflected** (يعتمد على السياق)

### 📂 Directory Brute-Force
- 200+ مسار عالي القيمة (.git, .env, backups, admin panels, actuator, swagger...)
- تقييم خطورة تلقائي حسب نوع المسار

### 🔒 فحص الإعدادات الخاطئة
- Security headers (HSTS, CSP, X-Frame-Options...)
- Cookie flags (Secure, HttpOnly)
- HTTP methods خطرة (TRACE/PUT/DELETE)
- Banner disclosure + robots.txt

## 🚀 الاستخدام

```bash
# فحص كامل (كل المحركات)
python3 webvulnx.py -u https://target.example --full

# SQLi + XSS فقط
python3 webvulnx.py -u https://target.example/app --sqli --xss

# Directory busting مع wordlist مخصص
python3 webvulnx.py -u https://target.example --dirs -w wordlists/dirs.txt

# مع تقرير JSON + HTML
python3 webvulnx.py -u https://target.example --full \
  --json reports/scan.json --html reports/scan.html

# خلف بروكسي (Burp Suite) + cookies محددة
python3 webvulnx.py -u https://target.example --full \
  --proxy http://127.0.0.1:8080 --cookie "PHPSESSID=abc123"

# تهرب من WAF بسيط (تأخير بين الطلبات)
python3 webvulnx.py -u https://target.example --sqli --delay 0.5 --time-blind 8
```

## 🧪 جرّبها على معمل التدريب

```bash
cd ../demo-lab && python3 vuln_app.py 8080 &
python3 webvulnx.py -u http://127.0.0.1:8080 --full --time-blind 3
```

نتائج المعمل المتوقعة:
```
[Critical] SQL Injection (Error-Based)   [id]   -> /page?id=1
[High]     SQL Injection (Boolean-Blind) [id]   -> /news?id=1
[High]     SQL Injection (Time-Blind)    [id]   -> /news?id=1
[Critical] SQL Injection (Error-Based)   [user] -> /login  (POST)
[High]     Reflected XSS (Executable)    [q]    -> /search
[High]     Sensitive Path Exposed               -> /.env, /backup.sql
[Medium]   Sensitive Path Exposed               -> /admin
```

## 📊 التقارير

- **Console**: ملون مع severity tags + evidence
- **JSON**: منظم للتحليل الآلي / الدمج مع SIEM
- **HTML**: تقرير عرض احترافي (Dark theme)

## ⚖️ قانوني

لا تفحص إلا تطبيقات تملكها أو لديك تصريح رسمي باختبارها. احصل على **written authorization** دائماً قبل أي اختبار.
