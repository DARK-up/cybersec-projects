# Demo Lab — معمل التدريب الآمن ⚠️

تطبيق ويب **ضعيف عمداً** + خدمات وهمية، لتجربة أدوات NetRecon / WebVulnX بشكل **قانوني 100%** على جهازك.

> 🚨 **تحذير**: هذا التطبيق غير آمن **عن قصد**. لا ترفعه على أي شبكة عامة أو خادم إنتاج أبداً.

## 🚀 التشغيل

```bash
# النافذة 1: تطبيق الويب الضعيف (port 8080)
python3 vuln_app.py 8080

# النافذة 2: خدمات وهمية لبصمة NetRecon
python3 fake_services.py
```

## 🎯 الثغرات المزروعة (لتجربة الكشف)

| المسار | الثغرة | الأداة التي تكشفها |
|--------|--------|-------------------|
| `/search?q=` | Reflected XSS (انعكاس خام) | WebVulnX XSS engine |
| `/page?id=` | SQLi Error-Based (رسالة خطأ MySQL) | WebVulnX SQLi engine |
| `/news?id=` | SQLi Boolean + Time-Based Blind | WebVulnX SQLi engine |
| `/login` (POST) | SQLi في حقل user | WebVulnX SQLi engine |
| `/admin` | لوحة إدارة مخفية | DirBuster |
| `/backup.sql` | تسريب قاعدة بيانات | DirBuster (High) |
| `/robots.txt` | يكشف /secret-panel | DirBuster + Audit |
| `/\.env` | تسريب أسرار (DB_PASS, API_KEY) | DirBuster (High) |
| Headers | لا توجد security headers + banner disclosure | Misconfig Audit |

## 🔧 الخدمات الوهمية (fake_services.py)

| المنفذ | الخدمة | البانر |
|--------|--------|--------|
| 2222 | SSH | OpenSSH_8.9p1 Ubuntu |
| 2121 | FTP | ProFTPD 1.3.5 (Debian) |
| 2525 | SMTP | Postfix (Ubuntu) |
| 1143 | IMAP | Dovecot |
| 6380 | Redis | +PONG |

## 🧪 سيناريو تدريب كامل

```bash
# 1) شغّع المعمل
python3 vuln_app.py 8080 &
python3 fake_services.py &

# 2) استكشف بالـ NetRecon
cd ../netrecon
python3 netrecon.py -t 127.0.0.1 -p 2222,2121,2525,6380,1143,8080 --no-resolve

# 3) امسح الويب بـ WebVulnX
cd ../webvulnx
python3 webvulnx.py -u http://127.0.0.1:8080 --full --time-blind 3 \
  --json reports/lab.json --html reports/lab.html

# 4) افتح التقرير
# reports/lab.html
```

## 📝 ملاحظة

كل "الثغرات" هنا محاكاة بسيطة (Python stdlib فقط) — الهدف تعليم تدفق عمل
الفحص الأمني كامل: Recon → Crawl → Vuln scan → Report.
