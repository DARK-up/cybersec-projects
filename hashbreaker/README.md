# HashBreaker v2.0 — تحديد وكسر الهاشات المتقدم

أداة متكاملة لتحديد نوع الهاش وكسره بـ Dictionary + Rules + Mask attacks مع multiprocessing.

## ✨ المميزات

### 🔎 محرك تحديد الهاشات (25+ صيغة)
MD5, MD4, SHA1, SHA2 family, **NTLM**, LM, MySQL 3.x/4.1+, MSSQL 2000/2005+,
bcrypt, sha256/512crypt, md5crypt, apr1, phpass (WordPress/phpBB), Django (SHA/PBKDF2),
LDAP SSHA, Argon2, yescrypt, scrypt, Base64-encoded...

### 💥 محرك الكسر
| Mode | الوصف |
|------|-------|
| **Dictionary** | قوائم كلمات مع دعم multi-target |
| **Rules** | 25+ قاعدة تحويل (capitalize, leet, append years/symbols, reverse...) |
| **Mask** | brute-force موجه: `?l?l?d?d` مع charsets مخصصة |
| **Hybrid** | Dictionary + Rules + Mask معاً |
| **Multiprocessing** | يستخدم كل أنوية المعالج |
| **Salted** | md5+salt, sha256+salt, hmac-sha256/sha512 |
| **pwdump/shadow** | يقرأ ملفات Windows pwdump وLinux shadow مباشرة |

### 🧠 ميزة خاصة: MD4 Pure-Python
OpenSSL 3 شال MD4 من الـ default provider — فـ NTLM/MD4/LM بتكسر عادياً
عن طريق **MD4 fallback مكتوب من الصفر (RFC 1320)** — متحقق منه بـ official test vectors.

## 🚀 الاستخدام

```bash
# تحديد نوع هاش
python3 hashbreaker.py identify -x 5f4dcc3b5aa765d61d8327deb882cf99
python3 hashbreaker.py identify -f hashes.txt

# كسر بـ Dictionary + Rules
python3 hashbreaker.py crack -f hashes.txt -w wordlists/common-pass.txt --rules

# كسر NTLM بـ Mask (4 أحرف صغيرة)
python3 hashbreaker.py crack -x 0cb6948805f797bf2a82807973b89537 -a ntlm --mask '?l?l?l?l'

# هاش مملح
python3 hashbreaker.py crack -x <sha256-hex> -a sha256+salt -s "mysalt" -w wordlist.txt

# ملف pwdump كامل (عدة مستخدمين)
python3 hashbreaker.py crack -f pwdump.txt -w wordlists/common-pass.txt --rules \
  --json reports/cracked.json

# قياس سرعة الخوارزميات
python3 hashbreaker.py benchmark
```

### Mask tokens
| Token | Charset |
|-------|---------|
| `?l` | abcdefghijklmnopqrstuvwxyz |
| `?u` | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| `?d` | 0123456789 |
| `?s` | special chars |
| `?a` | كل ما سبق |
| `?h` / `?H` | hex lowercase / uppercase |
| `?X=abc` | charset مخصص (`--charset`) |

## 📊 مثال على الإخراج

```
[+] Wordlist: wordlists/common-pass.txt (159 words)
[*] Workers: 8 | Targets: 3 | Rules: ON | Mask: OFF
[FOUND] user=admin algo=md5 password=password
[FOUND] user=guest algo=md5 password=test
[+] Done in 0.04s | rate ≈ 306,664 H/s | cracked 2/3
```

## 📁 صيغة ملف الهاشات

```
5f4dcc3b5aa765d61d8327deb882cf99          # هاش فقط
admin:5f4dcc3b5aa765d61d8327deb882cf99    # user:hash
bob:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::   # pwdump
alice:$6$salt$hash...                      # shadow
```

## ⚖️ قانوني

لا تكسر هاشات إلا ضمن تدقيق مصرح به (مثلاً: تدقيق كلمات السر لمؤسستك).
