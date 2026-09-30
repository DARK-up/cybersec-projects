# HashBreaker v2.0 — Advanced Hash Identification & Cracking Suite

A complete hash identification and password recovery toolkit with dictionary,
rules, and mask attacks — powered by a multiprocessing cracking engine.

## ✨ Features

### 🔎 Hash Identification Engine (25+ formats)
MD5, MD4, SHA1, SHA2 family, **NTLM**, LM, MySQL 3.x / 4.1+, MSSQL 2000/2005+,
bcrypt, sha256/512crypt, md5crypt, apr1, phpass (WordPress / phpBB),
Django (SHA / PBKDF2), LDAP SSHA, Argon2, yescrypt, scrypt, Base64-encoded, ...

### 💥 Cracking Engine
| Mode | Description |
|------|-------------|
| **Dictionary** | Wordlists with multi-target support |
| **Rules** | 25+ mangling rules (capitalize, leet, append years/symbols, reverse, ...) |
| **Mask** | Targeted brute-force: `?l?l?d?d` with custom charsets |
| **Hybrid** | Dictionary + rules + mask combined |
| **Multiprocessing** | Utilizes all CPU cores |
| **Salted hashes** | md5+salt, sha256+salt, hmac-sha256/sha512 |
| **pwdump / shadow** | Parses Windows pwdump and Linux shadow files directly |

### 🧠 Highlight: Pure-Python MD4
OpenSSL 3 removed MD4 from the default provider — so NTLM / MD4 / LM cracking
works anyway through a **from-scratch MD4 fallback (RFC 1320)**, validated
against the complete official test-vector suite.

## 🚀 Usage

```bash
# Identify a hash type
python3 hashbreaker.py identify -x 5f4dcc3b5aa765d61d8327deb882cf99
python3 hashbreaker.py identify -f hashes.txt

# Dictionary attack with rules
python3 hashbreaker.py crack -f hashes.txt -w wordlists/common-pass.txt --rules

# Crack NTLM with a 4-char lowercase mask
python3 hashbreaker.py crack -x 0cb6948805f797bf2a82807973b89537 -a ntlm --mask '?l?l?l?l'

# Salted hash
python3 hashbreaker.py crack -x <sha256-hex> -a sha256+salt -s "mysalt" -w wordlist.txt

# Full pwdump file (multiple users)
python3 hashbreaker.py crack -f pwdump.txt -w wordlists/common-pass.txt --rules \
  --json reports/cracked.json

# Benchmark the algorithms
python3 hashbreaker.py benchmark
```

## 📚 Wordlists

| File | Words | Purpose |
|------|-------|---------|
| `wordlists/common-pass.txt` | ~160 | Instant smoke test — **will not crack real passwords** |
| `wordlists/rockyou.txt` | 14,344,392 | The real thing. Not in git (GitHub rejects files >100 MB) |

Get rockyou (one command, Kali/Linux or Windows):

```bash
# Kali / Linux / macOS  — reuses /usr/share/wordlists/rockyou.txt.gz when present
./get-rockyou.sh
```

```bat
:: Windows — double-click, or run from cmd
get-rockyou.bat
```

Kali ships it already, so this also works with no download:

```bash
sudo apt install wordlists
gunzip -k /usr/share/wordlists/rockyou.txt.gz
ln -s /usr/share/wordlists/rockyou.txt wordlists/rockyou.txt
```

Then crack with it:

```bash
python3 hashbreaker.py crack -x 5f4dcc3b5aa765d61d8327deb882cf99 \
  -w wordlists/rockyou.txt --workers 4
# [+] CRACKED  5f4dcc3b5aa765d61d8327deb882cf99  ->  password
```

**Performance notes**

- rockyou is streamed line-by-line; it is never loaded into RAM (139 MB as a
  Python list would need several GB). Observed throughput: **~740 kH/s** for
  MD5/SHA-1 on 4 workers, and cracking stops the moment every target is found.
- **Mangling rules are skipped automatically** for wordlists above 250 k words
  (`14.3 M × ~10 rules = 100 M+ attempts`, i.e. hours). Rules stay on for small
  lists and for mask attacks.
- If a hash survives the full rockyou pass it is reported as *not present in
  this wordlist* — that usually means the hash is **salted**, the password is
  strong/random, or the digest is not a plain unsalted password hash. Next
  steps: supply the salt (`-s`), run a mask attack (`--mask '?l?l?l?l?d?d'`),
  or move to `hashcat` on a GPU.

### Mask Tokens
| Token | Charset |
|-------|---------|
| `?l` | abcdefghijklmnopqrstuvwxyz |
| `?u` | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| `?d` | 0123456789 |
| `?s` | special characters |
| `?a` | all of the above |
| `?h` / `?H` | hex lowercase / uppercase |
| `?X=abc` | custom charset (`--charset`) |

## 📊 Sample Output

```
[+] Wordlist: wordlists/common-pass.txt (159 words)
[*] Workers: 8 | Targets: 3 | Rules: ON | Mask: OFF
[FOUND] user=admin algo=md5 password=password
[FOUND] user=guest algo=md5 password=test
[+] Done in 0.04s | rate ≈ 306,664 H/s | cracked 2/3
```

## 📁 Input File Formats

```
5f4dcc3b5aa765d61d8327deb882cf99          # bare hash
admin:5f4dcc3b5aa765d61d8327deb882cf99    # user:hash
bob:1001:aad3...:8846f7eaee8fb117ad06bdd830b7586c:::   # pwdump
alice:$6$salt$hash...                      # shadow entry
```

## ⚖️ Legal

Only crack hashes within an authorized audit scope (e.g. your organization's
own password policy assessment).
