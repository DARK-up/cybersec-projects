#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# HashBreaker — get the rockyou.txt wordlist (14.3 M passwords, ~139 MB)
#
#   ./get-rockyou.sh
#
# Kali already ships it:  /usr/share/wordlists/rockyou.txt.gz
# Otherwise it is downloaded from the Kali Linux package mirror.
# rockyou.txt is NOT stored in git (GitHub rejects files larger than 100 MB).
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/wordlists"
DEST="rockyou.txt"

if [[ -s "$DEST" ]]; then
  echo "[+] $DEST already present: $(wc -l < "$DEST") words"
  exit 0
fi

# 1) use the Kali system copy when it exists
for SYS in /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/rockyou.txt; do
  if [[ -f "$SYS" ]]; then
    echo "[*] Found system wordlist: $SYS"
    case "$SYS" in
      *.gz) gunzip -c "$SYS" > "$DEST" ;;
      *)    cp "$SYS" "$DEST" ;;
    esac
    echo "[+] $DEST ready: $(wc -l < "$DEST") words"
    exit 0
  fi
done

# 2) otherwise download it
MIRRORS=(
  "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz"
  "https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz"
)
for URL in "${MIRRORS[@]}"; do
  echo "[*] Trying $URL"
  if curl -fL --retry 2 --max-time 600 -o /tmp/rockyou.gz "$URL"; then
    if [[ $(stat -c%s /tmp/rockyou.gz) -gt 1000000 ]]; then
      gunzip -c /tmp/rockyou.gz > "$DEST"
      rm -f /tmp/rockyou.gz
      echo "[+] $DEST ready: $(wc -l < "$DEST") words"
      exit 0
    fi
  fi
done

echo "[-] Could not fetch rockyou.txt automatically."
echo "    Kali:      sudo apt install wordlists && gunzip -k /usr/share/wordlists/rockyou.txt.gz"
echo "    Manual:    put any big wordlist at $(pwd)/$DEST"
exit 1
