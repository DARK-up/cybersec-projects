#!/usr/bin/env bash
# =============================================================
# upload_to_github.sh — push the portfolio to GitHub in one command
# =============================================================
# Usage:
#   GITHUB_TOKEN=ghp_xxx ./upload_to_github.sh <github-username> [repo-name] [public|private]
#
# Example:
#   GITHUB_TOKEN=ghp_ABC123... ./upload_to_github.sh ahmed-mohamed cybersec-projects public
#
# The token needs the "repo" scope (classic) OR Contents+Administration
# (fine-grained). You can revoke/delete the token right after the push succeeds.
# =============================================================
set -euo pipefail

USERNAME="${1:-}"
REPO="${2:-cybersec-projects}"
VISIBILITY="${3:-public}"
TOKEN="${GITHUB_TOKEN:-}"

if [[ -z "$USERNAME" || -z "$TOKEN" ]]; then
  echo "Usage: GITHUB_TOKEN=ghp_xxx ./upload_to_github.sh <username> [repo] [public|private]"
  exit 1
fi

echo "==> Creating repo $USERNAME/$REPO ($VISIBILITY) ..."
if [[ "$VISIBILITY" == "private" ]]; then PRIVATE=true; else PRIVATE=false; fi

HTTP=$(curl -s -o /tmp/gh_repo.json -w "%{http_code}" \
  -X POST "https://api.github.com/user/repos" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"name\":\"$REPO\",\"private\":$PRIVATE,\"description\":\"Red Team cybersecurity portfolio — 4 tested security tools + vulnerable demo lab\",\"has_issues\":true,\"has_wiki\":false}")

if [[ "$HTTP" == "201" ]]; then
  echo "==> Repo created OK"
elif [[ "$HTTP" == "422" ]]; then
  echo "==> Repo already exists — will push to it"
else
  echo "==> GitHub API error (HTTP $HTTP):"
  cat /tmp/gh_repo.json
  exit 1
fi

echo "==> Pushing code ..."
cd "$(dirname "$0")"
git remote remove origin 2>/dev/null || true
git remote add origin "https://x-access-token:${TOKEN}@github.com/${USERNAME}/${REPO}.git"
git push -u origin main --force

echo ""
echo "=============================================="
echo " DONE! Your projects are live at:"
echo " https://github.com/${USERNAME}/${REPO}"
echo "=============================================="
