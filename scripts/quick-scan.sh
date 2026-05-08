#!/usr/bin/env bash
# ============================================================
# quick-scan.sh — Fast target assessment for bug bounty triage
# ============================================================
# Usage:  ./quick-scan.sh <domain>
# Purpose: Quick 2-min scan to decide if a target is worth deeper recon
# ============================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

[[ $# -lt 1 ]] && { echo "Usage: $0 <domain>"; exit 1; }
DOMAIN="$1"

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${CYAN}  Quick Scan: $DOMAIN${NC}"
echo "  $(date -u)"
echo ""

# ---- DNS + Basic Info ----
echo -e "${CYAN}--- DNS Records ---${NC}"
for rtype in A AAAA CNAME MX NS TXT; do
    result=$(dig +short "$DOMAIN" "$rtype" 2>/dev/null | head -5)
    [[ -n "$result" ]] && echo "  $rtype: $result"
done

# Check for WAF
echo ""
echo -e "${CYAN}--- WAF Detection ---${NC}"
HEADERS=$(curl -sI "https://$DOMAIN" --max-time 10 2>/dev/null)
WAF_SIGS=("cloudflare" "akamai" "incapsula" "sucuri" "wordfence" "aws" "fastly" "varnish" "mod_security" "waf")
for sig in "${WAF_SIGS[@]}"; do
    if echo "$HEADERS" | grep -qi "$sig"; then
        warn "WAF detected: $sig"
    fi
done
[[ -z "$HEADERS" ]] && warn "No HTTP response received" || log "HTTP response received"

# Interesting headers
echo ""
echo -e "${CYAN}--- Security Headers ---${NC}"
for hdr in "X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy" "Strict-Transport-Security" "X-XSS-Protection" "Access-Control-Allow-Origin" "Set-Cookie"; do
    val=$(echo "$HEADERS" | grep -i "^$hdr:" | head -1 | cut -d: -f2- | xargs)
    if [[ -n "$val" ]]; then
        case "$hdr" in
            "X-Frame-Options"|"X-Content-Type-Options"|"Content-Security-Policy"|"Strict-Transport-Security"|"X-XSS-Protection")
                echo -e "  ${GREEN}✓${NC} $hdr: ${val:0:80}"
                ;;
            "Access-Control-Allow-Origin")
                [[ "$val" == "*" ]] && echo -e "  ${RED}✗${NC} $hdr: $val (CORS wildcard!)" || echo -e "  ${GREEN}✓${NC} $hdr: ${val:0:80}"
                ;;
            "Set-Cookie")
                if ! echo "$val" | grep -qi "secure\|httponly\|samesite"; then
                    echo -e "  ${RED}✗${NC} $hdr: Missing Secure/HttpOnly/SameSite flags"
                else
                    echo -e "  ${GREEN}✓${NC} $hdr: Has security flags"
                fi
                ;;
        esac
    else
        [[ "$hdr" != "Set-Cookie" ]] && echo -e "  ${RED}✗${NC} $hdr: MISSING"
    fi
done

# ---- Subdomain Quick Count ----
echo ""
echo -e "${CYAN}--- Subdomain Count (subfinder) ---${NC}"
if command -v subfinder &>/dev/null; then
    SUBS=$(subfinder -d "$DOMAIN" -silent 2>/dev/null | wc -l)
    log "Found $SUBS subdomains"
else
    warn "subfinder not installed"
fi

# ---- Technology Detection ----
echo ""
echo -e "${CYAN}--- Technology Stack ---${NC}"
if command -v httpx &>/dev/null && command -v subfinder &>/dev/null; then
    echo "$DOMAIN" | httpx -silent -tech-detect -title -status-code 2>/dev/null | head -5
else
    warn "httpx/subfinder not installed"
fi

# ---- Common Paths Probe ----
echo ""
echo -e "${CYAN}--- Interesting Paths ---${NC}"
for path in "/robots.txt" "/sitemap.xml" "/.well-known/security.txt" "/.git/HEAD" "/.env" "/api" "/swagger" "/graphql" "/debug" "/admin" "/login" "/register" "/wp-admin" "/wp-login.php" "/.htaccess" "/server-status" "/server-info" "/phpinfo.php" "/actuator" "/actuator/health"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN$path" --max-time 5 2>/dev/null)
    case "$CODE" in
        200) echo -e "  ${GREEN}200${NC} $path" ;;
        301|302) echo -e "  ${YELLOW}$CODE${NC} $path" ;;
        403) echo -e "  ${RED}403${NC} $path (forbidden — may exist!)" ;;
        401) echo -e "  ${RED}401${NC} $path (auth required)" ;;
    esac
done

echo ""
echo -e "${CYAN}--- Assessment Complete ---${NC}"
echo "  If you see 200s on /.git, /.env, /debug, /admin — high priority."
echo "  Missing security headers = potential clickjacking/injection."
echo "  CORS wildcard = potential data theft."
echo ""
