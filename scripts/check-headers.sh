#!/usr/bin/env bash
# ============================================================
# check-headers.sh — Audit security headers + cookie flags
# ============================================================
# Usage:  ./check-headers.sh <domain|url>
# Output: Missing headers, insecure cookies, info leaks
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

[[ $# -lt 1 ]] && { echo "Usage: $0 <domain|url>"; exit 1; }

TARGET="$1"
[[ "$TARGET" != http* ]] && TARGET="https://$TARGET"

echo -e "${CYAN}  Security Header Audit: $TARGET${NC}"
echo "  $(date -u)"
echo ""

# Fetch headers
HEADERS=$(curl -sIL "$TARGET" --max-time 15 --connect-timeout 10 2>/dev/null)
CODE=$(echo "$HEADERS" | grep -m1 "^HTTP/" | awk '{print $2}')
echo -e "  Status: $CODE"
echo ""

# ---- Required Security Headers ----
echo -e "${CYAN}--- Security Headers ---${NC}"

check_header() {
    local name="$1"
    local severity="$2"  # critical, high, medium, low
    local value
    value=$(echo "$HEADERS" | grep -i "^$name:" | tail -1 | cut -d: -f2- | xargs 2>/dev/null)
    
    if [[ -n "$value" ]]; then
        case "$severity" in
            critical|high)
                echo -e "  ${GREEN}✓${NC} $name: ${value:0:100}"
                ;;
            *)
                echo -e "  ${GREEN}✓${NC} $name: ${value:0:100}"
                ;;
        esac
    else
        case "$severity" in
            critical) echo -e "  ${RED}✗ [CRITICAL]${NC} $name: MISSING" ;;
            high)     echo -e "  ${RED}✗ [HIGH]${NC} $name: MISSING" ;;
            medium)   echo -e "  ${YELLOW}✗ [MEDIUM]${NC} $name: MISSING" ;;
            low)      echo -e "  ${YELLOW}✗ [LOW]${NC} $name: MISSING" ;;
        esac
    fi
}

check_header "Strict-Transport-Security" "high"
check_header "Content-Security-Policy" "high"
check_header "X-Content-Type-Options" "medium"
check_header "X-Frame-Options" "medium"
check_header "X-XSS-Protection" "low"
check_header "Referrer-Policy" "medium"
check_header "Permissions-Policy" "low"
check_header "Cross-Origin-Embedder-Policy" "low"
check_header "Cross-Origin-Opener-Policy" "low"
check_header "Cross-Origin-Resource-Policy" "low"

# ---- CORS Check ----
echo ""
echo -e "${CYAN}--- CORS Configuration ---${NC}"
CORS=$(curl -sI -H "Origin: https://evil.com" "$TARGET" --max-time 10 2>/dev/null | grep -i "access-control-allow-origin")
if [[ -n "$CORS" ]]; then
    if echo "$CORS" | grep -qi "evil.com\|\*"; then
        echo -e "  ${RED}✗ [CRITICAL]${NC} CORS reflects evil.com or wildcard!"
        echo "    $CORS"
    else
        echo -e "  ${GREEN}✓${NC} CORS doesn't reflect evil.com"
    fi
else
    echo -e "  ${GREEN}✓${NC} No CORS headers (no cross-origin access)"
fi

# ---- Cookie Audit ----
echo ""
echo -e "${CYAN}--- Cookie Flags ---${NC}"
COOKIES=$(curl -sI "$TARGET" --max-time 10 2>/dev/null | grep -i "^set-cookie:")
if [[ -n "$COOKIES" ]]; then
    while IFS= read -r cookie; do
        cookie_name=$(echo "$cookie" | cut -d= -f1 | sed 's/set-cookie: //i')
        ISSUES=()
        
        echo "$cookie" | grep -qi "secure" || ISSUES+=("No Secure")
        echo "$cookie" | grep -qi "httponly" || ISSUES+=("No HttpOnly")
        echo "$cookie" | grep -qi "samesite" || ISSUES+=("No SameSite")
        
        if [[ ${#ISSUES[@]} -gt 0 ]]; then
            echo -e "  ${RED}✗${NC} $cookie_name: ${ISSUES[*]}"
        else
            echo -e "  ${GREEN}✓${NC} $cookie_name: All flags set"
        fi
    done <<< "$COOKIES"
else
    echo "  No cookies set"
fi

# ---- Info Leak Detection ----
echo ""
echo -e "${CYAN}--- Information Disclosure ---${NC}"

# Server header
SERVER=$(echo "$HEADERS" | grep -i "^server:" | tail -1 | cut -d: -f2- | xargs 2>/dev/null)
[[ -n "$SERVER" ]] && echo -e "  ${YELLOW}!${NC} Server: $SERVER" || echo -e "  ${GREEN}✓${NC} Server header hidden"

# X-Powered-By
POWERED=$(echo "$HEADERS" | grep -i "^x-powered-by:" | tail -1 | cut -d: -f2- | xargs 2>/dev/null)
[[ -n "$POWERED" ]] && echo -e "  ${RED}✗${NC} X-Powered-By: $POWERED (tech disclosure!)" || echo -e "  ${GREEN}✓${NC} X-Powered-By hidden"

# X-AspNet-Version
ASPNET=$(echo "$HEADERS" | grep -i "^x-aspnet" | head -3)
[[ -n "$ASPNET" ]] && echo -e "  ${RED}✗${NC} ASP.NET version disclosed: $ASPNET" || true

# ---- HTTP to HTTPS Redirect ----
echo ""
echo -e "${CYAN}--- HTTPS Redirect ---${NC}"
HTTP_CODE=$(curl -sI -o /dev/null -w "%{http_code}" "http://${TARGET#https://}" --max-time 10 2>/dev/null)
REDIRECT_URL=$(curl -sI "http://${TARGET#https://}" --max-time 10 2>/dev/null | grep -i "^location:" | cut -d: -f2- | xargs)
if [[ "$HTTP_CODE" =~ ^30[1278] ]]; then
    if echo "$REDIRECT_URL" | grep -qi "^https"; then
        echo -e "  ${GREEN}✓${NC} HTTP → HTTPS redirect ($HTTP_CODE → $REDIRECT_URL)"
    else
        echo -e "  ${YELLOW}!${NC} Redirects but not to HTTPS: $REDIRECT_URL"
    fi
else
    echo -e "  ${RED}✗${NC} No HTTP→HTTPS redirect (status: $HTTP_CODE)"
fi

echo ""
echo -e "${CYAN}--- Audit Complete ---${NC}"
echo "  Any CRITICAL findings = worth reporting in bug bounty"
echo "  Missing HSTS + CSP + X-Frame-Options = common VDP-eligible issues"
