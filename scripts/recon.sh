#!/usr/bin/env bash
# ============================================================
# recon.sh — Automated bug bounty reconnaissance pipeline
# ============================================================
# Usage:  ./recon.sh <domain> [output_dir]
# Output: subdomains, live hosts, endpoints, nuclei scan results
#
# Requirements: subfinder, httpx, gau, waybackurls, katana, nuclei
# Install: go install github.com/projectdiscovery/{subfinder,httpx,katana,nuclei}/cmd/...@latest
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo '  ____  _____ _____ ____   ___ ____   ____   _   _ ___________'
    echo ' |  _ \| ____|_   _|  _ \ / _ \___ \ / ___| | | | |__  /__  /'
    echo ' | |_) |  _|   | | | |_) | | | |__) | |     | |_| | / /  / / '
    echo ' |  _ <| |___  | | |  _ <| |_| / __/| |___  |  _  |/ /_ / /_ '
    echo ' |_| \_\_____| |_| |_| \_\\___/_____|\_____| |_| |_/____/____|'
    echo -e "${NC}"
    echo -e "  ${GREEN}Automated Bug Bounty Recon Pipeline${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 <domain> [output_dir]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com /tmp/recon-output"
    echo "  $0 '*.example.com'              # wildcard subdomain scan"
    echo ""
    exit 1
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }
step() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

check_deps() {
    local missing=()
    for cmd in subfinder httpx nuclei; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}"
        echo "Install: go install github.com/projectdiscovery/${missing[0]}/cmd/${missing[0]}@latest"
        exit 1
    fi
    # Optional tools (warn but don't fail)
    for cmd in gau waybackurls katana ffuf; do
        command -v "$cmd" &>/dev/null || warn "Optional tool not found: $cmd (skipping related step)"
    done
}

# ---- Parse args ----
[[ $# -lt 1 ]] && usage
DOMAIN="$1"
BASE_DIR="${2:-./recon-$DOMAIN-$(date +%Y%m%d_%H%M%S)}"

# Strip wildcard for directory naming
SAFE_DOMAIN="${DOMAIN//\*/_wildcard}"

# Create output directories
OUT="$BASE_DIR/$SAFE_DOMAIN"
mkdir -p "$OUT"/{subdomains,endpoints,nuclei,ffuf,screenshots}
cd "$OUT"

banner
log "Target: $DOMAIN"
log "Output: $OUT"
echo ""

# ============================================================
# PHASE 1: Subdomain Enumeration
# ============================================================
step "PHASE 1: Subdomain Enumeration"

log "Running subfinder..."
subfinder -d "$DOMAIN" -silent -all -o subdomains/subfinder.txt 2>/dev/null
SUBFINDER_COUNT=$(wc -l < subdomains/subfinder.txt 2>/dev/null || echo 0)
log "subfinder found: $SUBFINDER_COUNT subdomains"

# Passive sources via gau/wayback (optional)
if command -v gau &>/dev/null; then
    log "Running gau for passive subdomain discovery..."
    echo "$DOMAIN" | gau --subs 2>/dev/null | unfurl -u domains 2>/dev/null | sort -u > subdomains/gau.txt || true
    GAU_COUNT=$(wc -l < subdomains/gau.txt 2>/dev/null || echo 0)
    log "gau found: $GAU_COUNT additional domains"
fi

# Merge + deduplicate
cat subdomains/*.txt 2>/dev/null | sort -u > subdomains/all.txt
TOTAL_SUBS=$(wc -l < subdomains/all.txt)
log "Total unique subdomains: $TOTAL_SUBS"

# ============================================================
# PHASE 2: HTTP Probing
# ============================================================
step "PHASE 2: HTTP Probing (httpx)"

log "Probing for live HTTP services..."
cat subdomains/all.txt | httpx -silent -status-code -title -tech-detect -follow-redirects \
    -threads 50 -timeout 10 -o probes/httpx_full.txt 2>/dev/null

# Extract just live URLs
grep -oP 'https?://[^\s]+' probes/httpx_full.txt | sort -u > probes/live_urls.txt 2>/dev/null || true
LIVE_COUNT=$(wc -l < probes/live_urls.txt 2>/dev/null || echo 0)
log "Live HTTP services: $LIVE_COUNT"

# Status code breakdown
if [[ -f probes/httpx_full.txt ]]; then
    echo ""
    echo "  Status code breakdown:"
    grep -oP '\[\d+\]' probes/httpx_full.txt | sort | uniq -c | sort -rn | head -10 | while read count code; do
        echo "    $code: $count"
    done
fi

# ============================================================
# PHASE 3: Endpoint Discovery
# ============================================================
step "PHASE 3: Endpoint Discovery"

# From gau (passive archive crawling)
if command -v gau &>/dev/null; then
    log "Running gau (passive endpoint discovery)..."
    cat probes/live_urls.txt 2>/dev/null | unfurl -u domains 2>/dev/null | sort -u | \
        while read d; do echo "$d"; done | gau --threads 5 2>/dev/null | sort -u > endpoints/gau.txt || true
    GAU_EP=$(wc -l < endpoints/gau.txt 2>/dev/null || echo 0)
    log "gau endpoints: $GAU_EP"
fi

# From waybackurls (optional)
if command -v waybackurls &>/dev/null; then
    log "Running waybackurls..."
    cat subdomains/all.txt | waybackurls 2>/dev/null | sort -u > endpoints/wayback.txt || true
    WB_EP=$(wc -l < endpoints/wayback.txt 2>/dev/null || echo 0)
    log "waybackurls endpoints: $WB_EP"
fi

# From katana (active crawling, optional)
if command -v katana &>/dev/null && [[ -f probes/live_urls.txt ]]; then
    log "Running katana (active crawling)..."
    katana -list probes/live_urls.txt -d 3 -jc -silent -o endpoints/katana.txt 2>/dev/null || true
    KATANA_EP=$(wc -l < endpoints/katana.txt 2>/dev/null || echo 0)
    log "katana endpoints: $KATANA_EP"
fi

# Merge endpoints
cat endpoints/*.txt 2>/dev/null | sort -u > endpoints/all.txt
TOTAL_EP=$(wc -l < endpoints/all.txt)
log "Total unique endpoints: $TOTAL_EP"

# Extract URLs with interesting parameters (potential injection points)
grep -E '[?&](id|user|page|file|path|url|redirect|callback|token|search|query|name|email|sort|type|action|cmd|exec|lang|debug|admin|test|dev|config|key|hash|ref|src|dest|target|host|port|input|data|val|value|content|body|msg|message|text|desc|description)=' \
    endpoints/all.txt > endpoints/params.txt 2>/dev/null || true
PARAM_COUNT=$(wc -l < endpoints/params.txt 2>/dev/null || echo 0)
log "Endpoints with interesting parameters: $PARAM_COUNT"

# ============================================================
# PHASE 4: Technology Fingerprinting
# ============================================================
step "PHASE 4: Technology Fingerprinting"

if [[ -f probes/httpx_full.txt ]]; then
    log "Extracting technologies from httpx output..."
    # Extract tech detect info
    grep -oP '\[.*?\]' probes/httpx_full.txt | tr '[]' ' ' | tr ',' '\n' | \
        sed 's/^ *//;s/ *$//' | sort | uniq -c | sort -rn | head -30 > probes/technologies.txt
    log "Top technologies found:"
    head -10 probes/technologies.txt | while read count tech; do
        echo "    $tech ($count)"
    done
fi

# ============================================================
# PHASE 5: Nuclei Scanning
# ============================================================
step "PHASE 5: Nuclei Vulnerability Scanning"

if [[ -f probes/live_urls.txt ]] && [[ -s probes/live_urls.txt ]]; then
    # Critical + High severity first
    log "Running nuclei (critical + high)..."
    nuclei -l probes/live_urls.txt -severity critical,high -silent \
        -o nuclei/critical_high.txt -stats -si 60 2>/dev/null || true
    CRIT=$(grep -c '\[critical\]\|[CRITICAL]' nuclei/critical_high.txt 2>/dev/null || echo 0)
    HIGH=$(grep -c '\[high\]\|[HIGH]' nuclei/critical_high.txt 2>/dev/null || echo 0)
    log "Critical: $CRIT | High: $HIGH findings"

    # Medium + Low + Info
    log "Running nuclei (medium, low, info)..."
    nuclei -l probes/live_urls.txt -severity medium,low,info -silent \
        -o nuclei/medium_low_info.txt -stats -si 60 2>/dev/null || true

    # Combine all findings
    cat nuclei/*.txt 2>/dev/null | sort -u > nuclei/all_findings.txt
    TOTAL_FINDINGS=$(wc -l < nuclei/all_findings.txt 2>/dev/null || echo 0)
    log "Total nuclei findings: $TOTAL_FINDINGS"
else
    warn "No live URLs found, skipping nuclei scan"
fi

# ============================================================
# SUMMARY
# ============================================================
step "RECON COMPLETE"

echo ""
echo -e "${GREEN}  Target:${NC}            $DOMAIN"
echo -e "${GREEN}  Subdomains:${NC}        $TOTAL_SUBS"
echo -e "${GREEN}  Live Services:${NC}     $LIVE_COUNT"
echo -e "${GREEN}  Endpoints:${NC}         $TOTAL_EP"
echo -e "${GREEN}  Parameterized URLs:${NC} $PARAM_COUNT"
echo -e "${GREEN}  Nuclei Findings:${NC}   ${TOTAL_FINDINGS:-0}"
echo ""
echo -e "${CYAN}  Output directory: $OUT${NC}"
echo ""
echo "  Key files:"
echo "    subdomains/all.txt        — All unique subdomains"
echo "    probes/live_urls.txt      — Live HTTP services"
echo "    probes/httpx_full.txt     — Full httpx output (status, title, tech)"
echo "    endpoints/all.txt         — All discovered endpoints"
echo "    endpoints/params.txt      — URLs with parameters (injection candidates)"
echo "    nuclei/critical_high.txt  — Critical + High severity findings"
echo "    nuclei/all_findings.txt   — All nuclei findings"
echo ""

# Generate quick summary file
cat > summary.json << EOF
{
    "target": "$DOMAIN",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "subdomains_total": $TOTAL_SUBS,
    "live_services": $LIVE_COUNT,
    "endpoints_total": $TOTAL_EP,
    "endpoints_with_params": $PARAM_COUNT,
    "nuclei_findings": ${TOTAL_FINDINGS:-0}
}
EOF
log "Summary saved to summary.json"
