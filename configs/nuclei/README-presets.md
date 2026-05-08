# ============================================================
# nuclei-severity.yaml — Custom nuclei scan presets
# ============================================================
# Usage:
#   nuclei -l targets.txt -t configs/nuclei/critical-only.yaml
#   nuclei -l targets.txt -t configs/nuclei/api-testing.yaml
#   nuclei -l targets.txt -t configs/nuclei/full-scan.yaml
# ============================================================

# ---- Preset 1: Critical-Only (fast, high signal) ----
# File: critical-only.yaml
# Use: First pass on a new target — only show critical stuff
severity:
  - critical
  - high
tags:
  - rce
  - sqli
  - ssrf
  - takeover
  - auth-bypass
  - exposed-panels
  - default-login
  - cve

# ---- Preset 2: API Testing ----
# File: api-testing.yaml
# Use: When target has REST/GraphQL APIs
tags:
  - api
  - graphql
  - jwt
  - cors
  - ssrf
  - idor
  - rate-limit
  - misconfiguration
severity:
  - critical
  - high
  - medium

# ---- Preset 3: Full Scan (comprehensive, slow) ----
# File: full-scan.yaml
# Use: Deep scan on high-value targets
severity:
  - critical
  - high
  - medium
  - low
  - info
tags:
  - cve
  - misconfiguration
  - default-login
  - exposure
  - tech
  - network
  - dns
  - ssl
  - headers
  - takeover
  - rce
  - sqli
  - xss
  - ssrf
  - lfi
  - redirect
