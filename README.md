# 🐛 Bug Bounty Toolkit

Real working tools for bug bounty hunting. Not templates — these are scripts I actually use.

## 📦 Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `recon.sh` | Full recon pipeline (subdomain → live hosts → endpoints → nuclei) | `./recon.sh example.com` |
| `quick-scan.sh` | 2-min target assessment (headers, WAF, tech, paths) | `./quick-scan.sh example.com` |
| `check-headers.sh` | Security header + cookie audit | `./check-headers.sh example.com` |
| `fuzz-params.sh` | Parameter fuzzing (SQLi, XSS, SSRF, LFI, redirect, cmdi) | `./fuzz-params.sh "https://t.com/page?id=FUZZ"` |

## 🛠️ Requirements

```bash
# Core (required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Extended (optional — scripts work without these)
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

## 📋 Methodology

- **[IDOR Hunting](methodology/idor-hunting.md)** — Easiest entry point. No special tools needed, high bounty potential.
- **[SSRF Hunting](methodology/ssrf-hunting.md)** — Cloud metadata, internal pivoting, protocol smuggling.

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/0xcucur/bugbounty-notes.git
cd bugbounty-notes

# 2. Make scripts executable
chmod +x scripts/*.sh

# 3. Quick target assessment
./scripts/quick-scan.sh target.com

# 4. Full recon (5-15 min)
./scripts/recon.sh target.com

# 5. Check security headers
./scripts/check-headers.sh target.com

# 6. Fuzz parameters
./scripts/fuzz-params.sh "https://target.com/page?id=FUZZ"
```

## 📁 Configs

- `configs/nuclei/README-presets.md` — Nuclei scan presets (critical-only, API testing, full scan)
- `configs/ffuf/` — ffuf configurations (coming soon)

## 📊 Scan Flow

```
quick-scan.sh     → Is target worth it? (2 min)
    ↓
recon.sh          → Full recon pipeline (10-30 min)
    ↓
check-headers.sh  → Easy header findings (1 min)
    ↓
fuzz-params.sh    → Parameter injection testing (5-15 min)
    ↓
Manual testing    → Burp Suite + browser for logic bugs
```

## 🎯 Platforms

- [HackerOne](https://hackerone.com) — Largest platform, VDPs + paid programs
- [Bugcrowd](https://bugcrowd.com) — Crowdsourced, good for beginners
- [Immunefi](https://immunefi.com) — Web3/DeFi bounties (highest payouts)

## ⚠️ Legal

Only test targets with explicit authorization (bug bounty programs or VDPs). These tools are for authorized security testing only.

---

*Hunting since May 2026. Scripts updated regularly as I learn new techniques.*
