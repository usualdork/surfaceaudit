<p align="center">
  <pre>
   ____              __                 _             _ _ _
  / ___| _   _ _ __ / _| __ _  ___ ___/ \  _   _  __| (_) |_
  \___ \| | | | '__| |_ / _` |/ __/ _ \ /\ | | | |/ _` | | __|
   ___) | |_| | |  |  _| (_| | (_|  __/ ___ \ |_| | (_| | | |_
  |____/ \__,_|_|  |_|  \__,_|\___\___/_/   \_\__,_|\__,_|_|\__|
  </pre>
</p>

<h3 align="center">Open-source external attack surface management with AI-powered analysis</h3>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
  <img src="https://img.shields.io/badge/tests-592%20passed-brightgreen.svg" alt="Tests: 592 passed">
</p>

---

SurfaceAudit discovers, classifies, and assesses your internet-facing assets, enriches them with threat intelligence from 4 sources, monitors for changes, and generates AI-powered security reports — all from a single CLI command.

```
pip install surfaceaudit
surfaceaudit scan --targets example.com --enrich --ai-key $GEMINI_API_KEY
```

**Output:** A JSON scan report + an AI-generated markdown report with executive summary, asset inventory, remediation recommendations with MITRE ATT&CK mappings, and threat intelligence summary.

## Why SurfaceAudit?

Most open-source ASM tools do one thing. SurfaceAudit does the full pipeline:

```
Discover → Classify → Assess → Enrich → Monitor → Report (AI)
```

| What you get | How it works |
|---|---|
| Asset discovery | Passive recon via Shodan — no packets sent to targets |
| Smart classification | YAML rule engine classifies assets (web server, database, IoT, etc.) |
| Vulnerability assessment | 5 matcher types: word, regex, port, version_compare, DSL |
| Threat intelligence | VirusTotal + GreyNoise + AbuseIPDB + crt.sh with correlation scoring |
| Continuous monitoring | Watch mode with diff detection and Slack/Discord/webhook alerts |
| AI-powered reports | Gemma 4 generates executive summaries and remediation guidance |
| DevSecOps integration | SARIF output for GitHub Security tab + Actions workflow included |

## Quick Start

### Install

```bash
pip install surfaceaudit
```

### Set API Keys

```bash
# Required: Shodan for asset discovery
export SHODAN_API_KEY="your-shodan-key"

# Optional: AI-powered reports (auto-enabled when set)
export GEMINI_API_KEY="your-gemini-key"
```

### Run a Scan

```bash
# Basic scan
surfaceaudit scan --targets example.com

# Scan with enrichment (VirusTotal, GreyNoise, AbuseIPDB, crt.sh)
surfaceaudit scan --targets example.com --enrich

# Scan with everything — enrichment + AI report
surfaceaudit scan --config config.yaml --enrich
```

Every scan produces:
- **JSON report** — structured scan data for automation
- **Markdown report** — AI-generated analysis (when Gemini API key is set)

### Example AI Report Output

```markdown
# SurfaceAudit Scan Report

## Executive Summary
A recent external scan identified 23 web servers on the angel-one.vip domain.
All assets are classified as high risk due to outdated Nginx versions below 1.20.
Threat intelligence from VirusTotal, GreyNoise, and AbuseIPDB shows clean IP
reputation across all sources...

## Remediation Recommendations
1. **Outdated Nginx Version**
   - Risk: Known CVEs allowing RCE, DoS, or information disclosure
   - Fix: `apt update && apt upgrade nginx`, set `server_tokens off;`
   - MITRE ATT&CK: T1210 (Exploitation of Remote Services)
```

## Configuration

Create a YAML config file for repeatable scans:

```yaml
api_key: "${SHODAN_API_KEY}"
targets:
  - "hostname:example.com"
  - "hostname:api.example.com"
output_format: json
output_file: scan_results.json

enrichment:
  enabled: true
  providers:
    virustotal:
      enabled: true
      api_key: "${VT_API_KEY}"
    greynoise:
      enabled: true
      api_key: "${GREYNOISE_API_KEY}"
    abuseipdb:
      enabled: true
      api_key: "${ABUSEIPDB_API_KEY}"
    crtsh:
      enabled: true
  cache_dir: ".surfaceaudit/cache"
  cache_ttl_hours: 24

ai:
  enabled: true
  api_key: "${GEMINI_API_KEY}"
  model: "gemma-4-31b-it"

watch:
  history_dir: ".surfaceaudit/history"
  notifications:
    - type: slack
      webhook_url: "${SLACK_WEBHOOK_URL}"
      on: [new_assets, risk_increase]
    - type: discord
      webhook_url: "${DISCORD_WEBHOOK_URL}"
      on: []  # all events
```

```bash
surfaceaudit scan --config config.yaml --enrich
```

## CLI Reference

```bash
# Scan with custom rules and filters
surfaceaudit scan --targets example.com \
  --exclude-rules rule-1,rule-2 \
  --tags web,database \
  --min-severity high

# Scan with SARIF output for GitHub Security
surfaceaudit scan --targets example.com \
  --output-format sarif \
  --output-file results.sarif

# Watch mode — scan, diff, and notify
surfaceaudit watch --config config.yaml

# Compare two scan reports
surfaceaudit compare scan_a.json scan_b.json

# Save a reusable config
surfaceaudit save-config --output config.yaml \
  --targets example.com --provider shodan

# Disable AI for a single scan
surfaceaudit scan --targets example.com --no-ai
```

## YAML Rule Engine

Write custom detection rules using a Nuclei-inspired YAML format with 5 matcher types:

```yaml
id: detect-outdated-apache
info:
  name: Outdated Apache HTTP Server
  author: your-team
  severity: high
  tags: [web, vulnerable_version]
  description: Apache below 2.4.50 has known CVEs
match:
  condition: and
  matchers:
    - type: word
      field: banner
      words: [apache]
    - type: version_compare
      field: service_version
      operator: lt
      version: "2.4.50"
assess:
  category: vulnerable_version
  severity: high
  description: "Apache {service_version} is below 2.4.50"
```

**Matcher types:** `word` (substring), `regex` (pattern), `port` (number), `version_compare` (semantic), `dsl` (boolean expressions)

Load custom rules:
```bash
surfaceaudit scan --targets example.com --rules-dir ./my-rules
```

## GitHub Actions

Add to `.github/workflows/surfaceaudit.yml`:

```yaml
name: SurfaceAudit Scan
on:
  schedule:
    - cron: "0 6 * * 1"  # Weekly Monday 6am UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install SurfaceAudit
        run: pip install surfaceaudit

      - name: Run scan
        env:
          SHODAN_API_KEY: ${{ secrets.SHODAN_API_KEY }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          surfaceaudit scan \
            --api-key "$SHODAN_API_KEY" \
            --targets "example.com" \
            --output-format sarif \
            --output-file results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Docker

```bash
docker build -t surfaceaudit .
docker run --rm \
  -e SHODAN_API_KEY="your-key" \
  -e GEMINI_API_KEY="your-gemini-key" \
  surfaceaudit scan --targets example.com --enrich
```

## Architecture

```
surfaceaudit scan --targets example.com --enrich
        │
        ▼
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Discover   │────▶│   Classify   │────▶│    Assess    │
│  (Shodan)    │     │ (Rule Engine)│     │ (Rule Engine)│
└─────────────┘     └──────────────┘     └──────────────┘
                                                │
                    ┌───────────────────────────┘
                    ▼
        ┌──────────────────┐     ┌─────────────────┐
        │     Enrich       │────▶│   AI Analysis   │
        │ VT+GN+AIPDB+CRT │     │   (Gemma 4)     │
        └──────────────────┘     └─────────────────┘
                    │                     │
                    ▼                     ▼
            ┌──────────┐         ┌──────────────┐
            │ JSON/SARIF│         │ Markdown     │
            │ Report    │         │ Report       │
            └──────────┘         └──────────────┘
```

## Comparison

| Feature | SurfaceAudit | Nuclei | SpiderFoot | Shodan CLI | Censys ASM |
|---|:---:|:---:|:---:|:---:|:---:|
| Open source | ✅ | ✅ | ✅ | ❌ | ❌ |
| Passive (no probing) | ✅ | ❌ | ✅ | ✅ | ✅ |
| YAML rule engine | ✅ | ✅ | ❌ | ❌ | ❌ |
| Threat intel enrichment | ✅ | ❌ | ✅ | ❌ | ❌ |
| Correlation risk score | ✅ | ❌ | ❌ | ❌ | ✅ |
| AI-powered reports | ✅ | ❌ | ❌ | ❌ | ❌ |
| Watch mode + alerts | ✅ | ❌ | ❌ | ❌ | ✅ |
| SARIF / GitHub Security | ✅ | ❌ | ❌ | ❌ | ❌ |
| pip install | ✅ | ❌ | ✅ | ✅ | ❌ |
| Price | Free | Free | Free | $49-899/mo | Enterprise |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and how to add rules or providers.

```bash
git clone https://github.com/your-org/surfaceaudit.git
cd surfaceaudit
pip install -e ".[dev]"
pytest tests/  # 592 tests, 40 property-based
```

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
