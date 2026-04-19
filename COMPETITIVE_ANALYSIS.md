# SurfaceAudit — Competitive Analysis

## The Landscape

The external attack surface management (EASM) space splits into three tiers: commercial platforms ($10k-100k+/year), developer-focused SaaS tools ($50-900/month), and open-source projects (free). SurfaceAudit competes in the open-source tier but delivers capabilities that overlap with the commercial tier.

## Direct Competitors (Open Source)

### Nuclei — 18k stars
**What it does:** Template-based vulnerability scanner. Sends HTTP/DNS/TCP requests to targets and checks responses against 9,000+ community YAML templates.

**How close to us:** Nuclei is the closest competitor in terms of YAML rule engine design — our v2 engine was directly inspired by their matcher system. But the overlap ends there. Nuclei is an *active scanner* (it sends packets to targets, which can trigger IDS alerts and is potentially illegal without authorization). SurfaceAudit is *passive* — it queries Shodan's existing scan data. Nuclei has no asset classification, no enrichment, no watch mode, no AI analysis, and no SARIF output.

**Threat level: Low.** Different category. Nuclei scans for vulns, we manage attack surfaces. They're complementary, not competing.

### OWASP Amass — 10.1k stars
**What it does:** Subdomain enumeration and asset discovery using DNS, web scraping, and API integrations. Written in Go.

**How close to us:** Amass does one thing well — finding subdomains. It has no vulnerability assessment, no rule engine, no enrichment pipeline, no risk scoring, no watch mode, no notifications, and no AI. It's a discovery tool, not an ASM platform.

**Threat level: Low.** Amass could be a *data source* for SurfaceAudit (like Shodan is), not a competitor.

### SpiderFoot — 13k stars
**What it does:** OSINT automation framework with 200+ modules. Queries dozens of data sources (Shodan, VirusTotal, etc.) and maps relationships between entities. Has a web UI.

**How close to us:** SpiderFoot is the closest competitor overall. It queries similar data sources (Shodan, VirusTotal, GreyNoise, AbuseIPDB) and correlates findings. However, SpiderFoot is a general-purpose OSINT tool — it gathers data but doesn't assess it. No YAML rule engine, no semantic version comparison, no correlation risk scoring formula, no SARIF output, no GitHub Actions integration, no AI-powered reports. SpiderFoot's web UI is a plus, but it's also heavier to deploy.

**Threat level: Medium.** Overlapping data sources, but different approach. SpiderFoot gathers intelligence; SurfaceAudit assesses and monitors attack surfaces.

### reconFTW — 5.5k stars
**What it does:** Bash script that orchestrates 30+ tools (Amass, Nuclei, httpx, etc.) into an automated recon pipeline. Runs subdomain enumeration, port scanning, vulnerability scanning, and more.

**How close to us:** reconFTW is a pipeline orchestrator, not a standalone tool. It glues together other tools with bash scripts. No custom rule engine, no enrichment correlation, no watch mode, no SARIF, no AI. It's also complex to install (requires 30+ tools) vs our `pip install surfaceaudit`.

**Threat level: Low.** Different approach entirely. reconFTW is for bug bounty hunters who want to run everything at once.

### Faraday — 5.1k stars
**What it does:** Vulnerability management platform with a web UI. Aggregates results from multiple scanners (Nmap, Nessus, Burp, etc.) into a unified dashboard.

**How close to us:** Faraday is a vulnerability *management* platform, not a scanner or ASM tool. It doesn't discover assets or assess them — it aggregates results from other tools. No overlap with our core pipeline.

**Threat level: None.** Different category. Faraday could consume SurfaceAudit's output.

## Indirect Competitors (Commercial)

### Shodan ($49 one-time / $59-899/month API)
**What it does:** Search engine for internet-connected devices. Indexes banners, ports, and services across the entire IPv4 space.

**Relationship:** Shodan is our *data source*, not our competitor. We use their API for discovery. Shodan provides raw data; we provide the assessment, enrichment, monitoring, and AI analysis layer on top. A Shodan membership gives you search results. SurfaceAudit gives you a security assessment with remediation recommendations.

### Censys ASM (Custom enterprise pricing, starting ~$100/month for individuals)
**What it does:** Certificate-focused asset discovery and attack surface management. Scans all 65,535 ports. Cloud-based platform with web UI.

**How close to us:** Censys ASM is the commercial product most similar to what we do. They discover assets, classify them, and monitor for changes. But they're closed-source, cloud-only, and expensive. We're open-source, self-hosted, and free. They don't have a YAML rule engine, AI-powered reports, or SARIF output.

### Palo Alto Xpanse / Mandiant ASM / CrowdStrike Falcon Surface
**What they do:** Enterprise EASM platforms with massive scanning infrastructure, threat intelligence, and SOC integration.

**How close to us:** These are the gold standard for enterprise ASM. They have features we don't (proprietary scanning infrastructure, massive threat intel databases, SOC workflow integration). But they cost $50k-200k+/year and are closed-source. SurfaceAudit delivers 80% of the value at 0% of the cost for teams that can self-host.

## Feature Matrix

| Feature | SurfaceAudit | Nuclei | Amass | SpiderFoot | reconFTW | Shodan | Censys ASM |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Open source | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| pip install | ✅ | ❌ (Go) | ❌ (Go) | ✅ | ❌ (Bash) | ✅ | ❌ |
| Asset discovery | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Asset classification | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| YAML rule engine | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Version comparison | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DSL expressions | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Threat intel enrichment | ✅ (4 sources) | ❌ | ❌ | ✅ (200+ modules) | ❌ | ❌ | ❌ |
| Correlation risk score | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Watch mode / monitoring | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (Monitor) | ✅ |
| Slack/Discord notifications | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| SARIF output | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GitHub Actions | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AI-powered reports | ✅ (Gemma 4) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Passive (no direct probing) | ✅ | ❌ | Partial | ✅ | ❌ | ✅ | ✅ |
| Self-hosted / Docker | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Report encryption | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Price | Free | Free | Free | Free | Free | $49-899/mo | Custom |

## What Makes SurfaceAudit Unique

No other open-source tool combines all of these in a single `pip install`:

1. Passive discovery via Shodan (no packets sent to targets)
2. Nuclei-style YAML rule engine with 5 matcher types
3. Cross-source threat intelligence from 4 free APIs
4. Composite correlation risk scoring (0-100)
5. Watch mode with diff detection and webhook notifications
6. AI-powered executive summaries and remediation via Gemma 4
7. SARIF output for GitHub Security tab integration
8. 592 tests including 40 property-based tests

The closest competitor (SpiderFoot) has more data sources but no rule engine, no risk scoring formula, no AI reports, and no SARIF. The closest commercial product (Censys ASM) has similar capabilities but costs money and is closed-source.

## Target Audience

1. Security engineers at startups/SMBs who can't afford Censys/Xpanse
2. DevSecOps teams who want ASM findings in their GitHub Security tab
3. Bug bounty hunters who need quick enriched recon
4. Security consultants who need professional AI-generated reports for clients
5. Python developers who want an extensible ASM framework
