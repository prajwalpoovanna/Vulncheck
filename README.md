# VulnCheck Technical Exercise

This repository contains a complete solution for the VulnCheck technical exercise, including:

- Automated vulnerability analysis and enrichment using the VulnCheck API
- Evidence-based prioritization using CVSS, EPSS, KEV, and exploit maturity
- Interactive Dash web dashboard for visualization and triage
- Executive briefing for CISO/leadership (see `slides/`)
- Clean, reproducible environment and setup scripts

## Features

**Step 1: Technical Analysis**
- Loads CPEs, fetches and enriches CVEs (CVSS, EPSS, KEV, exploit maturity)
- Classifies vulnerabilities into prioritization pyramid tiers
- Outputs CSV, JSON, and summary in `analysis/`

**Step 2: Web Dashboard**
- Key metrics, prioritization pyramid, interactive charts, sortable/filterable table
- Real-time filtering by priority, severity, exploit status
- CSV export functionality

**Step 3: Executive Briefing**
- Comprehensive executive briefing for CISO/leadership (see `slides/`)
- Evidence-based recommendations with business impact analysis
- VulnCheck intelligence value proposition

## Setup & Usage

### 1. Environment Setup

**Setup with Python venv (recommended):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure API Key

Copy `.env.example` to `.env` and add your VulnCheck API key:
```
VULNCHECK_API_KEY=your_key_here
```

Or set it directly in your environment:
```bash
export VULNCHECK_API_KEY=your_key_here
```

### 3. Run Analysis

```bash
python run_analysis.py
# Outputs written to analysis/
```

### 4. Run Dashboard

```bash
python dashboard_app.py
# Dashboard at http://127.0.0.1:8050
```

## Deliverables

- `run_analysis.py` — analysis script with VulnCheck API integration
- `dashboard_app.py` — Dash web app with interactive visualizations
- `analysis/` — outputs: `enriched_vulnerabilities.csv`, `vulnerabilities.json`, `analysis_summary.md`
- `slides/` — executive briefing (PDF and Markdown)
- `README.md` — this file
- `requirements.txt` — Python dependencies

## Executive Briefing

Executive briefing slides are available in `slides/`:
- `EXECTIVE_BRIEFING.md` — Comprehensive markdown briefing with analysis and recommendations
- `Executive_Briefing_simple.pdf` — PDF version for presentations

## Technical Implementation

### API Endpoints Used
- **VulnCheck NVD2 Index** (`/v3/index/vulncheck-nvd2`): CVSS scores and vulnerability metadata
- **VulnCheck EPSS Index** (`/v3/index/epss`): Exploit prediction scoring
- **VulnCheck Exploits** (`/v3/index/exploits`): Real-world exploit intelligence
- **VulnCheck CPE** (`/v3/cpe`): CVE discovery by CPE strings

### Risk Scoring Formula
```
risk_score = (cvss_v3_score * 0.4) + 
             (epss_score * 100 * 0.3) + 
             (cisa_kev ? 10 : 0) + 
             (has_exploit ? 5 : 0)
```

### Prioritization Pyramid Tiers
1. Ransomware/Botnets (CISA KEV + Weaponized exploits)
2. Threat Actors/APTs (CISA KEV + any exploit)
3. Unattributed KEV (CISA KEV only)
4. VulnCheck KEV (VulnCheck KEV)
5. Weaponized (Weaponized exploits)
6. Proof-of-Concept (POC exploits)
7. All Other Vulnerabilities

---

For questions or improvements, open an issue or contact the repository owner.