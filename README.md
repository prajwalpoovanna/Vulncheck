# VulnCheck Technical Exercise

This repository contains a complete solution for the VulnCheck technical exercise, including:

- Automated vulnerability analysis and enrichment using the VulnCheck API
- Evidence-based prioritization and risk scoring
- Interactive Dash web dashboard for visualization and triage
- Executive briefing slides (see `slides/`)
- Clean, reproducible environment and setup scripts

## Features

**Step 1: Technical Analysis**
- Loads CPEs, fetches and enriches CVEs (CVSS, EPSS, KEV, exploit maturity)
- Classifies vulnerabilities into prioritization pyramid tiers
- Outputs CSV, JSON, and summary in `analysis/`

**Step 2: Web Dashboard**
- Key metrics, prioritization pyramid, interactive charts, sortable/filterable table
- Real-time filtering by priority, severity, exploit status

**Step 3: Executive Briefing**
- Executive slides for CISO/leadership (see `slides/`)

## Setup & Usage

### 1. Environment Setup

**Recommended (conda):**
```bash
conda env create -f environment.yml
conda activate vulncheck
```

**Or (pip/venv):**
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure API Key

Copy `.env.example` to `.env` and add your VulnCheck API key:
```
VULNCHECK_API_KEY=your_key_here
```

### 3. Run Analysis

```bash
python run_analysis.py
# Outputs written to analysis/
```

### 4. Run Dashboard

```bash
# If using conda (recommended)
./run_dashboard.sh
# Or with venv
python dashboard_app.py
# Dashboard at http://127.0.0.1:8050
```

### 5. Run Tests

```bash
pytest
```

## Deliverables

- `run_analysis.py` — analysis script
- `dashboard_app.py` — Dash web app
- `analysis/` — outputs: `enriched_vulnerabilities.csv`, `vulnerabilities.json`, `analysis_summary.md`
- `slides/` — executive briefing slides (PDF/HTML/MD)
- `README.md` — this file
- `environment.yml`, `requirements.txt` — environment setup
- `tests/` — test coverage for analysis logic

## Executive Briefing

Place your executive slides (PDF/HTML/MD) in `slides/` before submission. Remove any API keys from your environment.

---

For questions or improvements, open an issue or contact the author.