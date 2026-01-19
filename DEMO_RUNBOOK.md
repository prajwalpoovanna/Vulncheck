# VulnCheck Exercise Demo Runbook

This runbook provides step-by-step instructions for demonstrating each component of the VulnCheck technical exercise.

---

## Pre-Demo Setup (5 minutes before)

### 1. Verify Environment
```bash
cd ~/Desktop/vulncheck-exercise\ 2
source .venv/bin/activate
```

### 2. Verify API Key
```bash
# Check that .env file exists and has API key
cat .env | grep VULNCHECK_API_KEY
# Should show: VULNCHECK_API_KEY=your_key_here
```

### 3. Test Quick Run (Optional)
```bash
# Quick test to ensure everything works
python run_analysis.py
# Should complete in ~10-15 seconds
```

---

## Demo Flow (15-20 minutes total)

## **Part 1: Technical Analysis (5 minutes)**

### Introduction
> "I've built an automated vulnerability analysis system using the VulnCheck API that enriches CVE data with threat intelligence to prioritize remediation efforts."

### Demo Steps

**1. Show the Input CPEs**
```bash
# Open run_analysis.py and scroll to SAMPLE_CPES (line ~44)
cat run_analysis.py | grep -A 5 "SAMPLE_CPES ="
```

**Talking Points:**
- "We're analyzing 4 different systems: PAN-OS firewall, Windows Server, WebIG, and Traffic Management"
- "These represent a typical enterprise environment"

**2. Run the Analysis**
```bash
python run_analysis.py
```

**Talking Points (while it runs ~10 seconds):**
- "The script queries 3 VulnCheck API endpoints:"
  - **vulncheck-nvd2**: CVSS scores and vulnerability metadata
  - **epss**: Exploit prediction scoring (probability of exploitation)
  - **exploits**: Real-world exploit availability and maturity
- "For each CPE, we fetch CVEs and enrich them with threat intelligence"

**3. Review the Output**
```bash
# Show the analysis summary
cat analysis/analysis_summary.md
```

**Key Highlights:**
- ✅ "10 CVEs found across our 4 systems"
- ✅ "2 HIGH severity (CVSS ≥ 7.0) requiring immediate attention"
- ✅ "1 CVE with confirmed active exploits (CVE-2025-0133)"
- ✅ "Top risk: CVE-2025-0133 with risk score of 6.79 despite no CVSS yet"

**4. Show the Enriched Data**
```bash
# Open CSV to show the enriched data
head -5 analysis/enriched_vulnerabilities.csv | column -t -s,
```

**Talking Points:**
- "Each CVE is enriched with CVSS, EPSS, KEV status, exploit intelligence"
- "Risk score calculated using: CVSS (40%) + EPSS (30%) + KEV bonus + Exploit bonus"
- "Notice CVE-2025-0133: 0.0 CVSS but 6% EPSS and confirmed exploit = highest priority"

---

## **Part 2: Interactive Dashboard (7 minutes)**

### Introduction
> "I built an interactive Dash web application that visualizes the vulnerability data and enables security teams to triage and prioritize remediation."

### Demo Steps

**1. Launch the Dashboard**
```bash
python dashboard_app.py
```

**Wait for output:**
```
📊 Loaded 10 vulnerabilities
🔴 Critical: 0
🟠 High: 2
💥 With Exploits: 1
🎯 CISA KEV: 0

🌐 Dashboard running at: http://localhost:8050
```

**2. Open Browser**
```bash
# Open in default browser
open http://localhost:8050
```

### Dashboard Walkthrough

**A. Key Metrics Cards (Top Section)**

**Talking Points:**
- "At a glance: 10 total CVEs, 2 HIGH severity, 1 with active exploits"
- "Average risk score of 1.69 (moderate overall risk)"
- "Zero CISA KEV entries means no government-confirmed active threats yet"

**B. Prioritization Pyramid**

**Talking Points:**
- "This is the heart of evidence-based prioritization"
- "7 tiers from most critical (Ransomware) to least (All Other)"
- "1 CVE in Proof-of-Concept tier (has exploit code available)"
- "9 CVEs in 'All Other' tier (monitor but lower priority)"
- **Key Point**: "We prioritize based on exploit availability, not just CVSS"

**C. CVSS Distribution Chart**

**Talking Points:**
- "Most vulnerabilities are LOW severity or unscored (too new)"
- "2 HIGH severity CVEs clustered around 7.0-7.5"
- "No CRITICAL (9.0+) vulnerabilities in our environment"

**D. Exploit Availability Pie Chart**

**Talking Points:**
- "10% have exploits available (1 out of 10)"
- "This is the exploit we need to patch immediately"

**E. CVSS vs EPSS Scatter Plot**

**Talking Points:**
- "This shows the correlation between severity (CVSS) and exploitability (EPSS)"
- "Notice the outlier: low CVSS but high EPSS = CVE-2025-0133"
- "This is why CVSS-only prioritization fails"
- "Sized by risk score shows our algorithm properly weights exploit data"

**F. Top 10 Vulnerable Systems**

**Talking Points:**
- "PAN-OS has 5 CVEs (50% of our vulnerability surface)"
- "Windows Server 2025 also has 5 CVEs"
- "Prioritize patching PAN-OS first due to perimeter exposure"

**G. Interactive Data Table**

**Demonstrate Filtering:**

1. **Filter by Priority Tier**
   - Select "Proof-of-Concept" from dropdown
   - "This immediately shows our CVE with active exploits"

2. **Filter by CVSS Severity**
   - Select "High (7.0-8.9)"
   - "2 vulnerabilities need immediate patching"

3. **Filter by Exploit Status**
   - Select "Has Exploits"
   - "This is our #1 priority: CVE-2025-0133"

4. **Sort by Risk Score**
   - Click column header
   - "Highest risk floats to top regardless of CVSS"

5. **Download CSV**
   - Click "Download CSV" button
   - "Teams can export filtered data for ticketing systems"

**Key Takeaway:**
> "Security teams can quickly filter, sort, and export actionable data instead of manually reviewing spreadsheets."

---

## **Part 3: Executive Briefing (5 minutes)**

### Introduction
> "I prepared an executive briefing that translates technical vulnerability data into business risk and actionable recommendations for leadership."

### Demo Steps

**1. Open the Briefing**
```bash
# Open in VS Code or text editor
code slides/EXECTIVE_BRIEFING.md

# Or display in terminal with formatting
cat slides/EXECTIVE_BRIEFING.md
```

### Briefing Walkthrough

**A. Executive Summary (30 seconds)**

**Talking Points:**
- "One-page summary for CISO: 10 CVEs, 1 with exploits, 2 HIGH severity"
- "Key recommendation: Patch CVE-2025-0133 within 7 days"
- "Highest risk in PAN-OS perimeter firewall (50% of vulnerabilities)"

**B. Scope & Methodology (1 minute)**

**Talking Points:**
- "Analyzed 4 systems representing typical enterprise infrastructure"
- "Used 4 VulnCheck data sources: NVD2, EPSS, Exploits, KEV"
- "This is point-in-time analysis (Jan 19, 2026) - continuous monitoring needed"

**C. Key Findings Table (1 minute)**

**Highlight the Top 3 CVEs:**

| CVE | System | CVSS | EPSS | Exploit | Risk |
|-----|--------|------|------|---------|------|
| CVE-2025-0133 | PAN-OS | TBD* | 6% | YES | 6.79 |
| CVE-2025-0130 | PAN-OS | 7.5 | 0.04% | NO | 3.01 |
| CVE-2025-4615 | PAN-OS | 7.2 | 0.07% | NO | 2.90 |

**Talking Points:**
- "CVE-2025-0133: XSS in GlobalProtect - no CVSS yet but exploit confirmed"
- "CVE-2025-0130: DoS vulnerability - HIGH severity, low exploit probability"
- "All top 3 are in PAN-OS = perimeter security risk"

**D. Business Impact (1 minute)**

**Talking Points:**
- **PAN-OS Risk**: "First line of defense compromised = gateway to network"
- **CVE-2025-0133**: "JavaScript execution could steal admin credentials"
- **CVE-2025-0130**: "Packet flood = firewall DoS = business disruption"
- **Windows Risk**: "Internal privilege escalation for lateral movement"

**E. Recommended Actions (1.5 minutes)**

**Immediate (7 days):**
1. Patch CVE-2025-0133 (XSS exploit)
2. Deploy WAF rules to block XSS attempts
3. Enable enhanced logging on GlobalProtect

**Short-term (30 days):**
4. Patch 2 HIGH severity CVEs
5. MFA for all admin access
6. Restrict management interface to jump boxes

**Long-term:**
7. Integrate VulnCheck API into vulnerability management
8. Automate EPSS-based prioritization
9. Network segmentation for zero-trust

**F. VulnCheck Value Proposition (30 seconds)**

**Key Differentiator Table:**

| Traditional | VulnCheck |
|------------|-----------|
| CVSS-only | CVSS + EPSS + KEV + Exploits |
| 2 HIGH severity | 1 exploit = top priority |
| Reactive | Proactive threat intelligence |

**Talking Points:**
- "Traditional approach would miss CVE-2025-0133 (no CVSS yet)"
- "VulnCheck detected exploit before widespread use"
- "EPSS helps focus on statistically likely threats"

---

## Demo Q&A Preparation

### Common Questions & Answers

**Q: How often should we run this analysis?**
> "Daily for critical assets, weekly for standard infrastructure. VulnCheck API can be integrated into CI/CD or vulnerability scanners for continuous monitoring."

**Q: What if we have hundreds of CVEs?**
> "The dashboard scales well. You can filter by system, tier, or severity. Export filtered data to JIRA/ServiceNow for ticket creation. The prioritization pyramid ensures you focus on the top 10-20 highest risk CVEs first."

**Q: Why is CVE-2025-0133 top priority with 0.0 CVSS?**
> "This is the power of threat intelligence. CVSS is backward-looking (how bad is the vulnerability). EPSS + exploit data is forward-looking (will this be exploited). Active exploit + 6% EPSS = imminent threat despite no CVSS."

**Q: How accurate is EPSS?**
> "EPSS is maintained by FIRST.org using ML models trained on 10+ years of exploitation data. 6% probability puts CVE-2025-0133 in the 90th percentile - only 10% of CVEs are more likely to be exploited."

**Q: Can this integrate with our existing tools?**
> "Yes. The CSV export works with Excel/JIRA. The JSON output integrates with SIEMs, Splunk, or ElasticSearch. VulnCheck has official integrations with Tenable, Qualys, and Rapid7."

**Q: What about false positives?**
> "The analysis includes compensating controls section. CVE-2025-0130 is HIGH severity but LOW EPSS (0.04%) = patch in normal cycle. CVE-2025-0133 has exploit + 6% EPSS = emergency patch."

---

## Post-Demo Cleanup

**1. Stop Dashboard**
```bash
# Press Ctrl+C in the terminal running dashboard_app.py
```

**2. Deactivate Environment (Optional)**
```bash
deactivate
```

**3. Archive Results (Optional)**
```bash
# Create submission package
zip -r vulncheck-submission.zip \
  run_analysis.py \
  dashboard_app.py \
  analysis/ \
  slides/ \
  README.md \
  requirements.txt \
  -x "*.pyc" "__pycache__/*" ".DS_Store"
```

---

## Demo Time Breakdown

| Section | Duration | Key Focus |
|---------|----------|-----------|
| Intro & Setup | 2 min | Environment, API key |
| Part 1: Analysis | 5 min | API calls, enrichment, risk scoring |
| Part 2: Dashboard | 7 min | Visualizations, filtering, prioritization |
| Part 3: Briefing | 5 min | Business impact, recommendations |
| Q&A | 3-5 min | Technical questions |
| **Total** | **20-25 min** | |

---

## Tips for a Smooth Demo

✅ **Practice the demo flow 2-3 times** before presenting  
✅ **Have the dashboard pre-loaded** if you have slow internet  
✅ **Keep terminal windows organized** (analysis in one, dashboard in another)  
✅ **Zoom browser to 125-150%** for visibility in screen shares  
✅ **Have the PDF briefing open** as backup if Markdown rendering fails  
✅ **Close unnecessary applications** to avoid notifications  
✅ **Test audio/video** 5 minutes before the demo  

---

## Fallback Plan

**If API fails during demo:**
1. Use existing `analysis/` outputs (already generated)
2. Say: "I'll show you the results from the previous run"
3. Proceed with dashboard and briefing as normal

**If dashboard won't start:**
1. Show `enriched_vulnerabilities.csv` in Excel/VS Code
2. Walk through data fields manually
3. Focus more time on executive briefing

**If screen sharing has issues:**
1. Open slides PDF and share that
2. Walk through code in VS Code with syntax highlighting
3. Show terminal output with `cat` commands

---

Good luck with your demo! 🚀
