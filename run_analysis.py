#!/usr/bin/env python3
"""
Step 1: Technical Analysis
Load CPEs, fetch CVEs from VulnCheck, and enrich with exploit intelligence.
"""
import argparse
import json
import os
import logging
import pandas as pd
import requests
from pathlib import Path
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables (expects VULNCHECK_API_KEY)
load_dotenv()
API_KEY = os.getenv('VULNCHECK_API_KEY')
if not API_KEY:
    raise SystemExit("Missing VULNCHECK_API_KEY in environment. Create a .env file or set the variable before running.")

BASE_URL = "https://api.vulncheck.com/v3"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def make_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries, backoff_factor=backoff_factor,
                  status_forcelist=status_forcelist, allowed_methods=frozenset(['GET', 'POST']))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.headers.update(HEADERS)
    return session

SESSION = make_session()

# Sample CPEs from the exercise
SAMPLE_CPES = [
    "cpe:2.3:o:paloaltonetworks:pan-os:11.2.4:h2:*:*:*:*:*:*",
    "cpe:2.3:a:smart-hm:webig:215.9:*:*:*:*:*:*:*",
    "cpe:2.3:a:vantiv:virtual_traffic_management:22.7r1:*:*:*:*:*:*:*",
    "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100.4946:*:*:*:*:*:*:*"
]

def fetch_cves_for_cpe(cpe):
    """Fetch CVEs for a given CPE using VulnCheck API with retries."""
    url = f"{BASE_URL}/cpe"
    params = {"cpe": cpe, "isVulnerable": True}
    try:
        logger.info(f"Querying CVEs for CPE: %s", cpe)
        resp = SESSION.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get('data', [])
    except Exception as e:
        logger.warning("Error fetching CVEs for %s: %s", cpe, e)
        return []

def enrich_cve_details(cve_id):
    """Enrich CVE with exploit intelligence from VulnCheck."""
    try:
        vuln_url = f"{BASE_URL}/index/vulncheck-nvd2"
        exploit_url = f"{BASE_URL}/index/exploits"

        logger.info("Enriching CVE %s", cve_id)
        vuln_resp = SESSION.get(vuln_url, params={'cve': cve_id}, timeout=15)
        vuln_resp.raise_for_status()
        vuln_data = vuln_resp.json().get('data', [{}])[0] if vuln_resp.json().get('data') else {}

        exploit_resp = SESSION.get(exploit_url, params={'cve': cve_id}, timeout=15)
        exploit_resp.raise_for_status()
        exploit_data = exploit_resp.json().get('data', [])

        cvss_v3 = vuln_data.get('cvssV3', {})
        cvss_v2 = vuln_data.get('cvssV2', {})
        cvss_v3_score = cvss_v3.get('baseScore')
        cvss_v3_severity = cvss_v3.get('baseSeverity')
        if cvss_v3_score is None:
            cvss_v3_score = cvss_v2.get('baseScore')
        if cvss_v3_severity is None:
            cvss_v3_severity = cvss_v2.get('baseSeverity')
        if cvss_v3_score is None:
            cvss_v3_score = vuln_data.get('cvssScore', 0.0)
        if cvss_v3_severity is None:
            cvss_v3_severity = 'UNKNOWN'
        epss = vuln_data.get('epss', {})
        epss_score = epss.get('score', 0.0)
        epss_percentile = epss.get('percentile', 0.0)
        return {
            'cve_id': cve_id,
            'cvss_v3_score': cvss_v3_score if cvss_v3_score is not None else 0.0,
            'cvss_v3_severity': cvss_v3_severity,
            'epss_score': epss_score if epss_score is not None else 0.0,
            'epss_percentile': epss_percentile if epss_percentile is not None else 0.0,
            'cisa_kev': vuln_data.get('cisa_kev', False),
            'vulncheck_kev': vuln_data.get('vulncheck_kev', False),
            'has_exploit': len(exploit_data) > 0,
            'exploit_count': len(exploit_data),
            'exploit_maturity': exploit_data[0].get('maturity', 'UNKNOWN') if exploit_data else 'NONE',
            'description': vuln_data.get('descriptions', [{}])[0].get('value', '')[:200],
            'published_date': vuln_data.get('published', ''),
            'last_modified': vuln_data.get('lastModified', '')
        }
    except Exception as e:
        logger.warning('Error enriching %s: %s', cve_id, e)
        return None

def classify_priority_tier(row):
    """Classify CVE into pyramid tiers based on VulnCheck intelligence."""
    # Pyramid tiers from exercise
    if row['cisa_kev'] and row['has_exploit'] and row['exploit_maturity'] == "WEAPONIZED":
        return "Ransomware/Botnets"
    elif row['cisa_kev'] and row['has_exploit']:
        return "Threat Actors (APTs)"
    elif row['cisa_kev']:
        return "Unattributed KEV"
    elif row['vulncheck_kev']:
        return "VulnCheck KEV"
    elif row['has_exploit'] and row['exploit_maturity'] == "WEAPONIZED":
        return "Weaponized"
    elif row['has_exploit']:
        return "Proof-of-Concept"
    else:
        return "All Other Vulnerabilities"

def main():
    print("Starting VulnCheck Technical Analysis...")
    
    all_cves = []
    
    # Step 1: Fetch CVEs for each CPE
    for cpe in SAMPLE_CPES:
        print(f"Processing CPE: {cpe}")
        cves = fetch_cves_for_cpe(cpe)
        for cve in cves[:5]:  # Limit to 5 CVEs per CPE for demo
            # API may return either dicts or plain CVE string identifiers
            if isinstance(cve, dict):
                cve_id = cve.get("cve")
            else:
                cve_id = cve

            if cve_id:
                enriched = enrich_cve_details(cve_id)
                if enriched:
                    enriched["affected_cpe"] = cpe
                    all_cves.append(enriched)
    
    # Create DataFrame
    df = pd.DataFrame(all_cves)
    # If no CVEs were gathered, write empty outputs and exit gracefully
    if df.empty:
        output_dir = Path("analysis")
        output_dir.mkdir(exist_ok=True)

        # write empty CSV/JSON
        csv_path = output_dir / "enriched_vulnerabilities.csv"
        df.to_csv(csv_path, index=False)
        json_path = output_dir / "vulnerabilities.json"
        df.to_json(json_path, orient="records", indent=2)

        summary = f"""
        ========================
        ANALYSIS SUMMARY
        ========================
        Total CVEs Found: 0

        No CVE data was retrieved. This commonly indicates an authorization
        issue when calling the VulnCheck API (HTTP 401). Please ensure
        that `VULNCHECK_API_KEY` is set and valid in your environment or
        in a .env file.
        """

        summary_path = output_dir / "analysis_summary.md"
        with open(summary_path, "w") as f:
            f.write(summary)

        print(summary)
        print(f"✅ Wrote empty outputs to: {output_dir}")
        raise SystemExit(1)

    # Step 2: Apply priority tier classification
    else:
        df['priority_tier'] = df.apply(classify_priority_tier, axis=1)
        
        # Coerce numeric types to ensure consistent formatting/operations
        # Ensure NaN values are properly filled before calculations
        df['cvss_v3_score'] = pd.to_numeric(df['cvss_v3_score'], errors='coerce').fillna(0.0)
        df['epss_score'] = pd.to_numeric(df['epss_score'], errors='coerce').fillna(0.0)
        df['exploit_count'] = pd.to_numeric(df['exploit_count'], errors='coerce').fillna(0).astype(int)

        # Calculate risk_score with proper NaN handling
        df['risk_score'] = (
            df['cvss_v3_score'] * 0.4 +
            df['epss_score'] * 100 * 0.3 +
            df['cisa_kev'].apply(lambda v: 10 if v else 0) +
            df['has_exploit'].apply(lambda v: 5 if v else 0)
        ).astype(float)

        # Sort by risk score
        df = df.sort_values('risk_score', ascending=False)
    
    # Step 3: Save outputs
    output_dir = Path("analysis")
    output_dir.mkdir(exist_ok=True)
    
    # Save as CSV
    csv_path = output_dir / "enriched_vulnerabilities.csv"
    df.to_csv(csv_path, index=False, float_format='%.4f')
    print(f"✅ Saved enriched data to: {csv_path}")
    
    # Save as JSON - replace NaN/None with 0.0 for numeric columns
    df_json = df.copy()
    df_json['cvss_v3_score'] = df_json['cvss_v3_score'].fillna(0.0)
    df_json['epss_score'] = df_json['epss_score'].fillna(0.0)
    df_json['epss_percentile'] = df_json['epss_percentile'].fillna(0.0)
    df_json['risk_score'] = df_json['risk_score'].fillna(0.0)
    
    json_path = output_dir / "vulnerabilities.json"
    df_json.to_json(json_path, orient="records", indent=2)
    print(f"✅ Saved JSON data to: {json_path}")
    
    # Generate summary
    summary = f"""
    ========================
    ANALYSIS SUMMARY
    ========================
    Total CVEs Found: {len(df)}
    
    Priority Tier Distribution:
    {df['priority_tier'].value_counts().to_string()}
    
    Severity Breakdown:
    - Critical (CVSS ≥ 9.0): {len(df[df['cvss_v3_score'] >= 9.0])}
    - High (CVSS ≥ 7.0): {len(df[df['cvss_v3_score'] >= 7.0])}
    - Medium (CVSS ≥ 4.0): {len(df[(df['cvss_v3_score'] >= 4.0) & (df['cvss_v3_score'] < 7.0)])}
    - Low (CVSS < 4.0): {len(df[df['cvss_v3_score'] < 4.0])}
    
    Exploit Intelligence:
    - With Exploits: {df['has_exploit'].sum()}
    - CISA KEV: {df['cisa_kev'].sum()}
    - VulnCheck KEV: {df['vulncheck_kev'].sum()}
    
    Top 5 Highest Risk CVEs:
    {df[['cve_id', 'cvss_v3_score', 'priority_tier', 'risk_score']].head().to_string()}
    """
    
    summary_path = output_dir / "analysis_summary.md"
    with open(summary_path, "w") as f:
        f.write(summary)
    
    print(summary)
    print(f"✅ Saved summary to: {summary_path}")
    print("\n✅ Analysis complete! Run 'python dashboard_app.py' to launch the dashboard.")

if __name__ == "__main__":
    main()