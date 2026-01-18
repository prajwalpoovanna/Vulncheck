import pytest
import pandas as pd
from run_analysis import classify_priority_tier


def make_row(**kwargs):
    defaults = {
        'cisa_kev': False,
        'vulncheck_kev': False,
        'has_exploit': False,
        'exploit_maturity': 'NONE',
        'cvss_v3_score': 0.0,
        'epss_score': 0.0
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


def test_classify_ransomware():
    row = make_row(cisa_kev=True, has_exploit=True, exploit_maturity='WEAPONIZED')
    assert classify_priority_tier(row) == 'Ransomware/Botnets'


def test_classify_vulncheck_kev():
    row = make_row(vulncheck_kev=True)
    assert classify_priority_tier(row) == 'VulnCheck KEV'


def test_classify_weaponized():
    row = make_row(has_exploit=True, exploit_maturity='WEAPONIZED')
    assert classify_priority_tier(row) == 'Weaponized'
