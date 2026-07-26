"""Quick standalone test for attribution.py — run directly, no server needed."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # v2/api/

import pandas as pd
from app.context.attribution import get_attack_context, has_ip_attribution


def test_no_ip_data():
    """Simulates your current CIC-IDS-2017 files — no IP columns."""
    df = pd.DataFrame({
        " Destination Port": [3389, 80, 22],
        " Flow Duration": [1200, 500, 8000],
    })
    print("=== TEST: No IP data (CIC-IDS-2017 style) ===")
    print("has_ip_attribution:", has_ip_attribution(df))
    result = get_attack_context(df, row_index=0)
    print(result)
    print()


def test_with_ip_data():
    """
    Simulates Zeek-style data — has src/dst IP + timestamp.
    Uses a full minute of activity so the 1min sliding window
    has enough span to actually form a window.
    """
    base_time = pd.Timestamp("2026-01-01 00:00:00")
    n = 20
    df = pd.DataFrame({
        "timestamp": [base_time + pd.Timedelta(seconds=3 * i) for i in range(n)],
        "id.orig_h": ["203.0.113.45"] * n,
        "id.resp_h": ["10.0.0.5"] * n,
        "id.orig_p": [51234 + i for i in range(n)],
        "id.resp_p": [80] * n,
        "proto": ["tcp"] * n,
        "duration": [0.1] * n,
        "conn_state": ["S0"] * n,  # failed/half-open — DDoS-like signature
        "label": ["DDoS"] * n,
    })
    print("=== TEST: With IP data (Zeek style, 20 rows over ~1min) ===")
    print("has_ip_attribution:", has_ip_attribution(df))
    result = get_attack_context(df, row_index=0)
    print(result)
    print()


if __name__ == "__main__":
    test_no_ip_data()
    test_with_ip_data()