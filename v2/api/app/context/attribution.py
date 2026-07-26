"""
================================================================================
AEGIS AI v2 - Attack Attribution Module
================================================================================

Module      : attribution.py
Description : Adaptive context extraction — determines WHERE an attack came
              from when source/destination IP data is available, and
              gracefully degrades to port-level attribution when it isn't
              (e.g. anonymized public benchmark datasets like CIC-IDS-2017).
Author      : Prerak Nain
================================================================================
"""

import pandas as pd
from typing import Dict, List, Optional

from app.context.sliding_window import (
    normalize_schema,
    prepare_timestamps,
    build_sliding_windows_host,
)


# ==============================================================================
# COMMON PORT REFERENCE — for the degraded (no-IP) mode
# ==============================================================================

PORT_REFERENCE = {
    20: "FTP (data)", 21: "FTP (control)", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    27017: "MongoDB",
}

PORT_RISK_NOTES = {
    22: "credential/brute-force target",
    3389: "common ransomware entry point after compromise",
    3306: "database — potential data exfiltration target",
    5432: "database — potential data exfiltration target",
    445: "SMB — lateral movement / worm propagation vector",
    23: "Telnet — legacy, frequently unencrypted credentials",
}


# ==============================================================================
# IP ATTRIBUTION DETECTION
# ==============================================================================

def has_ip_attribution(df: pd.DataFrame) -> bool:
    """
    Check whether the uploaded data includes source/destination IP columns.

    Returns True for Zeek conn.log format (id.orig_h/id.resp_h) or an
    unmodified CICFlowMeter export (Source IP/Destination IP). Returns
    False for anonymized public benchmark data like CIC-IDS-2017, which
    strips IP columns before release.
    """
    cols_lower = [str(c).strip().lower() for c in df.columns]

    src_markers = {"source ip", "src_ip", "id.orig_h", "sa"}
    dst_markers = {"destination ip", "dst_ip", "id.resp_h", "da"}

    has_src = any(c in cols_lower for c in src_markers)
    has_dst = any(c in cols_lower for c in dst_markers)

    return has_src and has_dst


def _find_column(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    """Find the actual column name matching one of several possible labels."""
    cols_lower = {str(c).strip().lower(): c for c in df.columns}
    for candidate in candidates:
        if candidate in cols_lower:
            return cols_lower[candidate]
    return None


# ==============================================================================
# MODE A: FULL HOST-CENTRIC ATTRIBUTION (IP data available)
# ==============================================================================

def extract_full_attribution(df: pd.DataFrame, row_index: int) -> Dict:
    """
    Full attribution using sliding-window host-centric analysis.
    Requires src_ip, dst_ip, and timestamp columns to be present.
    """
    try:
        working = normalize_schema(df.copy(), schema="auto")
        working = prepare_timestamps(working)
    except Exception as e:
        return {
            "mode": "full",
            "available": False,
            "reason": f"Could not normalize schema/timestamps: {e}",
        }

    if row_index >= len(working):
        row_index = 0

    target_row = working.iloc[row_index]
    host_ip = target_row.get("src_ip")

    if host_ip is None:
        return {"mode": "full", "available": False, "reason": "No src_ip on target row"}

    # Run host-centric windows at the 1min scale — a reasonable default
    # granularity for behavioral context around a single flagged flow
    window_size = pd.Timedelta("1min")
    host_windows = build_sliding_windows_host(
        working, window_label="1min", window_size=window_size,
        step_size=window_size / 2, label_col="label"
    )

    if len(host_windows) == 0:
        return {
            "mode": "full", "available": True, "host_ip": str(host_ip),
            "behavioral_context": None,
            "note": "IP present but insufficient windowed activity to profile.",
        }

    # Find the window(s) covering this host, pick the most active one
    host_matches = host_windows[host_windows["host_ip"] == host_ip]
    if len(host_matches) == 0:
        return {
            "mode": "full", "available": True, "host_ip": str(host_ip),
            "behavioral_context": None,
            "note": "IP present but no matching windowed profile found.",
        }

    profile = host_matches.sort_values("host_conn_count", ascending=False).iloc[0].to_dict()

    return {
        "mode": "full",
        "available": True,
        "host_ip": str(host_ip),
        "behavioral_context": {
            "connection_count": int(profile.get("host_conn_count", 0)),
            "timing_regularity_cv": round(float(profile.get("host_iat_cv", 0) or 0), 4),
            "external_traffic_ratio": round(float(profile.get("host_external_ratio", 0) or 0), 3),
            "unique_destination_ports": int(profile.get("host_unique_dst_ports", 0) or 0),
            "port_scan_signature": round(float(profile.get("host_port_scan_score", 0) or 0), 3),
            "failed_connection_ratio": round(float(profile.get("host_failed_ratio", 0) or 0), 3),
            "top_destination_ratio": round(float(profile.get("host_top_dst_ratio", 0) or 0), 3),
        },
    }


# ==============================================================================
# MODE B: DEGRADED PORT-LEVEL ATTRIBUTION (no IP data — e.g. CIC-IDS-2017)
# ==============================================================================

def extract_port_attribution(df: pd.DataFrame, row_index: int) -> Dict:
    """
    Fallback attribution when IP columns are unavailable. Uses destination
    port alone — still gives useful signal about the LIKELY TARGET SERVICE
    and intent, even without knowing the source.
    """
    port_col = _find_column(df, ["destination port", "dst_port", "dp"])

    if port_col is None:
        return {
            "mode": "degraded",
            "available": False,
            "reason": "No destination port column found either.",
        }

    if row_index >= len(df):
        row_index = 0

    try:
        port = int(df.iloc[row_index][port_col])
    except (ValueError, TypeError):
        return {"mode": "degraded", "available": False, "reason": "Port value not numeric."}

    service = PORT_REFERENCE.get(port, "unrecognized/high port")
    risk_note = PORT_RISK_NOTES.get(port)

    return {
        "mode": "degraded",
        "available": True,
        "host_ip": None,
        "destination_port": port,
        "likely_service": service,
        "risk_note": risk_note,
        "disclosure": (
            "Source IP attribution unavailable — this dataset does not "
            "include IP address columns (standard anonymization for "
            "published security benchmarks like CIC-IDS-2017). Upload "
            "Zeek conn.log or an unmodified CICFlowMeter export for full "
            "source attribution."
        ),
    }


# ==============================================================================
# PUBLIC ENTRY POINT
# ==============================================================================

def get_attack_context(df: pd.DataFrame, row_index: int) -> Dict:
    """
    Main entry point. Automatically selects full or degraded attribution
    mode based on what data is actually present in the uploaded file.
    """
    if has_ip_attribution(df):
        result = extract_full_attribution(df, row_index)
        if result.get("available"):
            return result
        # Full mode was attempted but failed for some reason — fall back
        return extract_port_attribution(df, row_index)

    return extract_port_attribution(df, row_index)