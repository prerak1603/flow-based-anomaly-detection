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

import logging

import pandas as pd
from typing import Dict, List, Optional

from app.context.sliding_window import (
    normalize_schema,
    prepare_timestamps,
    build_sliding_windows_host,
)

logger = logging.getLogger("aegis")


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

def _normalize_col(col: str) -> str:
    """
    Normalize a column name for alias matching: lowercase, strip, and
    collapse the common separator conventions (space/underscore/hyphen/dot)
    to a single space, so "Src IP", "src_ip", "SRC-IP", and "id.orig_h" all
    compare the same way regardless of which tool produced the file.
    "SourceIP"-style no-separator variants are handled as explicit aliases
    below rather than here, since there's no separator to collapse.
    """
    c = str(col).strip().lower()
    for sep in ("_", "-", "."):
        c = c.replace(sep, " ")
    return c


# Every variant here maps to the SAME real-world field via name, regardless
# of position in the file — a column matches by what it's called, not by
# where it sits among the other columns. Previously this only matched
# "source ip" / "src_ip" / "id.orig_h" / "sa" (and the destination
# equivalents) — genuine variants like "Src IP", "source_ip", and
# "SourceIP" fell through and were silently treated as "no IP data".
SRC_IP_ALIASES = {"source ip", "src ip", "sourceip", "srcip", "id orig h", "sa"}
DST_IP_ALIASES = {"destination ip", "dst ip", "destinationip", "dstip", "id resp h", "da"}


def detect_ip_columns(df: pd.DataFrame) -> Optional[Dict[str, str]]:
    """
    Scan by column NAME for source/destination IP columns — not by
    position or exact casing. Returns the actual column names found, e.g.
    {"source": "Source IP", "destination": "Destination IP"}, so a caller
    (or a log line, or the API response) can state plainly what was
    detected instead of it being an opaque yes/no. Returns None if either
    side is missing.
    """
    normalized = {_normalize_col(c): c for c in df.columns}

    src_col = next((normalized[a] for a in SRC_IP_ALIASES if a in normalized), None)
    dst_col = next((normalized[a] for a in DST_IP_ALIASES if a in normalized), None)

    if src_col and dst_col:
        return {"source": src_col, "destination": dst_col}
    return None


def has_ip_attribution(df: pd.DataFrame) -> bool:
    """
    Check whether the uploaded data includes source/destination IP columns.

    Returns True for Zeek conn.log format (id.orig_h/id.resp_h) or an
    unmodified CICFlowMeter export (Source IP/Destination IP), under any
    of the common naming variants (see SRC_IP_ALIASES/DST_IP_ALIASES).
    Returns False for anonymized public benchmark data like CIC-IDS-2017,
    which strips IP columns before release.
    """
    return detect_ip_columns(df) is not None


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

    The IP lookup itself only needs src_ip/dst_ip (via schema
    normalization); a timestamp column is only needed for the *behavioral*
    (sliding-window) profiling on top of that. These used to be gated
    together — a normalize_schema()+prepare_timestamps() pair wrapped in
    one try/except — so a file with real IP columns but no Timestamp
    column (common; CICFlowMeter exports frequently omit it) raised inside
    prepare_timestamps(), got swallowed by that except, and the caller
    (get_attack_context) saw `available: False` and fell all the way back
    to degraded/port-only mode — discarding the IP data that was actually
    right there. Fixed by resolving host_ip first (schema-only, no
    timestamp needed) and only gating the sliding-window step specifically
    on timestamps, degrading gracefully to "IP known, no behavioral
    context" instead of "no IP data at all" when timestamps are missing.
    """
    try:
        working = normalize_schema(df.copy(), schema="auto")
    except Exception as e:
        return {"mode": "full", "available": False, "reason": f"Could not normalize schema: {e}"}

    if "src_ip" not in working.columns:
        return {"mode": "full", "available": False, "reason": "No src_ip column after schema normalization"}

    if row_index >= len(working):
        row_index = 0

    target_row = working.iloc[row_index]
    host_ip = target_row.get("src_ip")

    if host_ip is None or (isinstance(host_ip, float) and pd.isna(host_ip)):
        return {"mode": "full", "available": False, "reason": "No src_ip on target row"}

    try:
        working = prepare_timestamps(working)
    except Exception as e:
        return {
            "mode": "full",
            "available": True,
            "host_ip": str(host_ip),
            "behavioral_context": None,
            "note": f"IP present but no usable timestamp column for windowed behavioral analysis ({e}).",
        }

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

    Every result carries `ip_columns_detected` — the actual column names
    matched (e.g. {"source": "Source IP", "destination": "Destination IP"}),
    or None if neither side was found — so which columns drove the mode
    decision is visible in the API response and logs, not just inferrable
    from which mode came back.
    """
    ip_columns = detect_ip_columns(df)
    logger.info(f"Attribution: ip_columns_detected={ip_columns}")

    if ip_columns:
        result = extract_full_attribution(df, row_index)
        if not result.get("available"):
            # Full mode was attempted but failed for some reason — fall back
            result = extract_port_attribution(df, row_index)
    else:
        result = extract_port_attribution(df, row_index)

    result["ip_columns_detected"] = ip_columns
    return result