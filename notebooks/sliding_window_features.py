import pandas as pd
import numpy as np

# ============================================================
# SLIDING WINDOW FEATURE EXTRACTION
# Now supports BOTH network-centric AND host-centric analysis
# ============================================================

WINDOW_SIZES = {
    "10s":  pd.Timedelta("10s"),
    "1min": pd.Timedelta("1min"),
    "5min": pd.Timedelta("5min"),
    "15min": pd.Timedelta("15min"),
    "1hr":  pd.Timedelta("1hr"),
}

# Schema adapters (same as before)
SCHEMA_ADAPTERS = {
    "zeek": {
        "ts": "timestamp", "id.orig_h": "src_ip", "id.resp_h": "dst_ip",
        "id.orig_p": "src_port", "id.resp_p": "dst_port", "proto": "protocol",
        "duration": "duration", "orig_bytes": "orig_bytes", 
        "resp_bytes": "dst_bytes", "conn_state": "conn_state",
    },
    "cicids": {
        "Timestamp": "timestamp", "Source IP": "src_ip", "Destination IP": "dst_ip",
        "Source Port": "src_port", "Destination Port": "dst_port", "Protocol": "protocol",
        "Flow Duration": "duration", "Total Fwd Packets": "orig_bytes",
        "Total Backward Packets": "dst_bytes", "Label": "label",
    },
    "netflow": {
        "te": "timestamp", "sa": "src_ip", "da": "dst_ip", "sp": "src_port",
        "dp": "dst_port", "pr": "protocol", "td": "duration",
        "ibyt": "orig_bytes", "obyt": "dst_bytes", "lbl": "label",
    },
    "universal": None,
}


def detect_schema(df):
    """Auto-detect dataset format."""
    cols = set(df.columns)
    if "id.orig_h" in cols: return "zeek"
    if "Source IP" in cols and "Flow Duration" in cols: return "cicids"
    if "sa" in cols and "ibyt" in cols: return "netflow"
    if "src_ip" in cols and "timestamp" in cols: return "universal"
    raise ValueError(f"Unknown schema: {list(cols)[:10]}")


def normalize_schema(df, schema="auto"):
    """Convert to universal column names."""
    if schema == "auto":
        schema = detect_schema(df)
        print(f"[Schema] Detected: {schema}")
    
    mapping = SCHEMA_ADAPTERS.get(schema)
    if mapping:
        df = df.rename(columns={k: v for k, v in mapping.items() if k in df.columns})
    return df


def prepare_timestamps(df):
    """Convert timestamp column to datetime."""
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        if pd.api.types.is_float_dtype(df["timestamp"]) or pd.api.types.is_integer_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


# ============================================================
# NETWORK-CENTRIC FEATURE EXTRACTION (Original)
# ============================================================

def aggregate_window_network(window_df):
    """
    Extract NETWORK-WIDE features from a window.
    Looks at overall traffic patterns.
    """
    feats = {}
    n = len(window_df)
    feats["conn_count"] = n
    
    if n == 0:
        return feats
    
    cols = set(window_df.columns)
    
    # Volume features
    if "orig_bytes" in cols:
        ob = pd.to_numeric(window_df["orig_bytes"], errors="coerce").fillna(0)
        feats["orig_bytes_sum"] = ob.sum()
        feats["orig_bytes_mean"] = ob.mean()
        feats["orig_bytes_std"] = ob.std(ddof=0)
    
    if "dst_bytes" in cols:
        db = pd.to_numeric(window_df["dst_bytes"], errors="coerce").fillna(0)
        feats["dst_bytes_sum"] = db.sum()
        feats["dst_bytes_mean"] = db.mean()
        feats["dst_bytes_std"] = db.std(ddof=0)
    
    if "orig_bytes" in cols and "dst_bytes" in cols:
        feats["bytes_ratio"] = feats.get("orig_bytes_sum", 0) / (feats.get("dst_bytes_sum", 0) + 1e-9)
    
    # Duration features
    if "duration" in cols:
        dur = pd.to_numeric(window_df["duration"], errors="coerce").fillna(0)
        feats["duration_mean"] = dur.mean()
        feats["duration_max"] = dur.max()
        feats["duration_std"] = dur.std(ddof=0)
    
    # Diversity features
    if "src_ip" in cols:
        feats["unique_src_ips"] = window_df["src_ip"].nunique()
    if "dst_ip" in cols:
        feats["unique_dst_ips"] = window_df["dst_ip"].nunique()
    if "dst_port" in cols:
        feats["unique_dst_ports"] = window_df["dst_port"].nunique()
    if "src_port" in cols:
        feats["unique_src_ports"] = window_df["src_port"].nunique()
    
    # Connection state features
    if "conn_state" in cols:
        feats["unique_conn_states"] = window_df["conn_state"].nunique()
        failed = window_df["conn_state"].isin(["REJ", "RSTO", "RSTOS0", "S0"])
        feats["failed_conn_ratio"] = failed.sum() / n if n > 0 else 0
    
    # Protocol distribution
    if "protocol" in cols:
        proto = window_df["protocol"].str.lower().value_counts(normalize=True)
        for p in ["tcp", "udp", "icmp"]:
            feats[f"proto_ratio_{p}"] = proto.get(p, 0.0)
    
    # Fan-out (lateral movement signal)
    if "src_ip" in cols and "dst_ip" in cols and n > 0:
        top_src = window_df["src_ip"].value_counts().idxmax()
        feats["top_src_fanout"] = window_df[window_df["src_ip"] == top_src]["dst_ip"].nunique()
    
    # Inter-arrival time
    if "timestamp" in cols and n > 1:
        ts = window_df["timestamp"].sort_values()
        iat = ts.diff().dt.total_seconds().dropna()
        if len(iat) > 0:
            feats["iat_mean"] = iat.mean()
            feats["iat_std"] = iat.std(ddof=0)
            feats["iat_min"] = iat.min()
    
    return feats


# ============================================================
# HOST-CENTRIC FEATURE EXTRACTION (NEW!)
# ============================================================

def aggregate_window_host(window_df, host_ip):
    """
    Extract features for a SINGLE HOST within a window.
    Tracks individual host behavior for detecting slow/stealthy attacks.
    
    Parameters:
    -----------
    window_df : DataFrame filtered to one host's connections
    host_ip : str, the source IP we're analyzing
    """
    feats = {}
    n = len(window_df)
    
    # Basic info
    feats["host_ip"] = host_ip
    feats["host_conn_count"] = n
    
    if n == 0:
        return feats
    
    cols = set(window_df.columns)
    
    # ========================================
    # HOST VOLUME PATTERNS
    # ========================================
    if "orig_bytes" in cols:
        ob = pd.to_numeric(window_df["orig_bytes"], errors="coerce").fillna(0)
        feats["host_bytes_sent_sum"] = ob.sum()
        feats["host_bytes_sent_mean"] = ob.mean()
        feats["host_bytes_sent_std"] = ob.std(ddof=0)
        feats["host_bytes_sent_max"] = ob.max()
    
    if "dst_bytes" in cols:
        db = pd.to_numeric(window_df["dst_bytes"], errors="coerce").fillna(0)
        feats["host_bytes_recv_sum"] = db.sum()
        feats["host_bytes_recv_mean"] = db.mean()
        feats["host_bytes_recv_std"] = db.std(ddof=0)
    
    # Upload/download ratio (data exfiltration signal)
    if "orig_bytes" in cols and "dst_bytes" in cols:
        feats["host_upload_download_ratio"] = (
            feats.get("host_bytes_sent_sum", 0) / (feats.get("host_bytes_recv_sum", 0) + 1e-9)
        )
    
    # ========================================
    # HOST DIVERSITY (Lateral Movement Detection)
    # ========================================
    if "dst_ip" in cols:
        feats["host_unique_destinations"] = window_df["dst_ip"].nunique()
        # Ratio: How many different hosts contacted vs total connections
        feats["host_destination_diversity"] = feats["host_unique_destinations"] / n
    
    if "dst_port" in cols:
        feats["host_unique_dst_ports"] = window_df["dst_port"].nunique()
        # High port diversity = scanning behavior
        feats["host_port_diversity"] = feats["host_unique_dst_ports"] / n
    
    # Service diversity (reconnaissance signal)
    if "protocol" in cols:
        feats["host_unique_protocols"] = window_df["protocol"].nunique()
    
    # ========================================
    # HOST TIMING PATTERNS (Beaconing/Regularity)
    # ========================================
    if "timestamp" in cols and n > 1:
        ts = window_df["timestamp"].sort_values()
        iat = ts.diff().dt.total_seconds().dropna()
        
        if len(iat) > 0:
            feats["host_iat_mean"] = iat.mean()
            feats["host_iat_std"] = iat.std(ddof=0)
            feats["host_iat_min"] = iat.min()
            feats["host_iat_max"] = iat.max()
            
            # Coefficient of variation (regularity metric)
            # Low CV = very regular (beaconing)
            if feats["host_iat_mean"] > 0:
                feats["host_iat_cv"] = feats["host_iat_std"] / feats["host_iat_mean"]
    
    if "duration" in cols:
        dur = pd.to_numeric(window_df["duration"], errors="coerce").fillna(0)
        feats["host_duration_mean"] = dur.mean()
        feats["host_duration_std"] = dur.std(ddof=0)
        feats["host_duration_max"] = dur.max()
    
    # ========================================
    # HOST BEHAVIORAL PATTERNS
    # ========================================
    
    # Failed connections (brute force, reconnaissance)
    if "conn_state" in cols:
        failed = window_df["conn_state"].isin(["REJ", "RSTO", "RSTOS0", "S0", "RSTR"])
        feats["host_failed_count"] = failed.sum()
        feats["host_failed_ratio"] = failed.sum() / n if n > 0 else 0
        
        # Connection state entropy (diversity of outcomes)
        state_counts = window_df["conn_state"].value_counts(normalize=True)
        feats["host_conn_state_entropy"] = -(state_counts * np.log2(state_counts + 1e-9)).sum()
    
    # Protocol distribution for this host
    if "protocol" in cols:
        proto = window_df["protocol"].str.lower().value_counts(normalize=True)
        for p in ["tcp", "udp", "icmp"]:
            feats[f"host_proto_ratio_{p}"] = proto.get(p, 0.0)
    
    # ========================================
    # HOST DESTINATION PATTERNS
    # ========================================
    
    # Top destination (is this host focused on one target?)
    if "dst_ip" in cols and n > 0:
        top_dst = window_df["dst_ip"].value_counts()
        if len(top_dst) > 0:
            feats["host_top_dst_count"] = top_dst.iloc[0]
            feats["host_top_dst_ratio"] = top_dst.iloc[0] / n
    
    # External vs internal communication
    if "dst_ip" in cols:
        # Simple heuristic: private IPs (RFC1918)
        def is_internal(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) != 4:
                    return False
                first = int(parts[0])
                second = int(parts[1])
                # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                return False
            except:
                return False
        
        internal_mask = window_df["dst_ip"].apply(is_internal)
        feats["host_internal_conn_count"] = internal_mask.sum()
        feats["host_external_conn_count"] = (~internal_mask).sum()
        feats["host_external_ratio"] = feats["host_external_conn_count"] / n if n > 0 else 0
    
    # ========================================
    # HOST PORT PATTERNS
    # ========================================
    
    if "dst_port" in cols:
        # Common service ports
        common_ports = {80, 443, 22, 23, 25, 53, 110, 143, 3389, 3306, 5432}
        port_values = pd.to_numeric(window_df["dst_port"], errors="coerce")
        common_mask = port_values.isin(common_ports)
        
        feats["host_common_port_ratio"] = common_mask.sum() / n if n > 0 else 0
        feats["host_uncommon_port_count"] = (~common_mask).sum()
        
        # Port scanning indicators
        if feats.get("host_unique_dst_ports", 0) > 10:
            # Many ports, few connections each = scan
            port_counts = window_df["dst_port"].value_counts()
            feats["host_port_scan_score"] = (port_counts == 1).sum() / len(port_counts)
    
    return feats


# ============================================================
# TARGET-CENTRIC FEATURE EXTRACTION (NEW!)
# ============================================================

def aggregate_window_target(window_df, target_ip):
    """
    Extract features for a SINGLE TARGET (destination) within a window.
    Tracks what's happening TO a specific host/server.
    Useful for detecting attacks against specific targets.
    """
    feats = {}
    n = len(window_df)
    
    feats["target_ip"] = target_ip
    feats["target_incoming_count"] = n
    
    if n == 0:
        return feats
    
    cols = set(window_df.columns)
    
    # How many different sources are contacting this target?
    if "src_ip" in cols:
        feats["target_unique_sources"] = window_df["src_ip"].nunique()
        feats["target_source_diversity"] = feats["target_unique_sources"] / n
        
        # Is one source dominating?
        top_src_count = window_df["src_ip"].value_counts().iloc[0]
        feats["target_top_source_ratio"] = top_src_count / n
    
    # Which ports are being targeted?
    if "dst_port" in cols:
        feats["target_unique_ports_hit"] = window_df["dst_port"].nunique()
        top_port = window_df["dst_port"].value_counts()
        if len(top_port) > 0:
            feats["target_most_hit_port"] = top_port.index[0]
            feats["target_top_port_ratio"] = top_port.iloc[0] / n
    
    # Connection success rate (target under attack?)
    if "conn_state" in cols:
        failed = window_df["conn_state"].isin(["REJ", "RSTO", "RSTOS0", "S0"])
        feats["target_failed_incoming_ratio"] = failed.sum() / n if n > 0 else 0
    
    # Volume received
    if "dst_bytes" in cols:
        db = pd.to_numeric(window_df["dst_bytes"], errors="coerce").fillna(0)
        feats["target_bytes_received_sum"] = db.sum()
    
    return feats


# ============================================================
# SLIDING WINDOW BUILDERS
# ============================================================

def build_sliding_windows_network(df, window_label, window_size, step_size=None, label_col="label"):
    """
    NETWORK-CENTRIC: Create windows analyzing entire network.
    (Original implementation)
    """
    if step_size is None:
        step_size = window_size / 2
    
    t_start = df["timestamp"].min()
    t_end = df["timestamp"].max()
    records = []
    current = t_start
    
    while current + window_size <= t_end + step_size:
        window_end = current + window_size
        mask = (df["timestamp"] >= current) & (df["timestamp"] < window_end)
        window_df = df[mask]
        
        feats = aggregate_window_network(window_df)
        feats["window"] = window_label
        feats["window_start"] = current
        feats["window_end"] = window_end
        feats["analysis_type"] = "network"
        
        if label_col in df.columns and len(window_df) > 0:
            feats["label"] = window_df[label_col].mode()[0] if len(window_df[label_col].mode()) > 0 else "unknown"
        
        records.append(feats)
        current += step_size
    
    return pd.DataFrame(records)


def build_sliding_windows_host(df, window_label, window_size, step_size=None, label_col="label"):
    """
    HOST-CENTRIC: Create windows for EACH source host separately.
    This catches slow/stealthy attacks from individual compromised hosts.
    """
    if step_size is None:
        step_size = window_size / 2
    
    if "src_ip" not in df.columns:
        print("[Warning] No src_ip column - skipping host-centric analysis")
        return pd.DataFrame()
    
    t_start = df["timestamp"].min()
    t_end = df["timestamp"].max()
    records = []
    
    # Get all unique source IPs
    hosts = df["src_ip"].unique()
    
    print(f"  [Host-Centric] Analyzing {len(hosts)} unique hosts...")
    
    for host in hosts:
        # Filter to this host's connections only
        host_df = df[df["src_ip"] == host]
        
        if len(host_df) == 0:
            continue
        
        current = t_start
        while current + window_size <= t_end + step_size:
            window_end = current + window_size
            mask = (host_df["timestamp"] >= current) & (host_df["timestamp"] < window_end)
            window_df = host_df[mask]
            
            # Only analyze if host had activity in this window
            if len(window_df) > 0:
                feats = aggregate_window_host(window_df, host)
                feats["window"] = window_label
                feats["window_start"] = current
                feats["window_end"] = window_end
                feats["analysis_type"] = "host"
                
                if label_col in df.columns:
                    feats["label"] = window_df[label_col].mode()[0] if len(window_df[label_col].mode()) > 0 else "unknown"
                
                records.append(feats)
            
            current += step_size
    
    return pd.DataFrame(records)


def build_sliding_windows_target(df, window_label, window_size, step_size=None, label_col="label"):
    """
    TARGET-CENTRIC: Create windows for EACH destination separately.
    This catches attacks against specific servers/targets.
    """
    if step_size is None:
        step_size = window_size / 2
    
    if "dst_ip" not in df.columns:
        print("[Warning] No dst_ip column - skipping target-centric analysis")
        return pd.DataFrame()
    
    t_start = df["timestamp"].min()
    t_end = df["timestamp"].max()
    records = []
    
    # Get all unique destination IPs
    targets = df["dst_ip"].unique()
    
    print(f"  [Target-Centric] Analyzing {len(targets)} unique targets...")
    
    for target in targets:
        # Filter to connections TO this target
        target_df = df[df["dst_ip"] == target]
        
        if len(target_df) == 0:
            continue
        
        current = t_start
        while current + window_size <= t_end + step_size:
            window_end = current + window_size
            mask = (target_df["timestamp"] >= current) & (target_df["timestamp"] < window_end)
            window_df = target_df[mask]
            
            if len(window_df) > 0:
                feats = aggregate_window_target(window_df, target)
                feats["window"] = window_label
                feats["window_start"] = current
                feats["window_end"] = window_end
                feats["analysis_type"] = "target"
                
                if label_col in df.columns:
                    feats["label"] = window_df[label_col].mode()[0] if len(window_df[label_col].mode()) > 0 else "unknown"
                
                records.append(feats)
            
            current += step_size
    
    return pd.DataFrame(records)


# ============================================================
# UNIFIED PIPELINE
# ============================================================

def build_all_windows(
    df, 
    schema="auto", 
    label_col="label", 
    step_fraction=0.5,
    analysis_types=["network", "host"]  # NEW: Choose analysis types!
):
    """
    Full pipeline with MULTIPLE analysis perspectives.
    
    Parameters:
    -----------
    df : DataFrame
        Raw network traffic data
    schema : str
        Format: "zeek", "cicids", "netflow", "auto"
    label_col : str
        Column with attack labels (if available)
    step_fraction : float
        Step size as fraction of window (0.5 = 50% overlap)
    analysis_types : list
        Which analyses to run: ["network"], ["host"], ["target"], or ["network", "host", "target"]
    
    Returns:
    --------
    dict of dicts:
        {
            "network": {"10s": df, "1min": df, ...},
            "host": {"10s": df, "1min": df, ...},
            "target": {"10s": df, "1min": df, ...}
        }
    """
    print("[1/3] Normalizing schema...")
    df = normalize_schema(df, schema=schema)
    
    print("[2/3] Preparing timestamps...")
    df = prepare_timestamps(df)
    
    print(f"[3/3] Building windows over {len(df):,} rows")
    print(f"      Time range: {df['timestamp'].min()} → {df['timestamp'].max()}")
    print(f"      Analysis types: {', '.join(analysis_types)}")
    
    all_results = {}
    
    for analysis_type in analysis_types:
        print(f"\n=== {analysis_type.upper()}-CENTRIC ANALYSIS ===")
        
        type_results = {}
        for label, size in WINDOW_SIZES.items():
            step = size * step_fraction
            
            if analysis_type == "network":
                result = build_sliding_windows_network(df, label, size, step, label_col)
            elif analysis_type == "host":
                result = build_sliding_windows_host(df, label, size, step, label_col)
            elif analysis_type == "target":
                result = build_sliding_windows_target(df, label, size, step, label_col)
            else:
                print(f"Unknown analysis type: {analysis_type}")
                continue
            
            type_results[label] = result
            print(f"  ✓ {label:6} → {len(result):6,} windows, {len(result.columns):2} features")
        
        all_results[analysis_type] = type_results
    
    return all_results


def merge_all_windows(all_windows):
    """
    Combine all window types and sizes into one dataset.
    Now handles multiple analysis types.
    """
    all_frames = []
    
    for analysis_type, windows_dict in all_windows.items():
        for window_size, df in windows_dict.items():
            if len(df) > 0:
                all_frames.append(df)
    
    if not all_frames:
        return pd.DataFrame()
    
    combined = pd.concat(all_frames, ignore_index=True)
    
    # One-hot encode window size and analysis type
    if "window" in combined.columns:
        combined = pd.get_dummies(combined, columns=["window"], prefix="scale")
    if "analysis_type" in combined.columns:
        combined = pd.get_dummies(combined, columns=["analysis_type"], prefix="view")
    
    return combined


# ============================================================
# USAGE EXAMPLE
# ============================================================

if __name__ == "__main__":
    
    # Load your data
    # df = pd.read_csv("conn.log", sep="\t", ...)
    
    # Option 1: Network-centric only (original)
    # windows = build_all_windows(df, analysis_types=["network"])
    
    # Option 2: Both network AND host-centric (RECOMMENDED)
    # windows = build_all_windows(df, analysis_types=["network", "host"])
    
    # Option 3: All three perspectives
    # windows = build_all_windows(df, analysis_types=["network", "host", "target"])
    
    # Access results:
    # df_network_1min = windows["network"]["1min"]
    # df_host_1min = windows["host"]["1min"]
    # df_target_1min = windows["target"]["1min"]
    
    print("Feature extraction code loaded!")
    print("Use: build_all_windows(df, analysis_types=['network', 'host'])")
