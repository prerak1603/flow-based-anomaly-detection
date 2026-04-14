"""
STEP 1: Prepare NSL-KDD Dataset
This converts NSL-KDD to work with your Phase 1 code
"""

import pandas as pd
import numpy as np
import os

print("Starting NSL-KDD preparation...")

# ============================================================
# AUTOMATIC PATH DETECTION
# ============================================================

# Get the location of this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Go up one level to project root
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

print(f"Project folder: {PROJECT_ROOT}")

# File locations
NSLKDD_PATH = os.path.join(PROJECT_ROOT, "csv_files", "KDDTrain+.txt")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "csv_output", "nslkdd_converted.csv")

# ============================================================
# NSL-KDD COLUMN NAMES (it has no headers in the file)
# ============================================================

COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# ============================================================
# MAIN CONVERSION FUNCTION
# ============================================================

def prepare_nslkdd():
    """
    Load NSL-KDD and convert to conn.log format
    """
    
    print("\n" + "="*60)
    print("STEP 1: PREPARING NSL-KDD DATASET")
    print("="*60)
    
    # Check if file exists
    print(f"\nLooking for KDDTrain+.txt...")
    print(f"Expected location: {NSLKDD_PATH}")
    
    if not os.path.exists(NSLKDD_PATH):
        print("\n❌ ERROR: KDDTrain+.txt NOT FOUND!")
        print("\nPlease move KDDTrain+.txt to:")
        print(f"  → {os.path.join(PROJECT_ROOT, 'csv_files')}/")
        print("\n(Put it in the same folder as conn.log)")
        
        # Try to list what's actually in csv_files
        csv_files_dir = os.path.join(PROJECT_ROOT, "csv_files")
        if os.path.exists(csv_files_dir):
            print("\nCurrently in csv_files folder:")
            for f in os.listdir(csv_files_dir):
                print(f"  - {f}")
        
        return None
    
    print("✓ File found!")
    
    # ────────────────────────────────────────────────────
    # STEP 1: Load NSL-KDD
    # ────────────────────────────────────────────────────
    
    print(f"\n[1/3] Loading NSL-KDD...")
    
    try:
        df = pd.read_csv(NSLKDD_PATH, names=COLUMN_NAMES)
        print(f"  ✓ Successfully loaded {len(df):,} records")
    except Exception as e:
        print(f"  ❌ Error loading file: {e}")
        return None
    
    # Show what attack types we have
    print(f"\n  Attack types found:")
    attack_counts = df['label'].value_counts()
    
    # Show top 5
    for i, (label, count) in enumerate(attack_counts.head(5).items()):
        print(f"    {label:15s}: {count:,} records")
    
    total_types = len(attack_counts)
    if total_types > 5:
        print(f"    ... and {total_types - 5} more types")
    
    print(f"\n  Total attack types: {total_types}")
    
    # ────────────────────────────────────────────────────
    # STEP 2: Convert to conn.log format
    # ────────────────────────────────────────────────────
    
    print(f"\n[2/3] Converting to conn.log format...")
    print("  (This makes it compatible with your Phase 1 code)")
    
    try:
        # Create synthetic IPs (NSL-KDD doesn't have real IPs)
        num_records = len(df)
        
        conn_log = pd.DataFrame({
            # Timestamps (sequential)
            'ts': np.arange(num_records),
            
            # IP addresses (synthetic)
            'id.orig_h': '192.168.1.' + (np.arange(num_records) % 254 + 1).astype(str),
            'id.resp_h': '10.0.0.' + (np.arange(num_records) % 254 + 1).astype(str),
            
            # Ports
            'id.orig_p': np.random.randint(1024, 65535, num_records),
            'id.resp_p': df['service'].map({
                'http': 80, 
                'ftp': 21, 
                'smtp': 25, 
                'ssh': 22, 
                'telnet': 23,
                'domain': 53,
                'ftp_data': 20,
                'pop_3': 110
            }).fillna(0).astype(int),
            
            # Protocol
            'proto': df['protocol_type'],
            
            # Duration
            'duration': df['duration'],
            
            # Bytes
            'orig_bytes': df['src_bytes'],
            'resp_bytes': df['dst_bytes'],
            
            # Connection state
            'conn_state': df['flag'],
            
            # ← MOST IMPORTANT: Keep the attack labels!
            'label': df['label'].str.strip()
        })
        
        print(f"  ✓ Successfully converted {len(conn_log):,} connections")
        
    except Exception as e:
        print(f"  ❌ Error during conversion: {e}")
        return None
    
    # ────────────────────────────────────────────────────
    # STEP 3: Save converted file
    # ────────────────────────────────────────────────────
    
    print(f"\n[3/3] Saving converted file...")
    
    try:
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        
        # Save
        conn_log.to_csv(OUTPUT_PATH, index=False)
        
        print(f"  ✓ Saved to: {OUTPUT_PATH}")
        
    except Exception as e:
        print(f"  ❌ Error saving file: {e}")
        return None
    
    # ────────────────────────────────────────────────────
    # Success!
    # ────────────────────────────────────────────────────
    
    print("\n" + "="*60)
    print("✅ STEP 1 COMPLETE!")
    print("="*60)
    
    print(f"\nOutput file created:")
    print(f"  Location: {OUTPUT_PATH}")
    print(f"  Records: {len(conn_log):,}")
    print(f"  Attack types: {conn_log['label'].nunique()}")
    print(f"  Has labels: YES ✓")
    
    print("\n" + "="*60)
    print("NEXT STEP:")
    print("="*60)
    print("Run Step 2 to train the model!")
    print("(I'll give you that code next)")
    
    return conn_log


# ============================================================
# RUN THE CONVERSION
# ============================================================

if __name__ == "__main__":
    try:
        result = prepare_nslkdd()
        
        if result is not None:
            print("\n✓ Ready to proceed to training!")
        else:
            print("\n✗ Please fix the errors above and try again")
            
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("\nPlease share this error message for help")