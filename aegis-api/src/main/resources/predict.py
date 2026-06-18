#!/usr/bin/env python3
import sys, json, os, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
SEVERITY  = {"Normal":"NONE","DoS":"HIGH","Probe":"MEDIUM","R2L":"HIGH","U2R":"CRITICAL"}

# NSL-KDD categorical encodings (sklearn LabelEncoder alphabetical order)
PROTOCOL_MAP = {'icmp': 0, 'tcp': 1, 'udp': 2}
FLAG_MAP = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4,
            'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}
SERVICE_MAP = {
    'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4, 'bgp': 5,
    'courier': 6, 'csnet_ns': 7, 'ctf': 8, 'daytime': 9, 'discard': 10,
    'domain': 11, 'domain_u': 12, 'echo': 13, 'eco_i': 14, 'ecr_i': 15,
    'efs': 16, 'exec': 17, 'finger': 18, 'ftp': 19, 'ftp_data': 20,
    'gopher': 21, 'harvest': 22, 'hostnames': 23, 'http': 24, 'http_2784': 25,
    'http_443': 26, 'http_8001': 27, 'imap4': 28, 'iso_tsap': 29, 'klogin': 30,
    'kshell': 31, 'ldap': 32, 'link': 33, 'login': 34, 'mtp': 35,
    'name': 36, 'netbios_dgm': 37, 'netbios_ns': 38, 'netbios_ssn': 39,
    'netstat': 40, 'nnsp': 41, 'nntp': 42, 'ntp_u': 43, 'other': 44,
    'pm_dump': 45, 'pop_2': 46, 'pop_3': 47, 'printer': 48, 'private': 49,
    'red_i': 50, 'remote_job': 51, 'rje': 52, 'shell': 53, 'smtp': 54,
    'sql_net': 55, 'ssh': 56, 'sunrpc': 57, 'supdup': 58, 'systat': 59,
    'telnet': 60, 'tftp_u': 61, 'tim_i': 62, 'time': 63, 'urh_i': 64,
    'urp_i': 65, 'uucp': 66, 'uucp_path': 67, 'vmnet': 68, 'whois': 69
}

def safe_float(val):
    """Convert to float, encoding categorical strings if needed."""
    val = val.strip()
    try:
        return float(val)
    except ValueError:
        # Try categorical maps
        if val.lower() in PROTOCOL_MAP:
            return float(PROTOCOL_MAP[val.lower()])
        if val in FLAG_MAP:
            return float(FLAG_MAP[val])
        if val in SERVICE_MAP:
            return float(SERVICE_MAP[val])
        if val.lower() in SERVICE_MAP:
            return float(SERVICE_MAP[val.lower()])
        return 0.0

def main():
    try:
        import joblib
        scaler  = joblib.load(os.path.join(MODEL_DIR, "phase2_feature_scaler.pkl"))
        encoder = joblib.load(os.path.join(MODEL_DIR, "phase2_label_encoder.pkl"))
        model   = joblib.load(os.path.join(MODEL_DIR, "phase2_stacking_ensemble.pkl"))

        FEATURE_NAMES = list(scaler.feature_names_in_)

        raw    = sys.argv[1].split(",")
        values = [safe_float(v) for v in raw]

        if len(values) == 6:
            full = np.zeros(41, dtype=float)
            full[0]=values[0]; full[1]=values[1]; full[3]=values[2]
            full[4]=values[3]; full[5]=values[4]; full[22]=values[5]
            full[23]=values[5]; full[28]=1.0; full[31]=255.0
            full[32]=255.0; full[33]=1.0
            values = full.tolist()

        X        = pd.DataFrame([values], columns=FEATURE_NAMES)
        X_scaled = scaler.transform(X)
        proba    = model.predict_proba(X_scaled)[0]
        classes  = list(encoder.classes_)
        idx      = int(np.argmax(proba))
        cls      = classes[idx]
        conf     = float(proba[idx])

        print(json.dumps({
            "threat_class":  cls,
            "severity":      SEVERITY.get(cls, "UNKNOWN"),
            "confidence":    round(conf, 6),
            "probabilities": {c: round(float(p),6) for c,p in zip(classes,proba)},
            "message":       "No threat detected." if cls=="Normal" else f"Threat: {cls} ({conf*100:.1f}%)"
        }))

    except Exception as e:
        print(json.dumps({
            "threat_class":"ERROR","severity":"UNKNOWN",
            "confidence":0.0,"probabilities":{},
            "message": str(e)
        }))

main()
