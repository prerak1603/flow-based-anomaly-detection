#!/usr/bin/env python3
import sys, json, os, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
SEVERITY  = {"Normal":"NONE","DoS":"HIGH","Probe":"MEDIUM","R2L":"HIGH","U2R":"CRITICAL"}

def main():
    try:
        import joblib
        scaler  = joblib.load(os.path.join(MODEL_DIR, "phase2_feature_scaler.pkl"))
        encoder = joblib.load(os.path.join(MODEL_DIR, "phase2_label_encoder.pkl"))
        model   = joblib.load(os.path.join(MODEL_DIR, "phase2_stacking_ensemble.pkl"))

        FEATURE_NAMES = list(scaler.feature_names_in_)

        raw    = sys.argv[1].split(",")
        values = [float(v.strip()) for v in raw]

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
