import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

#paths..
PURE_BENIGN_PATH = r"X:\AI_TI_ENGINE\data\raw\WiFi_and_MQTT\attacks\csv\train\Benign_train.pcap.csv"
VAL_PATH         = r"X:\AI_TI_ENGINE\data\processed\splits\val.csv"

OUT_DIR   = r"X:\AI_TI_ENGINE\data\processed\anomaly"
OUT_PATH  = os.path.join(OUT_DIR, "val_with_anomaly_scores.csv")

MODEL_PATH = r"X:\AI_TI_ENGINE\models\isolation_forest_model.pkl"

os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# =========================
# SETTINGS
# =========================
RANDOM_STATE = 42
N_JOBS = 4

# If RAM is tight, reduce this to 0.5 or 0.3
BENIGN_FRAC = 1.0

print("Loading PURE benign CSV ...")
df_benign = pd.read_csv(PURE_BENIGN_PATH)
print("Pure benign shape:", df_benign.shape)

# If benign file is huge, sample it
if BENIGN_FRAC < 1.0:
    df_benign = df_benign.sample(frac=BENIGN_FRAC, random_state=RANDOM_STATE)
    print(f"Using {int(BENIGN_FRAC*100)}% benign sample:", df_benign.shape)

# If label exists issues exist.. to drop it safely
if "label" in df_benign.columns:
    df_benign = df_benign.drop(columns=["label"])

# Convert to float32 to reduce memory usage
X_benign = df_benign.astype(np.float32)

print("\nTraining Isolation Forest on PURE benign traffic...")
iso = IsolationForest(
    n_estimators=200,
    max_samples="auto",
    contamination="auto",
    random_state=RANDOM_STATE,
    n_jobs=N_JOBS
)

iso.fit(X_benign)

joblib.dump(iso, MODEL_PATH)
print("✅ Isolation Forest model saved to:", MODEL_PATH)

# =========================
# SCORE VAL.CSV
# =========================
print("\nLoading val.csv ...")
df_val = pd.read_csv(VAL_PATH)
print("Val shape:", df_val.shape)

# Features (must match benign columns)
X_val = df_val.drop(columns=["label"]).astype(np.float32)

# decision_function: higher = more normal, lower = more anomalous
raw_score = iso.decision_function(X_val)

# Convert to anomaly direction (higher = more anomalous)
anomaly_raw = -raw_score

# Normalize anomaly score to 0..1 for AICE/SIEM usage
min_v = anomaly_raw.min()
max_v = anomaly_raw.max()
anomaly_score = (anomaly_raw - min_v) / (max_v - min_v + 1e-12)

# Threshold-based IF label: -1 anomaly, 1 normal
if_pred = iso.predict(X_val)

# Attach outputs
df_out = df_val.copy()
df_out["if_raw_score"] = raw_score
df_out["anomaly_score"] = anomaly_score
df_out["if_pred"] = if_pred

df_out.to_csv(OUT_PATH, index=False)

print("\n Scoring complete.")
print("Saved:", OUT_PATH)
print("Anomaly score range:", float(df_out["anomaly_score"].min()), "to", float(df_out["anomaly_score"].max()))
print("IF predicted anomalies count:", int((df_out["if_pred"] == -1).sum()))
