import os
import numpy as np
import pandas as pd
import joblib

# =========================
# INPUTS
# =========================
INPUT_SCORED_PATH = r"X:\AI_TI_ENGINE\data\processed\anomaly\val_with_anomaly_scores.csv"
RF_MODEL_PATH     = r"X:\AI_TI_ENGINE\models\optimized_random_forest_model.pkl"

# =========================
# OUTPUT
# =========================
OUT_DIR  = r"X:\AI_TI_ENGINE\data\processed\final"
OUT_PATH = os.path.join(OUT_DIR, "aice_event_output.csv")
os.makedirs(OUT_DIR, exist_ok=True)

# =========================
# LOAD DATA
# =========================
print("Loading scored validation file...")
df = pd.read_csv(INPUT_SCORED_PATH)

# Sanity check required columns exist
required_cols = ["label", "anomaly_score", "if_pred"]
for c in required_cols:
    if c not in df.columns:
        raise ValueError(f"Missing required column: {c}")

print("Loaded shape:", df.shape)

# =========================
# PREP FEATURES FOR RF
# =========================
# RF expects original 45 features (all columns excluding label + IF outputs)
drop_cols = ["label", "if_raw_score", "anomaly_score", "if_pred"]
X = df.drop(columns=[c for c in drop_cols if c in df.columns]).astype(np.float32)

print("RF feature shape:", X.shape)

# =========================
# LOAD RF MODEL
# =========================
print("Loading optimized RF model...")
rf = joblib.load(RF_MODEL_PATH)

# =========================
# RF PREDICTION + PROBABILITY
# =========================
print("Generating RF predictions and probabilities...")
rf_pred = rf.predict(X)
rf_prob = rf.predict_proba(X)[:, 1]   # probability of attack class=1

# =========================
# BUILD AICE OUTPUT (selected columns)
# =========================
# AICE needs a compact set of groupable fields + intelligence outputs
aice_cols = [
    "Protocol Type", "TCP", "UDP", "HTTP", "HTTPS", "DNS", "ARP", "ICMP",
    "Duration", "Rate", "Srate", "Drate", "IAT", "Tot size",
    "syn_count", "rst_count", "ack_count"
]

# Keep only columns that actually exist (safe)
keep_context = [c for c in aice_cols if c in df.columns]

df_out = pd.DataFrame()
df_out["event_id"] = [f"val_{i:07d}" for i in range(len(df))]

# Add grouping context
for c in keep_context:
    df_out[c] = df[c]

# Add intelligence outputs (these are the core handoff signals)
df_out["rf_pred"] = rf_pred
df_out["rf_attack_prob"] = rf_prob
df_out["anomaly_score"] = df["anomaly_score"]
df_out["if_pred"] = df["if_pred"]

# (Optional) Keep label for research testing only — remove in real deployment
df_out["label"] = df["label"]

# Save
df_out.to_csv(OUT_PATH, index=False)

print("\n AICE output created successfully!")
print("Saved to:", OUT_PATH)
print("Output shape:", df_out.shape)
print("Columns:", df_out.columns.tolist())
