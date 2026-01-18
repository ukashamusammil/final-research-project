import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import confusion_matrix, classification_report


# =========================
# PATHS
# =========================
TRAIN_PATH = r"X:\AI_TI_ENGINE\data\processed\splits\train.csv"
VAL_PATH   = r"X:\AI_TI_ENGINE\data\processed\splits\val.csv"
MODEL_PATH = r"X:\AI_TI_ENGINE\models\optimized_random_forest_model.pkl"

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# =========================
# SETTINGS
# =========================
N_JOBS = 4
CV_FOLDS = 2
N_ITER = 20
RANDOM_STATE = 42
TUNE_FRAC = 0.50   # reduce to 0.3 if RAM issues


print("Loading train.csv ...")
df_train = pd.read_csv(TRAIN_PATH)

X_train = df_train.drop(columns=["label"]).astype(np.float32)
y_train = df_train["label"]

# Subset for tuning
idx = X_train.sample(frac=TUNE_FRAC, random_state=RANDOM_STATE).index
X_tune = X_train.loc[idx]
y_tune = y_train.loc[idx]

print("Tuning data shape:", X_tune.shape)

# =========================
# PARAMETER SPACE
# =========================
param_dist = {
    "n_estimators": [200, 300, 500, 700],
    "max_depth": [None, 10, 20, 30, 40],
    "min_samples_split": [2, 5, 10, 20],
    "min_samples_leaf": [1, 2, 4, 10],
    "max_features": ["sqrt", "log2", None],
    "bootstrap": [True, False],
    "class_weight": [None, "balanced"]
}

base_model = RandomForestClassifier(
    random_state=RANDOM_STATE,
    n_jobs=1  # CRITICAL FIX
)

search = RandomizedSearchCV(
    estimator=base_model,
    param_distributions=param_dist,
    n_iter=N_ITER,
    cv=CV_FOLDS,
    scoring="f1_weighted",
    verbose=2,
    random_state=RANDOM_STATE,
    n_jobs=N_JOBS
)

print("\nStarting hyperparameter tuning...")
search.fit(X_tune, y_tune)

print("\nBest parameters:", search.best_params_)

# =========================
# FINAL TRAIN ON FULL TRAIN.CSV
# =========================
print("\nTraining final model on full train.csv...")
final_model = RandomForestClassifier(
    **search.best_params_,
    random_state=RANDOM_STATE,
    n_jobs=N_JOBS
)

final_model.fit(X_train, y_train)

joblib.dump(final_model, MODEL_PATH)
print("Saved final model to:", MODEL_PATH)

# =========================
# EVALUATE ON val.csv
# =========================
df_val = pd.read_csv(VAL_PATH)
X_val = df_val.drop(columns=["label"]).astype(np.float32)
y_val = df_val["label"]

y_pred = final_model.predict(X_val)

print("\nConfusion Matrix:")
print(confusion_matrix(y_val, y_pred))

print("\nClassification Report:")
print(classification_report(y_val, y_pred, digits=5))
