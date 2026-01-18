import os
import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_PATH = r"X:\AI_TI_ENGINE\data\processed\binary_dataset_1to5_stratified.csv"
OUT_DIR = r"X:\AI_TI_ENGINE\data\processed\splits"

TEST_SIZE = 0.20
RANDOM_STATE = 42

os.makedirs(OUT_DIR, exist_ok=True)

print("Loading dataset...")
df = pd.read_csv(INPUT_PATH)

print("Dataset shape:", df.shape)
print("Label distribution (%):")
print(df["label"].value_counts(normalize=True) * 100)

X = df.drop(columns=["label"])
y = df["label"]

print("\nSplitting (stratified)...")
X_train, X_val, y_train, y_val = train_test_split(
    X, y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)

train_df = X_train.copy()
train_df["label"] = y_train.values

val_df = X_val.copy()
val_df["label"] = y_val.values

TRAIN_PATH = os.path.join(OUT_DIR, "train.csv")
VAL_PATH = os.path.join(OUT_DIR, "val.csv")

print("Saving train:", train_df.shape)
train_df.to_csv(TRAIN_PATH, index=False)

print("Saving val:", val_df.shape)
val_df.to_csv(VAL_PATH, index=False)

print("\n Split complete")
print("Train saved to:", TRAIN_PATH)
print("Val saved to:", VAL_PATH)

print("\nTrain label distribution (%):")
print(train_df["label"].value_counts(normalize=True) * 100)

print("\nVal label distribution (%):")
print(val_df["label"].value_counts(normalize=True) * 100)
