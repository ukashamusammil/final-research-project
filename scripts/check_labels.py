import pandas as pd

DATASET_PATH = r"X:\AI_TI_ENGINE\data\processed\binary_dataset.csv"

df = pd.read_csv(DATASET_PATH, usecols=["label"])

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nLabel percentages:")
print(df["label"].value_counts(normalize=True) * 100)