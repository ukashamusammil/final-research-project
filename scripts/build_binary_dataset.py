import pandas as pd
import os

# Folder that contains Benign_train.pcap.csv + attack CSVs
RAW_DIR = r"X:\AI_TI_ENGINE\data\raw\WiFi_and_MQTT\attacks\csv\train"

# Output file
OUTPUT_PATH = r"X:\AI_TI_ENGINE\data\processed\binary_dataset.csv"

dfs = []

# BENIGN (label = 0) 
benign_file = "Benign_train.pcap.csv"
benign_path = os.path.join(RAW_DIR, benign_file)

df_benign = pd.read_csv(benign_path)
df_benign["label"] = 0
dfs.append(df_benign)

print(f"Loaded benign: {df_benign.shape}")

# ATTACKS (label = 1) scoped for my 4 devices
KEYWORDS = ["MQTT", "TCP", "UDP", "ICMP", "ARP", "Recon"]

for file in os.listdir(RAW_DIR):
    if file == benign_file:
        continue

    if file.endswith(".csv") and any(k in file for k in KEYWORDS):
        file_path = os.path.join(RAW_DIR, file)
        df_attack = pd.read_csv(file_path)
        df_attack["label"] = 1
        dfs.append(df_attack)
        print(f"Loaded attack: {file} -> {df_attack.shape}")

# MERGE 
df_final = pd.concat(dfs, ignore_index=True)

# SAVE 
df_final.to_csv(OUTPUT_PATH, index=False)

print("\n Binary dataset created successfully")
print("Final shape:", df_final.shape)
print("Saved to:", OUTPUT_PATH)
print("Columns count:", len(df_final.columns))  # 46 (45 + label)
