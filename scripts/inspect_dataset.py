import pandas as pd

# t=inspect file path
CSV_PATH = r"X:\AI_TI_ENGINE\data\raw\WiFi_and_MQTT\attacks\csv\train\Benign_train.pcap.csv"

# Load CSV
df = pd.read_csv(CSV_PATH)

print("\n================ SHAPE ================")
print("Rows, Columns:", df.shape)

print("\n================ COLUMNS ================")
print(df.columns.tolist())

print("\n================ DATA TYPES ================")
print(df.dtypes)
