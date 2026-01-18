import os
import pandas as pd

RAW_DIR = r"X:\AI_TI_ENGINE\data\raw\WiFi_and_MQTT\attacks\csv\train"
BENIGN_FILE = "Benign_train.pcap.csv"

OUTPUT_PATH = r"X:\AI_TI_ENGINE\data\processed\binary_dataset_1to5_stratified.csv"

# Keep scope aligned to your devices/protocols
KEYWORDS = ["MQTT", "TCP", "UDP", "ICMP", "ARP", "Recon"]

# Downsampling target: Attack = RATIO * Benign
RATIO = 5
RANDOM_STATE = 42

# Ensure each attack file contributes at least this many rows (keeps diversity)
MIN_PER_ATTACK_FILE = 5000


def list_attack_files():
    files = []
    for f in os.listdir(RAW_DIR):
        if f == BENIGN_FILE:
            continue
        if f.endswith(".csv") and any(k in f for k in KEYWORDS):
            files.append(f)
    return sorted(files)


def count_rows_fast(csv_path, chunksize=200_000):
    # Count rows without loading whole file into memory
    total = 0
    for chunk in pd.read_csv(csv_path, chunksize=chunksize):
        total += len(chunk)
    return total


def main():
    benign_path = os.path.join(RAW_DIR, BENIGN_FILE)
    if not os.path.exists(benign_path):
        raise FileNotFoundError(f"Benign file not found: {benign_path}")

    attack_files = list_attack_files()
    if not attack_files:
        raise RuntimeError("No attack CSV files matched your KEYWORDS in the folder.")

    print("Attack files selected (scoped):")
    for f in attack_files:
        print(" -", f)

    # --- Load benign fully ---
    df_benign = pd.read_csv(benign_path)
    df_benign["label"] = 0
    benign_count = len(df_benign)
    attack_target_total = benign_count * RATIO

    print("\nBenign rows:", benign_count)
    print("Target attack rows:", attack_target_total, f"(ratio 1:{RATIO})")

    # --- Count attack rows per file (1st pass) ---
    print("\nCounting rows per attack file (this may take a bit)...")
    attack_counts = {}
    total_attack_rows = 0
    for f in attack_files:
        p = os.path.join(RAW_DIR, f)
        c = count_rows_fast(p)
        attack_counts[f] = c
        total_attack_rows += c
        print(f"  {f}: {c}")

    if total_attack_rows == 0:
        raise RuntimeError("Total attack rows counted as 0. Something is wrong with the files.")

    # --- Allocate quotas per file (proportional + minimum) ---
    quotas = {}
    remaining = attack_target_total
    remaining_files = len(attack_files)

    print("\nAllocating per-file sampling quotas...")
    for i, f in enumerate(attack_files):
        file_rows = attack_counts[f]

        # proportional allocation
        q = round(attack_target_total * (file_rows / total_attack_rows))

        # enforce minimum contribution (as long as file has enough rows)
        q = min(file_rows, max(MIN_PER_ATTACK_FILE, q))

        # avoid overshooting remaining in the last steps
        remaining_files = len(attack_files) - i
        q = min(q, remaining - (remaining_files - 1) * 0)  # allow last file to absorb rounding

        quotas[f] = q
        remaining -= q
        print(f"  {f}: quota={q} (file_rows={file_rows})")

    # Fix rounding drift: if we undershot/overshot, adjust the largest file
    current_total = sum(quotas.values())
    diff = attack_target_total - current_total
    if diff != 0:
        largest_file = max(quotas, key=lambda k: attack_counts[k])
        new_q = quotas[largest_file] + diff
        new_q = max(0, min(new_q, attack_counts[largest_file]))
        print(f"\nAdjusting for rounding drift: diff={diff}")
        print(f"  Adjusting {largest_file}: {quotas[largest_file]} -> {new_q}")
        quotas[largest_file] = new_q

    print("\nFinal quota total:", sum(quotas.values()), "(should be close to target)", attack_target_total)

    # --- Write output (benign first, then sampled attacks) ---
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    # Write benign with header
    df_benign.to_csv(OUTPUT_PATH, index=False, mode="w")
    print("\nWrote benign to:", OUTPUT_PATH)

    # Append sampled attacks (2nd pass)
    for f in attack_files:
        p = os.path.join(RAW_DIR, f)
        q = quotas[f]
        if q <= 0:
            continue

        df_attack = pd.read_csv(p)
        df_attack["label"] = 1

        if q < len(df_attack):
            df_attack = df_attack.sample(n=q, random_state=RANDOM_STATE)
        # else: keep all rows if file is smaller than quota

        df_attack.to_csv(OUTPUT_PATH, index=False, mode="a", header=False)
        print(f"Appended {len(df_attack)} rows from {f}")

    print("\n✅ Stratified downsampling complete.")
    print("Saved to:", OUTPUT_PATH)
    print("Next: we will do stratified train/val split on this file.")


if __name__ == "__main__":
    main()
