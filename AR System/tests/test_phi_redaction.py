import json
import os
import sys
import re

# Add src to path to import PHI Redactor
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src', 'core'))
from modules.redaction import PHIRedactor

def test_phi_accuracy():
    print("🏥 STARTING PHI REDACTION ACCURACY TEST")
    print("=======================================")
    
    # 1. Load Data
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'optimized_phi_logs.json')
    
    try:
        with open(data_path, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Error: File not found at {data_path}")
        return

    print(f"📂 Loaded {len(logs)} log entries.")
    
    # 2. Limit to test set (e.g., first 1000 or random)
    test_set = logs[:1000] # Speed up test
    
    tp = 0 # True Positive (PHI Correctly Found)
    tn = 0 # True Negative (Safe logs correctly ignored)
    fp = 0 # False Positive (Redacted safe info)
    fn = 0 # False Negative (Missed PHI leak!)
    
    phi_engine = PHIRedactor()
    
    print("🧪 Processing...")
    
    for entry in test_set:
        raw_msg = entry['raw_log_message']
        ground_truth_has_phi = entry['phi_present']
        
        # Run Detection
        detected_phi = phi_engine.has_regex_phi(raw_msg)
        
        if detected_phi and ground_truth_has_phi:
            tp += 1
        elif not detected_phi and not ground_truth_has_phi:
            tn += 1
        elif detected_phi and not ground_truth_has_phi:
            fp += 1
            # print(f"  False Positive: {raw_msg}")
        elif not detected_phi and ground_truth_has_phi:
            fn += 1
            # print(f"  ⚠️ Missed PHI: {raw_msg}")

    # 3. Stats
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total * 100
    precision = tp / (tp + fp) * 100 if (tp+fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp+fn) > 0 else 0
    
    print("\n📊 TEST RESULTS (Sample: 1000 logs)")
    print("-----------------------------------")
    print(f"✅ Accuracy:  {accuracy:.2f}%")
    print(f"🎯 Precision: {precision:.2f}%")
    print(f"🔍 Recall:    {recall:.2f}%")
    print("-----------------------------------")
    print(f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
    
    if accuracy > 90:
        print("\n🏆 RESULT: PHI Module is HIGHLY ACCURATE.")
    else:
        print("\n⚠️ RESULT: PHI Module needs tuning.")

if __name__ == "__main__":
    test_phi_accuracy()
