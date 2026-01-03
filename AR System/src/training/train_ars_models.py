import json
import pandas as pd
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# Save paths
RESPONSE_MODEL_PATH = "ars_response_model.pkl"
PHI_MODEL_PATH = "ars_phi_model.pkl"

def load_data():
    print("Loading datasets...")
    with open("optimized_threat_triggers.json", "r") as f:
        threat_data = pd.DataFrame(json.load(f))
        
    with open("optimized_phi_logs.json", "r") as f:
        phi_data = pd.DataFrame(json.load(f))
        
    return threat_data, phi_data

def train_response_model(df):
    print("\nXXX TRAINING THREAT RESPONSE MODEL (ISOLATION LOGIC) XXX")
    
    # 1. Prepare Features (X) and Target (y)
    # We chose: Threat Type, Severity, Confidence Score
    X = df[['threat_type', 'severity', 'confidence_score']].copy()
    y = df['action_required']
    
    # 2. Encode Categorical Data (Strings -> Numbers)
    le_threat = LabelEncoder()
    le_severity = LabelEncoder()
    
    X['threat_type'] = le_threat.fit_transform(X['threat_type'])
    X['severity'] = le_severity.fit_transform(X['severity'])
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train Model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # 5. Evaluate
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Response Model Accuracy: {acc*100:.2f}%")
    
    # Define class names for the report
    target_names = ["NO_ACTION", "MONITOR", "ISOLATE", "ROLLBACK"]
    
    # Handle case where some classes might not be in the split (unlikely with 50k rows but good safety)
    unique_labels = sorted(list(set(y_test) | set(preds)))
    present_names = [target_names[i] for i in unique_labels]
    
    print("Classification Report:\n", classification_report(y_test, preds, target_names=present_names))
    
    # 6. Save Model & Encoders (We need encoders for prediction later)
    model_bundle = {
        "model": clf,
        "le_threat": le_threat,
        "le_severity": le_severity
    }
    with open(RESPONSE_MODEL_PATH, "wb") as f:
        pickle.dump(model_bundle, f)
    print(f"Saved Response Model to {RESPONSE_MODEL_PATH}")

def train_phi_detection_model(df):
    print("\nXXX TRAINING PHI DETECTION MODEL (TEXT SCANNER) XXX")
    
    # 1. Prepare Data
    X = df['raw_log_message']
    y = df['phi_present'].astype(int) # Convert True/False to 1/0
    
    # 2. Text Vectorization (Convert text to numbers using TF-IDF)
    # This learns which words (like 'Patient', 'ID', 'High') are important
    vectorizer = TfidfVectorizer(max_features=5000)
    X_vec = vectorizer.fit_transform(X)
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)
    
    # 4. Train Model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # 5. Evaluate
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"PHI Detection Accuracy: {acc*100:.2f}%")
    print("Classification Report:\n", classification_report(y_test, preds))
    
    # 6. Save Model & Vectorizer
    model_bundle = {
        "model": clf,
        "vectorizer": vectorizer
    }
    with open(PHI_MODEL_PATH, "wb") as f:
        pickle.dump(model_bundle, f)
    print(f"Saved PHI Model to {PHI_MODEL_PATH}")

if __name__ == "__main__":
    threat_df, phi_df = load_data()
    
    # Train both
    train_response_model(threat_df)
    train_phi_detection_model(phi_df)
    
    print("\nAll Training Complete. Models are ready for the ARS core.")
