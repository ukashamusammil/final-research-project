"""
Data Preprocessing Script
Prepares data for machine learning
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import os

def preprocess_dataset(input_path, output_path):
    """
    Complete preprocessing pipeline
    """
    
    print("="*70)
    print("🔧 DATA PREPROCESSING PIPELINE")
    print("="*70)
    
    # Step 1: Load data
    print("\n📂 Step 1: Loading dataset...")
    df = pd.read_csv(input_path)
    print(f"✅ Loaded {len(df):,} samples")
    
    # Step 2: Check missing values
    print("\n🔍 Step 2: Checking for missing values...")
    missing = df.isnull().sum()
    if missing.sum() == 0:
        print("✅ No missing values!")
    else:
        print(f"⚠️  Found {missing.sum()} missing values")
        # Fill missing numeric values with median
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        print("✅ Missing values filled")
    
    # Step 3: Encode categorical features
    print("\n🔤 Step 3: Encoding categorical features...")
    
    encoders = {}
    categorical_features = ['device_type', 'sensor_type', 'ward', 'protocol', 'attack_type']
    
    for feature in categorical_features:
        if feature in df.columns:
            le = LabelEncoder()
            df[f'{feature}_encoded'] = le.fit_transform(df[feature])
            encoders[feature] = le
            print(f"   ✅ Encoded {feature} ({len(le.classes_)} unique values)")
    
    # Convert boolean to int
    if 'life_support' in df.columns:
        df['life_support_int'] = df['life_support'].astype(int)
        print("   ✅ Converted life_support to integer")
    
    # Step 4: Create additional features
    print("\n⚙️  Step 4: Creating additional features...")
    
    # Binary attack indicator
    df['is_attack'] = (df['attack_type'] != 'normal').astype(int)
    print("   ✅ Created is_attack feature")
    
    # Critical device indicator
    df['is_critical_device'] = (df['criticality_tier'] >= 8).astype(int)
    print("   ✅ Created is_critical_device feature")
    
    # ICU indicator
    df['is_icu'] = (df['ward'] == 'ICU').astype(int)
    print("   ✅ Created is_icu feature")
    
    # Step 5: Select features for ML
    print("\n📊 Step 5: Selecting features for machine learning...")
    
    feature_columns = [
        'criticality_tier',
        'life_support_int',
        'device_type_encoded',
        'sensor_type_encoded',
        'ward_encoded',
        'protocol_encoded',
        'packet_size',
        'packet_rate',
        'packets_per_sec',
        'unique_ports',
        'failed_connections',
        'bytes_sent',
        'attack_severity',
        'hour_of_day',
        'day_of_week',
        'is_night',
        'is_weekend',
        'network_anomaly_score',
        'behavioral_anomaly_score',
        'time_anomaly_score',
        'is_attack',
        'is_critical_device',
        'is_icu'
    ]
    
    # Filter only existing columns
    available_features = [col for col in feature_columns if col in df.columns]
    print(f"   ✅ Selected {len(available_features)} features for training")
    
    # Step 6: Save preprocessed data
    print(f"\n💾 Step 6: Saving preprocessed data...")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"✅ Saved to: {output_path}")
    
    # Step 7: Save encoders
    print("\n🔐 Step 7: Saving label encoders...")
    encoders_path = '../../models/label_encoders.pkl'
    os.makedirs(os.path.dirname(encoders_path), exist_ok=True)
    with open(encoders_path, 'wb') as f:
        pickle.dump(encoders, f)
    print(f"✅ Encoders saved to: {encoders_path}")
    
    # Step 8: Create train-test split
    print("\n✂️  Step 8: Creating train-test split...")
    
    X = df[available_features]
    y = df['priority_label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )
    
    print(f"   ✅ Training samples: {len(X_train):,}")
    print(f"   ✅ Testing samples: {len(X_test):,}")
    
    print("\n   Training set distribution:")
    for priority, count in y_train.value_counts().items():
        pct = count / len(y_train) * 100
        print(f"      {priority:10} : {count:5,} ({pct:5.2f}%)")
    
    # Save splits
    print("\n💾 Step 9: Saving train-test splits...")
    X_train.to_csv('../../data/processed/X_train.csv', index=False)
    X_test.to_csv('../../data/processed/X_test.csv', index=False)
    y_train.to_csv('../../data/processed/y_train.csv', index=False)
    y_test.to_csv('../../data/processed/y_test.csv', index=False)
    print("   ✅ Saved X_train.csv, X_test.csv, y_train.csv, y_test.csv")
    
    print("\n" + "="*70)
    print("✅ PREPROCESSING COMPLETE!")
    print("="*70)
    
    return df, X_train, X_test, y_train, y_test, available_features


if __name__ == "__main__":
    # Run preprocessing
    df, X_train, X_test, y_train, y_test, features = preprocess_dataset(
        input_path='../../data/raw/esp32_iomt_monitoring_dataset.csv',
        output_path='../../data/processed/esp32_processed.csv'
    )
    
    print(f"\n📝 Feature list ({len(features)} features):")
    for i, feat in enumerate(features, 1):
        print(f"   {i:2d}. {feat}")