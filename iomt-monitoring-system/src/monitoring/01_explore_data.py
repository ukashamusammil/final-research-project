"""
Script 01: Data Exploration
Understand the ESP32 IoMT dataset structure
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Create results directory if it doesn't exist
os.makedirs('../../results', exist_ok=True)

print("="*75)
print("ESP32 IoMT DATASET EXPLORATION")
print("="*75)

# Load dataset
print("\n Loading dataset...")
df = pd.read_csv('../../data/raw/esp32_iomt_dataset_realistic.csv')

print(f"   Dataset loaded!")
print(f"   Shape: {df.shape}")
print(f"   Rows: {len(df):,}")
print(f"   Columns: {len(df.columns)}")

# Display first few rows
print("\n First 5 rows:")
print(df.head())

# Column names
print("\n All Columns:")
for i, col in enumerate(df.columns, 1):
    print(f"   {i:2d}. {col}")

# Basic statistics
print("\n Priority Label Distribution:")
priority_counts = df['priority_label'].value_counts()
for priority, count in priority_counts.items():
    pct = count / len(df) * 100
    print(f"   {priority:10} : {count:6,} ({pct:5.2f}%)")

print("\n Device Type Distribution:")
device_counts = df['device_type'].value_counts()
for device, count in device_counts.head(10).items():
    pct = count / len(df) * 100
    print(f"   {device:30} : {count:6,} ({pct:5.2f}%)")

print("\n Attack Type Distribution:")
attack_counts = df['attack_type'].value_counts()
for attack, count in attack_counts.items():
    pct = count / len(df) * 100
    print(f"   {attack:20} : {count:6,} ({pct:5.2f}%)")

print("\n Ward Distribution:")
ward_counts = df['ward'].value_counts()
for ward, count in ward_counts.items():
    pct = count / len(df) * 100
    print(f"   {ward:20} : {count:6,} ({pct:5.2f}%)")

# Visualizations
print("\n Creating visualizations...")

# 1. Priority distribution
plt.figure(figsize=(10, 6))
priority_counts.plot(kind='bar', color=['red', 'orange', 'blue', 'green', 'gray'])
plt.title('Priority Label Distribution', fontsize=14, fontweight='bold')
plt.xlabel('Priority Level')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('../../results/01_priority_distribution.png', dpi=300)
print("   Saved: results/01_priority_distribution.png")

# 2. Device type distribution
plt.figure(figsize=(12, 6))
device_counts.head(10).plot(kind='barh', color='skyblue')
plt.title('Top 10 Device Types', fontsize=14, fontweight='bold')
plt.xlabel('Count')
plt.ylabel('Device Type')
plt.tight_layout()
plt.savefig('../../results/02_device_distribution.png', dpi=300)
print("   Saved: results/02_device_distribution.png")

# 3. Attack type distribution
plt.figure(figsize=(10, 6))
attack_counts.plot(kind='bar', color='coral')
plt.title('Attack Type Distribution', fontsize=14, fontweight='bold')
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('../../results/03_attack_distribution.png', dpi=300)
print("   Saved: results/03_attack_distribution.png")

# Missing values check
print("\n Missing Values:")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("   No missing values found!")
else:
    print(missing[missing > 0])

# Data types
print("\n Data Types:")
print(df.dtypes)

print("\n" + "="*75)
print(" EXPLORATION COMPLETE!")
print("="*75)
print("\n Check the 'results' folder for visualizations!")
print(" Dataset is ready for preprocessing!\n")