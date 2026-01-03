"""
Data Exploration Script
Run this to understand your dataset
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)

def explore_dataset(filepath):
    """Comprehensive dataset exploration"""
    
    print("="*70)
    print("📊 ESP32 IOMT DATASET EXPLORATION")
    print("="*70)
    
    # Load data
    print("\n🔄 Loading dataset...")
    df = pd.read_csv(filepath)
    print(f"✅ Loaded {len(df):,} samples with {len(df.columns)} features")
    
    # Basic info
    print("\n" + "="*70)
    print("📋 BASIC INFORMATION")
    print("="*70)
    print(f"Shape: {df.shape}")
    print(f"\nColumns ({len(df.columns)}):")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i:2d}. {col}")
    
    # Data types
    print("\n" + "="*70)
    print("📝 DATA TYPES")
    print("="*70)
    print(df.dtypes)
    
    # Missing values
    print("\n" + "="*70)
    print("❓ MISSING VALUES")
    print("="*70)
    missing = df.isnull().sum()
    if missing.sum() == 0:
        print("✅ No missing values!")
    else:
        print(missing[missing > 0])
    
    # First 10 rows
    print("\n" + "="*70)
    print("👀 FIRST 10 ROWS")
    print("="*70)
    print(df.head(10))
    
    # Statistical summary
    print("\n" + "="*70)
    print("📈 STATISTICAL SUMMARY")
    print("="*70)
    print(df.describe())
    
    # Device distribution
    print("\n" + "="*70)
    print("📱 DEVICE TYPE DISTRIBUTION")
    print("="*70)
    device_counts = df['device_type'].value_counts()
    print(device_counts)
    print(f"\nTotal devices: {df['device_id'].nunique()}")
    
    # Sensor distribution
    print("\n" + "="*70)
    print("🔬 SENSOR TYPE DISTRIBUTION")
    print("="*70)
    print(df['sensor_type'].value_counts())
    
    # Protocol distribution
    print("\n" + "="*70)
    print("🌐 PROTOCOL DISTRIBUTION")
    print("="*70)
    protocol_counts = df['protocol'].value_counts()
    print(protocol_counts)
    for protocol, count in protocol_counts.items():
        pct = count / len(df) * 100
        print(f"  {protocol}: {pct:.1f}%")
    
    # Ward distribution
    print("\n" + "="*70)
    print("🏥 WARD DISTRIBUTION")
    print("="*70)
    print(df['ward'].value_counts())
    
    # Attack distribution
    print("\n" + "="*70)
    print("🚨 ATTACK TYPE DISTRIBUTION")
    print("="*70)
    attack_counts = df['attack_type'].value_counts()
    print(attack_counts)
    
    normal_pct = (df['attack_type'] == 'normal').sum() / len(df) * 100
    attack_pct = (df['attack_type'] != 'normal').sum() / len(df) * 100
    print(f"\nNormal traffic: {normal_pct:.1f}%")
    print(f"Attack traffic: {attack_pct:.1f}%")
    
    # Priority distribution
    print("\n" + "="*70)
    print("🎯 PRIORITY LABEL DISTRIBUTION")
    print("="*70)
    priority_counts = df['priority_label'].value_counts()
    for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if priority in priority_counts.index:
            count = priority_counts[priority]
            pct = count / len(df) * 100
            print(f"  {priority:10} : {count:6,} ({pct:5.2f}%)")
    
    # Criticality distribution
    print("\n" + "="*70)
    print("⚠️  CRITICALITY TIER DISTRIBUTION")
    print("="*70)
    print(df['criticality_tier'].value_counts().sort_index())
    
    # Life support devices
    life_support_count = df['life_support'].sum()
    life_support_pct = life_support_count / len(df) * 100
    print(f"\nLife support devices: {life_support_count:,} ({life_support_pct:.1f}%)")
    
    # Alert grouping stats
    if 'group_id' in df.columns:
        print("\n" + "="*70)
        print("🔗 ALERT GROUPING STATISTICS")
        print("="*70)
        attack_df = df[df['attack_type'] != 'normal']
        grouped = attack_df[attack_df['group_id'].notna()]
        
        if len(grouped) > 0:
            n_groups = grouped['group_id'].nunique()
            avg_size = len(grouped) / n_groups
            print(f"Total attack alerts: {len(attack_df):,}")
            print(f"Grouped alerts: {len(grouped):,}")
            print(f"Number of groups: {n_groups}")
            print(f"Average group size: {avg_size:.2f} alerts")
            print(f"Alert reduction: {((len(attack_df) - n_groups) / len(attack_df) * 100):.1f}%")
    
    # Create visualizations
    create_visualizations(df)
    
    print("\n" + "="*70)
    print("✅ EXPLORATION COMPLETE!")
    print("="*70)
    print("\nCheck the 'results' folder for visualization plots!")
    
    return df


def create_visualizations(df):
    """Create and save visualizations"""
    
    print("\n📊 Creating visualizations...")
    
    # Create results folder if it doesn't exist
    import os
    os.makedirs('../../results', exist_ok=True)
    
    # Figure 1: Device and Attack Distribution
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Device type
    df['device_type'].value_counts().plot(kind='bar', ax=axes[0, 0], color='steelblue')
    axes[0, 0].set_title('Device Type Distribution', fontsize=14, fontweight='bold')
    axes[0, 0].set_xlabel('Device Type')
    axes[0, 0].set_ylabel('Count')
    axes[0, 0].tick_params(axis='x', rotation=45)
    
    # Attack type
    df['attack_type'].value_counts().plot(kind='bar', ax=axes[0, 1], color='coral')
    axes[0, 1].set_title('Attack Type Distribution', fontsize=14, fontweight='bold')
    axes[0, 1].set_xlabel('Attack Type')
    axes[0, 1].set_ylabel('Count')
    axes[0, 1].tick_params(axis='x', rotation=45)
    
    # Priority label
    priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    priority_counts = df['priority_label'].value_counts()[priority_order]
    priority_counts.plot(kind='bar', ax=axes[1, 0], color='seagreen')
    axes[1, 0].set_title('Priority Label Distribution', fontsize=14, fontweight='bold')
    axes[1, 0].set_xlabel('Priority Level')
    axes[1, 0].set_ylabel('Count')
    
    # Ward distribution
    df['ward'].value_counts().plot(kind='bar', ax=axes[1, 1], color='purple')
    axes[1, 1].set_title('Ward Distribution', fontsize=14, fontweight='bold')
    axes[1, 1].set_xlabel('Ward')
    axes[1, 1].set_ylabel('Count')
    axes[1, 1].tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig('../../results/01_data_distribution.png', dpi=300, bbox_inches='tight')
    print("   ✅ Saved: results/01_data_distribution.png")
    plt.close()
    
    # Figure 2: Protocol and Sensor Distribution
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    # Protocol
    df['protocol'].value_counts().plot(kind='pie', ax=axes[0], autopct='%1.1f%%')
    axes[0].set_title('Protocol Distribution', fontsize=14, fontweight='bold')
    axes[0].set_ylabel('')
    
    # Sensor type
    df['sensor_type'].value_counts().plot(kind='barh', ax=axes[1], color='orange')
    axes[1].set_title('Sensor Type Distribution', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Count')
    
    plt.tight_layout()
    plt.savefig('../../results/02_protocol_sensor_distribution.png', dpi=300, bbox_inches='tight')
    print("   ✅ Saved: results/02_protocol_sensor_distribution.png")
    plt.close()
    
    # Figure 3: Attacks by Ward
    attack_df = df[df['attack_type'] != 'normal']
    attack_ward = pd.crosstab(attack_df['ward'], attack_df['attack_type'])
    
    plt.figure(figsize=(14, 8))
    attack_ward.plot(kind='bar', stacked=True, ax=plt.gca())
    plt.title('Attack Distribution by Ward', fontsize=14, fontweight='bold')
    plt.xlabel('Ward')
    plt.ylabel('Number of Attacks')
    plt.legend(title='Attack Type', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('../../results/03_attacks_by_ward.png', dpi=300, bbox_inches='tight')
    print("   ✅ Saved: results/03_attacks_by_ward.png")
    plt.close()
    
    print("\n   📁 All visualizations saved to 'results/' folder")


if __name__ == "__main__":
    # Run exploration
    df = explore_dataset('../../data/raw/esp32_iomt_monitoring_dataset.csv')
    
    # Optionally save summary to file
    with open('../../results/dataset_summary.txt', 'w') as f:
        f.write(f"Dataset Shape: {df.shape}\n")
        f.write(f"Total Samples: {len(df):,}\n")
        f.write(f"Total Features: {len(df.columns)}\n")
        f.write(f"\nColumns: {', '.join(df.columns)}\n")
    
    print("\n💾 Summary saved to: results/dataset_summary.txt")