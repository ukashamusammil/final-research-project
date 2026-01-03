"""
Alert Grouping Analysis
Groups related alerts into attack campaigns
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def analyze_alert_grouping():
    """
    Analyze how alerts are grouped into campaigns
    """
    
    print("="*70)
    print("🔗 ALERT GROUPING ANALYSIS")
    print("="*70)
    
    # Load preprocessed data
    print("\n📂 Loading preprocessed data...")
    df = pd.read_csv('../../data/processed/esp32_processed.csv')
    print(f"✅ Loaded {len(df):,} samples")
    
    # Filter only attack traffic
    print("\n🔍 Filtering attack traffic...")
    attack_df = df[df['is_attack'] == 1].copy()
    print(f"✅ Attack samples: {len(attack_df):,}")
    
    # Analyze existing groups
    print("\n📊 Analyzing alert groups...")
    
    # Load group_id from original dataset
    original_df = pd.read_csv('../../data/raw/esp32_iomt_monitoring_dataset.csv')
    attack_df['group_id'] = original_df[original_df['attack_type'] != 'normal']['group_id'].values
    
    # Group statistics
    grouped = attack_df[attack_df['group_id'].notna()]
    
    if len(grouped) > 0:
        n_groups = grouped['group_id'].nunique()
        avg_size = len(grouped) / n_groups
        max_size = grouped.groupby('group_id').size().max()
        min_size = grouped.groupby('group_id').size().min()
        
        print(f"\n✅ Alert Grouping Statistics:")
        print(f"   Total attack alerts: {len(attack_df):,}")
        print(f"   Grouped alerts: {len(grouped):,}")
        print(f"   Number of groups: {n_groups}")
        print(f"   Average group size: {avg_size:.2f} alerts")
        print(f"   Largest group: {max_size} alerts")
        print(f"   Smallest group: {min_size} alerts")
        
        # Alert reduction
        reduction_pct = ((len(attack_df) - n_groups) / len(attack_df)) * 100
        print(f"\n   🎯 Alert Reduction: {reduction_pct:.1f}%")
        print(f"      Security analysts see {n_groups} groups")
        print(f"      instead of {len(attack_df):,} individual alerts!")
        
        # Group by attack type
        print("\n📊 Groups by Attack Type:")
        
        # Load encoder to decode
        import pickle
        with open('../../models/label_encoders.pkl', 'rb') as f:
            encoders = pickle.load(f)
        
        attack_encoder = encoders['attack_type']
        
        # Count by attack type
        attack_type_groups = grouped.groupby('attack_type_encoded').agg({
            'group_id': 'nunique',
            'alert_id': 'count'
        }).rename(columns={'group_id': 'num_groups', 'alert_id': 'num_alerts'})
        
        # Decode attack types
        attack_type_groups.index = attack_encoder.inverse_transform(attack_type_groups.index)
        attack_type_groups['avg_alerts_per_group'] = (
            attack_type_groups['num_alerts'] / attack_type_groups['num_groups']
        )
        
        print(attack_type_groups)
        
        # Visualizations
        print("\n📊 Creating visualizations...")
        os.makedirs('../../results', exist_ok=True)
        
        # Plot 1: Group size distribution
        group_sizes = grouped.groupby('group_id').size()
        
        plt.figure(figsize=(12, 6))
        plt.hist(group_sizes, bins=30, color='steelblue', edgecolor='black')
        plt.axvline(avg_size, color='red', linestyle='--', linewidth=2,
                   label=f'Average: {avg_size:.2f}')
        plt.xlabel('Alerts per Group', fontsize=12)
        plt.ylabel('Number of Groups', fontsize=12)
        plt.title('Distribution of Alert Group Sizes\n', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig('../../results/07_group_size_distribution.png', dpi=300, bbox_inches='tight')
        print("   ✅ Saved: results/07_group_size_distribution.png")
        plt.close()
        
        # Plot 2: Attacks by ward and type
        ward_attack = pd.crosstab(
            attack_df['ward_encoded'], 
            attack_df['attack_type_encoded']
        )
        
        # Decode ward names
        ward_encoder = encoders['ward']
        ward_attack.index = ward_encoder.inverse_transform(ward_attack.index)
        ward_attack.columns = attack_encoder.inverse_transform(ward_attack.columns)
        
        plt.figure(figsize=(14, 8))
        ward_attack.plot(kind='bar', stacked=True, ax=plt.gca())
        plt.title('Attack Distribution by Ward and Type\n', fontsize=14, fontweight='bold')
        plt.xlabel('Ward', fontsize=12)
        plt.ylabel('Number of Alerts', fontsize=12)
        plt.legend(title='Attack Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig('../../results/08_attacks_by_ward_detailed.png', dpi=300, bbox_inches='tight')
        print("   ✅ Saved: results/08_attacks_by_ward_detailed.png")
        plt.close()
        
        # Plot 3: Top 20 largest groups
        top_groups = grouped.groupby('group_id').agg({
            'alert_id': 'count',
            'attack_type_encoded': 'first',
            'ward_encoded': 'first'
        }).sort_values('alert_id', ascending=False).head(20)
        
        # Decode
        top_groups['attack_type'] = attack_encoder.inverse_transform(
            top_groups['attack_type_encoded']
        )
        top_groups['ward'] = ward_encoder.inverse_transform(
            top_groups['ward_encoded']
        )
        
        plt.figure(figsize=(14, 8))
        colors = plt.cm.Set3(range(len(top_groups)))
        bars = plt.barh(range(len(top_groups)), top_groups['alert_id'], color=colors)
        plt.yticks(range(len(top_groups)), 
                  [f"{row['attack_type']}\n({row['ward']})" 
                   for idx, row in top_groups.iterrows()])
        plt.xlabel('Number of Alerts', fontsize=12)
        plt.title('Top 20 Largest Attack Campaigns\n', fontsize=14, fontweight='bold')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig('../../results/09_top_attack_campaigns.png', dpi=300, bbox_inches='tight')
        print("   ✅ Saved: results/09_top_attack_campaigns.png")
        plt.close()
        
        # Save grouping summary
        print("\n📝 Creating grouping summary...")
        with open('../../results/alert_grouping_summary.txt', 'w') as f:
            f.write("ALERT GROUPING ANALYSIS SUMMARY\n")
            f.write("="*70 + "\n\n")
            f.write(f"Total Attack Alerts: {len(attack_df):,}\n")
            f.write(f"Number of Groups: {n_groups}\n")
            f.write(f"Average Group Size: {avg_size:.2f} alerts\n")
            f.write(f"Alert Reduction: {reduction_pct:.1f}%\n\n")
            f.write("Groups by Attack Type:\n")
            f.write(attack_type_groups.to_string())
        
        print("   ✅ Summary saved to: results/alert_grouping_summary.txt")
    
    print("\n" + "="*70)
    print("✅ ALERT GROUPING ANALYSIS COMPLETE!")
    print("="*70)
    print(f"\n📊 Visualizations: 3 new files in results/ folder")
    print(f"📊 Alert reduction achieved: {reduction_pct:.1f}%")


if __name__ == "__main__":
    analyze_alert_grouping()