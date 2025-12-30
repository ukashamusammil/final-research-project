"""
Manual Input Demo - Interactive Alert Prioritization
Enter device details manually and see real-time priority prediction
"""

import pandas as pd
import numpy as np
import pickle
import os

def load_system():
    """Load trained model and encoders"""
    print("🔄 Loading Alert Prioritization System...")
    
    try:
        with open('../../models/alert_prioritization_model.pkl', 'rb') as f:
            model = pickle.load(f)
        
        with open('../../models/label_encoders.pkl', 'rb') as f:
            encoders = pickle.load(f)
        
        print("✅ System loaded successfully!\n")
        return model, encoders
    except FileNotFoundError:
        print("❌ Error: Model files not found!")
        print("Please run 03_train_prioritization_model.py first")
        exit(1)


def display_options(title, options):
    """Display numbered options for user selection"""
    print(f"\n{title}")
    print("=" * 70)
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    print("=" * 70)


def get_user_choice(prompt, max_value):
    """Get valid numeric choice from user"""
    while True:
        try:
            choice = int(input(prompt))
            if 1 <= choice <= max_value:
                return choice - 1  # Convert to 0-based index
            else:
                print(f"❌ Please enter a number between 1 and {max_value}")
        except ValueError:
            print("❌ Please enter a valid number")


def collect_device_info(encoders):
    """Collect device information from user"""
    
    print("\n" + "="*70)
    print("📱 DEVICE INFORMATION")
    print("="*70)
    
    # Device Type
    device_types = encoders['device_type'].classes_.tolist()
    display_options("Select Device Type:", device_types)
    device_type_idx = get_user_choice("Enter choice (1-4): ", len(device_types))
    device_type = device_types[device_type_idx]
    
    # Sensor Type
    sensor_types = encoders['sensor_type'].classes_.tolist()
    display_options("Select Sensor Type:", sensor_types)
    sensor_type_idx = get_user_choice(f"Enter choice (1-{len(sensor_types)}): ", len(sensor_types))
    sensor_type = sensor_types[sensor_type_idx]
    
    # Ward
    wards = encoders['ward'].classes_.tolist()
    display_options("Select Hospital Ward:", wards)
    ward_idx = get_user_choice(f"Enter choice (1-{len(wards)}): ", len(wards))
    ward = wards[ward_idx]
    
    # Protocol
    protocols = encoders['protocol'].classes_.tolist()
    display_options("Select Communication Protocol:", protocols)
    protocol_idx = get_user_choice(f"Enter choice (1-{len(protocols)}): ", len(protocols))
    protocol = protocols[protocol_idx]
    
    # Criticality Tier
    print("\n" + "="*70)
    print("Device Criticality (1-10 scale):")
    print("  10 = Life support (ICU ventilator, defibrillator)")
    print("  7-9 = Critical monitoring (ICU ECG, patient monitors)")
    print("  4-6 = Standard care (temperature sensors, fall detectors)")
    print("  1-3 = Non-critical (printers, workstations)")
    print("="*70)
    
    while True:
        try:
            criticality = int(input("Enter criticality (1-10): "))
            if 1 <= criticality <= 10:
                break
            print("❌ Please enter a number between 1 and 10")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Life Support
    print("\n" + "="*70)
    life_support_input = input("Is this a life support device? (yes/no): ").strip().lower()
    life_support = 1 if life_support_input in ['yes', 'y'] else 0
    
    # Determine if critical device
    is_critical_device = 1 if criticality >= 8 else 0
    is_icu = 1 if ward == "ICU" else 0
    
    return {
        'device_type': device_type,
        'device_type_encoded': device_type_idx,
        'sensor_type': sensor_type,
        'sensor_type_encoded': sensor_type_idx,
        'ward': ward,
        'ward_encoded': ward_idx,
        'protocol': protocol,
        'protocol_encoded': protocol_idx,
        'criticality_tier': criticality,
        'life_support_int': life_support,
        'is_critical_device': is_critical_device,
        'is_icu': is_icu
    }


def collect_attack_info(encoders):
    """Collect attack information from user"""
    
    print("\n" + "="*70)
    print("🚨 ATTACK INFORMATION")
    print("="*70)
    
    # Attack Type
    attack_types = [
        "normal (No attack)",
        "mqtt_injection (False sensor data)",
        "ddos (Denial of Service)",
        "ble_spoofing (Bluetooth spoofing)",
        "firmware_exploit (Device compromise)",
        "wifi_deauth (WiFi disconnection)",
        "mitm_ssl_strip (Man-in-the-middle)",
        "replay_attack (Old data replay)",
        "buffer_overflow (Memory exploit)"
    ]
    
    display_options("Select Attack Type:", attack_types)
    attack_idx = get_user_choice(f"Enter choice (1-{len(attack_types)}): ", len(attack_types))
    
    # Attack severity based on type
    attack_severities = [0, 35, 40, 30, 45, 25, 38, 28, 42]
    attack_severity = attack_severities[attack_idx]
    is_attack = 1 if attack_idx > 0 else 0
    
    # Network characteristics
    print("\n" + "="*70)
    print("📊 NETWORK CHARACTERISTICS")
    print("="*70)
    
    if is_attack:
        print("\nFor attack traffic, typical values:")
        print("  Packet size: 500-2000 bytes (higher for attacks)")
        print("  Packet rate: 100-2000 packets/min (much higher for DDoS)")
        print("  Failed connections: 10-200 (attacks cause failures)")
    else:
        print("\nFor normal traffic, typical values:")
        print("  Packet size: 128-512 bytes")
        print("  Packet rate: 10-50 packets/min")
        print("  Failed connections: 0-5")
    
    while True:
        try:
            packet_size = int(input("\nEnter packet size (bytes, 64-4096): "))
            if 64 <= packet_size <= 4096:
                break
            print("❌ Please enter a value between 64 and 4096")
        except ValueError:
            print("❌ Please enter a valid number")
    
    while True:
        try:
            packet_rate = int(input("Enter packet rate (packets/min, 1-5000): "))
            if 1 <= packet_rate <= 5000:
                break
            print("❌ Please enter a value between 1 and 5000")
        except ValueError:
            print("❌ Please enter a valid number")
    
    while True:
        try:
            failed_connections = int(input("Enter failed connections (0-200): "))
            if 0 <= failed_connections <= 200:
                break
            print("❌ Please enter a value between 0 and 200")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Calculate derived values
    packets_per_sec = round(packet_rate / 60, 2)
    bytes_sent = packet_size * packet_rate
    unique_ports = 1 if not is_attack else (50 if 'scan' in attack_types[attack_idx] else 2)
    
    # Anomaly scores
    print("\n" + "="*70)
    print("Anomaly Scores (0.0 to 1.0):")
    print("  Normal traffic: 0.0 - 0.2")
    print("  Suspicious: 0.2 - 0.5")
    print("  Likely attack: 0.5 - 1.0")
    print("="*70)
    
    while True:
        try:
            network_anomaly = float(input("\nNetwork anomaly score (0.0-1.0): "))
            if 0.0 <= network_anomaly <= 1.0:
                break
            print("❌ Please enter a value between 0.0 and 1.0")
        except ValueError:
            print("❌ Please enter a valid number")
    
    while True:
        try:
            behavioral_anomaly = float(input("Behavioral anomaly score (0.0-1.0): "))
            if 0.0 <= behavioral_anomaly <= 1.0:
                break
            print("❌ Please enter a value between 0.0 and 1.0")
        except ValueError:
            print("❌ Please enter a valid number")
    
    while True:
        try:
            time_anomaly = float(input("Time anomaly score (0.0-1.0): "))
            if 0.0 <= time_anomaly <= 1.0:
                break
            print("❌ Please enter a value between 0.0 and 1.0")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Time information
    print("\n" + "="*70)
    while True:
        try:
            hour_of_day = int(input("Enter hour of day (0-23): "))
            if 0 <= hour_of_day <= 23:
                break
            print("❌ Please enter a value between 0 and 23")
        except ValueError:
            print("❌ Please enter a valid number")
    
    is_night = 1 if hour_of_day < 6 or hour_of_day > 22 else 0
    
    while True:
        try:
            day_of_week = int(input("Enter day of week (0=Mon, 6=Sun): "))
            if 0 <= day_of_week <= 6:
                break
            print("❌ Please enter a value between 0 and 6")
        except ValueError:
            print("❌ Please enter a valid number")
    
    is_weekend = 1 if day_of_week >= 5 else 0
    
    return {
        'attack_type': attack_types[attack_idx].split(' ')[0],
        'attack_severity': attack_severity,
        'is_attack': is_attack,
        'packet_size': packet_size,
        'packet_rate': packet_rate,
        'packets_per_sec': packets_per_sec,
        'unique_ports': unique_ports,
        'failed_connections': failed_connections,
        'bytes_sent': bytes_sent,
        'network_anomaly_score': network_anomaly,
        'behavioral_anomaly_score': behavioral_anomaly,
        'time_anomaly_score': time_anomaly,
        'hour_of_day': hour_of_day,
        'day_of_week': day_of_week,
        'is_night': is_night,
        'is_weekend': is_weekend
    }


def make_prediction(model, features):
    """Make priority prediction"""
    
    # Create feature vector (23 features in correct order)
    feature_vector = pd.DataFrame([{
        'criticality_tier': features['criticality_tier'],
        'life_support_int': features['life_support_int'],
        'device_type_encoded': features['device_type_encoded'],
        'sensor_type_encoded': features['sensor_type_encoded'],
        'ward_encoded': features['ward_encoded'],
        'protocol_encoded': features['protocol_encoded'],
        'packet_size': features['packet_size'],
        'packet_rate': features['packet_rate'],
        'packets_per_sec': features['packets_per_sec'],
        'unique_ports': features['unique_ports'],
        'failed_connections': features['failed_connections'],
        'bytes_sent': features['bytes_sent'],
        'attack_severity': features['attack_severity'],
        'hour_of_day': features['hour_of_day'],
        'day_of_week': features['day_of_week'],
        'is_night': features['is_night'],
        'is_weekend': features['is_weekend'],
        'network_anomaly_score': features['network_anomaly_score'],
        'behavioral_anomaly_score': features['behavioral_anomaly_score'],
        'time_anomaly_score': features['time_anomaly_score'],
        'is_attack': features['is_attack'],
        'is_critical_device': features['is_critical_device'],
        'is_icu': features['is_icu']
    }])
    
    # Predict
    priority = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]
    confidence = max(probabilities) * 100
    
    # Get probability for each class
    classes = model.classes_
    prob_dict = dict(zip(classes, probabilities))
    
    return priority, confidence, prob_dict


def display_prediction(device_info, attack_info, priority, confidence, prob_dict):
    """Display prediction results in a nice format"""
    
    # Color codes
    colors = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m',       # Green
        'INFO': '\033[90m'       # Gray
    }
    reset = '\033[0m'
    bold = '\033[1m'
    
    color = colors.get(priority, reset)
    
    # Symbols
    symbols = {
        'CRITICAL': '🚨🚨🚨',
        'HIGH': '⚠️⚠️',
        'MEDIUM': '⚠️',
        'LOW': 'ℹ️',
        'INFO': '📌'
    }
    
    print("\n\n")
    print(color + "="*75 + reset)
    print(f"{bold}{symbols.get(priority, '')} PRIORITY PREDICTION RESULT {symbols.get(priority, '')}{reset}")
    print(color + "="*75 + reset)
    
    # Device Summary
    print(f"\n{bold}📱 DEVICE:{reset}")
    print(f"   Type:          {device_info['device_type']}")
    print(f"   Sensor:        {device_info['sensor_type']}")
    print(f"   Location:      {device_info['ward']}")
    print(f"   Protocol:      {device_info['protocol']}")
    print(f"   Criticality:   {device_info['criticality_tier']}/10", end='')
    if device_info['criticality_tier'] >= 8:
        print(f" {color}(HIGH CRITICALITY){reset}")
    else:
        print()
    
    if device_info['life_support_int'] == 1:
        print(f"   {color}{bold}⚕️  LIFE SUPPORT DEVICE ⚕️{reset}")
    
    # Attack Summary
    print(f"\n{bold}🚨 THREAT:{reset}")
    print(f"   Attack Type:   {attack_info['attack_type']}")
    print(f"   Severity:      {attack_info['attack_severity']}/45")
    print(f"   Packet Rate:   {attack_info['packet_rate']} packets/min")
    print(f"   Failed Conns:  {attack_info['failed_connections']}")
    
    # Prediction
    print(f"\n{bold}🎯 PREDICTION:{reset}")
    print(f"   {color}{bold}Priority:       {priority}{reset}")
    print(f"   Confidence:    {confidence:.1f}%")
    
    # Probability distribution
    print(f"\n{bold}📊 PROBABILITY DISTRIBUTION:{reset}")
    for cls in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if cls in prob_dict:
            prob = prob_dict[cls] * 100
            bar_length = int(prob / 2)
            bar = '█' * bar_length
            print(f"   {cls:10} : {prob:5.2f}% {bar}")
    
    # Recommended Action
    print(f"\n{bold}💡 RECOMMENDED ACTION:{reset}")
    if priority == 'CRITICAL':
        print(f"   {color}• IMMEDIATE isolation of device{reset}")
        print(f"   {color}• Alert security team AND clinical staff{reset}")
        print(f"   {color}• Initiate emergency response protocol{reset}")
        print(f"   {color}• Monitor patient vitals manually{reset}")
    elif priority == 'HIGH':
        print(f"   {color}• Priority investigation required{reset}")
        print(f"   {color}• Notify Security Operations Center{reset}")
        print(f"   {color}• Prepare for device isolation if needed{reset}")
    elif priority == 'MEDIUM':
        print(f"   • Investigate within 30 minutes")
        print(f"   • Log incident for security review")
        print(f"   • Monitor device closely")
    elif priority == 'LOW':
        print(f"   • Standard monitoring protocol")
        print(f"   • Schedule review during business hours")
        print(f"   • Document for trend analysis")
    else:
        print(f"   • Log for information")
        print(f"   • No immediate action required")
        print(f"   • Include in routine security report")
    
    print(f"\n" + color + "="*75 + reset)


def main():
    """Main interactive loop"""
    
    print("="*75)
    print("🏥 IoMT ALERT PRIORITIZATION - MANUAL INPUT DEMO")
    print("="*75)
    print("\nThis demo allows you to manually enter device and attack details")
    print("to see real-time priority predictions from your trained model.\n")
    
    # Load system
    model, encoders = load_system()
    
    while True:
        print("\n" + "="*75)
        print("📝 ENTER ALERT DETAILS")
        print("="*75)
        
        # Collect information
        device_info = collect_device_info(encoders)
        attack_info = collect_attack_info(encoders)
        
        # Combine features
        features = {**device_info, **attack_info}
        
        # Make prediction
        print("\n🔄 Processing alert...")
        priority, confidence, prob_dict = make_prediction(model, features)
        
        # Display result
        display_prediction(device_info, attack_info, priority, confidence, prob_dict)
        
        # Ask if user wants to continue
        print("\n")
        continue_choice = input("Would you like to test another alert? (yes/no): ").strip().lower()
        
        if continue_choice not in ['yes', 'y']:
            print("\n" + "="*75)
            print("✅ Thank you for using the IoMT Alert Prioritization System!")
            print("="*75)
            print("\n📊 Demo completed successfully!")
            print("🎯 Model made accurate predictions based on clinical impact")
            print("🏥 Patient safety prioritized in all decisions\n")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        print("✅ System shut down safely\n")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print("Please ensure all required files are in place\n")