from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import os
import json
import time
import random
import sys
import functools
import jwt
import datetime

# 1. Initialize App
app = Flask(__name__)
CORS(app)

# 2. Setup Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, 'logs', 'ars_events.json')
sys.path.append(os.path.join(BASE_DIR, 'src'))

# 3. Import Reporting Module
try:
    from core.modules.reporting import ReportGenerator
except ImportError:
    ReportGenerator = None
    print("Warning: Reporting module missing dependencies (pandas/matplotlib). PDF generation disabled.")

# 4. Routes
@app.route('/api/report', methods=['GET'])
def generate_report():
    """Generates and serves the PDF report."""
    if not ReportGenerator:
        return jsonify({"error": "Reporting dependencies missing (pip install pandas fpdf matplotlib seaborn)"}), 500
        
    try:
        reporter = ReportGenerator(log_file=LOG_FILE)
        pdf_path = reporter.generate_daily_report()
        # Serve the generated file
        return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Secret Key for JWT
app.config['SECRET_KEY'] = 'medguard_secret_key_123'

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1] # Bearer <token>
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    """Simple Admin Authentication."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Hardcoded credentials for prototype
    if username == "admin" and password == "medguard123":
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "status": "success", 
            "token": token,
            "role": "admin"
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/devices/add', methods=['POST'])
@token_required
def add_device():
    """Manually add a new device to inventory."""
    data = request.json
    new_device = {
        "id": data.get('id', f"D-{random.randint(200,999)}"),
        "ip": data.get('ip'),
        "type": data.get('type', "Manual Entry"),
        "location": data.get('location', "General Ward"),
        "status": "SAFE",
        "last_seen": "Just Now",
        "risk_score": 0
    }
    
    global DEVICES
    # check duplicates
    if not any(d['ip'] == new_device['ip'] for d in DEVICES):
        DEVICES.append(new_device)
        save_inventory() # Save changes
        return jsonify({"status": "success", "device": new_device})
    return jsonify({"error": "Device already exists"}), 400

@app.route('/api/devices/remove', methods=['POST'])
@token_required
def remove_device():
    """Remove a device from inventory."""
    data = request.json
    ip_to_remove = data.get('ip')
    
    global DEVICES
    DEVICES = [d for d in DEVICES if d['ip'] != ip_to_remove]
    save_inventory() # Save changes
    return jsonify({"status": "success", "message": "Device removed"})

@app.route('/api/privacy', methods=['GET'])
def get_privacy_logs():
    """Returns only Privacy/PHI related events."""
    events = read_logs()
    # Filter for PRIVACY_ALERT (Check original_type if event_type was remapped to INFO)
    privacy_events = [
        e for e in events 
        if e.get('event_type') == 'PRIVACY_ALERT' or e.get('original_type') == 'PRIVACY_ALERT'
    ]
    return jsonify(privacy_events)

@app.route('/api/history', methods=['GET'])
def get_history():
    """Returns full event history for the Incident Log."""
    return jsonify(read_logs())

def read_logs():
    """Reads the JSON log file safely."""
    if not os.path.exists(LOG_FILE):
        return []
    
    events = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        print(f"Error reading logs: {e}")
    return events

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Returns aggregated stats including specific Response Flow counts."""
    events = read_logs()
    
    total_events = len(events)
    # Filter by Decision Types
    quarantined = set()
    rollbacks = set()
    temporary_isolation = set()
    
    for e in events:
        decision = e.get('decision', 'NO_ACTION')
        ip = e.get('src_ip')
        
        if decision == "QUARANTINE":
            quarantined.add(ip)
            if ip in temporary_isolation:
                 temporary_isolation.remove(ip) # Moved to permanent
        elif decision == "ROLLBACK":
            rollbacks.add(ip)
            if ip in temporary_isolation:
                 temporary_isolation.remove(ip) # Restored
            if ip in quarantined:
                 quarantined.remove(ip) # Restored from quarantine (rare but possible manual override logic)
        elif decision == "ISOLATE":
             # Only count as temp if not fully quarantined yet
             if ip not in quarantined and ip not in rollbacks:
                 temporary_isolation.add(ip)

    # Calculate active threats (current danger)
    active_threats = len(quarantined) + len(temporary_isolation)
    
    # Calculate simple uptime
    uptime = "99.9%" if total_events > 0 else "100%"

    return jsonify({
        "total_events": total_events,
        "active_threats": active_threats,
        "system_health": "98%" if active_threats < 2 else "85%",
        "uptime": uptime,
        "recent_alerts": [e for e in events if e.get('event_type') == 'DANGER'][-50:],
        # Specific Counters for User Requirement:
        "metrics": {
            "temp_isolate": len(temporary_isolation),
            "quarantined": len(quarantined),
            "rollbacks": len(rollbacks),
            "phi_attempts": len([e for e in events if e.get('event_type') == 'PRIVACY_ALERT'])
        }
    })

# Persistence File
INVENTORY_FILE = os.path.join(BASE_DIR, 'logs', 'inventory.json')

def load_inventory():
    """Loads device inventory from JSON file."""
    if not os.path.exists(INVENTORY_FILE):
        return [
            {"id": "D-101", "ip": "192.168.1.50", "type": "Patient Monitor", "location": "ICU-Wing-A", "last_seen": "Active"},
            {"id": "D-102", "ip": "192.168.1.99", "type": "Infusion Pump", "location": "ICU-Wing-B", "last_seen": "Active"},
            {"id": "D-103", "ip": "192.168.1.105", "type": "MRI Gateway", "location": "Radiology", "last_seen": "Active"},
            {"id": "D-104", "ip": "192.168.1.200", "type": "Nurse Tablet", "location": "Station-1", "last_seen": "Active"},
        ]
    try:
        with open(INVENTORY_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading inventory: {e}")
        return []

def save_inventory():
    """Saves current global DEVICES to JSON file."""
    try:
        with open(INVENTORY_FILE, 'w') as f:
            json.dump(DEVICES, f, indent=4)
    except Exception as e:
        print(f"Error saving inventory: {e}")

# Global Device Inventory
DEVICES = load_inventory()

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Returns the list of active devices with status synced from AI logs."""
    logs = read_logs()
    
    # Scan logs to determine current state of each IP
    device_states = {}
    for log in logs:
        ip = log.get('src_ip')
        decision = log.get('decision')
        
        # Simple state machine based on log history order
        if decision == "QUARANTINE":
            device_states[ip] = "QUARANTINED"
        elif decision == "ROLLBACK":
            device_states[ip] = "SAFE"
        elif decision == "ISOLATE":
             # If not already quarantined, mark as isolating
             if device_states.get(ip) != "QUARANTINED":
                 device_states[ip] = "ISOLATING"

    # Apply to inventory
    response_devices = []
    
    for d in DEVICES:
        dev = d.copy() 
        ip = dev['ip']
        
        # Sync status from AI logs
        if ip in device_states:
            status = device_states[ip]
            dev['status'] = status
            
            if status == "QUARANTINED":
                dev['risk_score'] = 100
            elif status == "ISOLATING":
                dev['risk_score'] = 80
            elif status == "SAFE":
                dev['risk_score'] = 0
        else:
            # Default state if no AI events
            if 'status' not in dev: # Preserve manual isolate/release status if no AI event overrides it?
                dev['status'] = "SAFE"
                dev['risk_score'] = 0
            
        response_devices.append(dev)

    return jsonify(response_devices)

@app.route('/api/isolate', methods=['POST'])
@token_required
def isolate_device():
    """Handles manual isolation/release commands."""
    from flask import request
    data = request.json
    device_id = data.get('device_id')
    action = data.get('action') # 'ISOLATE' or 'RELEASE'
    
    print(f"⚠️ COMMAND RECEIVED: {action} DEVICE {device_id}")
    
    # Update global mock state
    global DEVICES
    for d in DEVICES:
        if d['id'] == device_id:
            d['status'] = 'ISOLATED' if action == 'ISOLATE' else 'SAFE'
            break
            
    # Save state changes (optional, if we want manual isolation to persist)
    save_inventory()
            
    return jsonify({"status": "success", "message": f"Device {action}D"})

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    """Returns real-time traffic data AND IoMT Model Prediction."""
    
    # 1. Base Traffic Stats
    events = read_logs()
    latest_severity = 0.5
    if events:
         last = events[-1]
         if last.get('event_type') == 'DANGER':
             latest_severity = 0.95
    
    cpu_load = 10 + (random.random() * 40 * latest_severity) + (40 if latest_severity > 0.8 else 0)
    packets = 2000 + (random.random() * 3000 * latest_severity)

    # 2. IoMT Model Inference (Automated)
    iomt_result = {"priority": "MONITORING", "confidence": 0}
    
    if IOMT_MODEL and IOMT_FEATURES is not None:
        try:
            # Simulate features based on current load
            # High load = High Packet Rate = Likely Attack
            sim_packet_rate = packets / 60.0
            sim_attack_sev = 40 if latest_severity > 0.8 else 0
            
            # Construct feature vector (Must match model expectations)
            # Defaulting to 'ESP32_Pulse_Oximeter' generally
            features = {
                'criticality_tier': 8.0, # Contain critical devices
                'life_support': 0,
                'device_type_encoded': 0, # Pulse Oximeter
                'ward_encoded': 0, # ICU
                'protocol_encoded': 0, # MQTT
                'packet_size': 512.0,
                'packet_rate': sim_packet_rate, # Dynamic
                'packets_per_sec': sim_packet_rate / 60.0,
                'unique_ports': 10 if latest_severity > 0.8 else 1,
                'failed_connections': 20 if latest_severity > 0.8 else 0,
                'bytes_sent': 512.0 * sim_packet_rate,
                'bytes_received': 512.0 * sim_packet_rate * 0.5,
                'flow_duration': 30.0,
                'hour_of_day': int(time.strftime("%H")),
                'day_of_week': 0, 
                'is_night': 0,
                'is_weekend': 0,
                'attack_type_encoded': 2 if latest_severity > 0.8 else 0, # 2=DDoS, 0=Normal (approx)
                'attack_severity': sim_attack_sev, # Dynamic
                'network_anomaly_score': latest_severity,
                'behavioral_anomaly_score': latest_severity,
                'time_anomaly_score': 0.0
            }
            
            X = pd.DataFrame([features])[IOMT_FEATURES]
            p_res = IOMT_MODEL.predict(X)[0]
            c_res = max(IOMT_MODEL.predict_proba(X)[0]) * 100
            
            iomt_result = {
                "priority": str(p_res),
                "confidence": round(float(c_res), 1),
                "timestamp": time.strftime("%H:%M:%S")
            }
            
            # Append to history
            IOMT_ALERTS.append(iomt_result)
            if len(IOMT_ALERTS) > 500: # Keep limit
                IOMT_ALERTS.pop(0)

        except Exception as e:
            print(f"Prediction Error: {e}")

    return jsonify({
        "time": time.strftime("%H:%M:%S"),
        "cpu_load": cpu_load,
        "packets": packets,
        "iomt": iomt_result
    })

# -------------------------------------------------------------------------
# IoMT MONITORING SYSTEM INTEGRATION
# -------------------------------------------------------------------------
import pickle
import pandas as pd

# Load Models
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'core', 'models')
try:
    with open(os.path.join(MODEL_PATH, 'alert_prioritization_model.pkl'), 'rb') as f:
        IOMT_MODEL = pickle.load(f)
    with open(os.path.join(MODEL_PATH, 'label_encoders.pkl'), 'rb') as f:
        IOMT_ENCODERS = pickle.load(f)
    with open(os.path.join(MODEL_PATH, 'feature_names.pkl'), 'rb') as f:
        IOMT_FEATURES = pickle.load(f)
    print("✅ IoMT Models Loaded Successfully")
except Exception as e:
    print(f"⚠️ Warning: IoMT Models not found in {MODEL_PATH}. Feature disabled. ({e})")
    IOMT_MODEL = None

# Store history of alerts for the Monitoring Tab
IOMT_ALERTS = []

@app.route('/api/iomt/analyze', methods=['POST'])
@token_required
def analyze_iomt():
    """Analyzes device & traffic data to predict threat priority."""
    if not IOMT_MODEL:
        return jsonify({"error": "AI Model not loaded"}), 503
        
    try:
        data = request.json
        # Extract inputs (Expects pre-processed or raw values)
        # For simplicity, we assume frontend sends raw values and we encode them here
        # or frontend sends encoded values. Let's do encoding here to match demo script.
        
        # 1. Transform Categorical
        # 1. Transform Categorical
        try:
            dev_type = int(IOMT_ENCODERS['device_type'].transform([data.get('device_type')])[0])
            ward = int(IOMT_ENCODERS['ward'].transform([data.get('ward')])[0])
            proto = int(IOMT_ENCODERS['protocol'].transform([data.get('protocol')])[0])
            attack = int(IOMT_ENCODERS['attack_type'].transform([data.get('attack_type', 'normal')])[0])
        except ValueError as e:
            return jsonify({"error": f"Invalid Category: {e}"}), 400

        # ... (features dict construction uses these ints now) ...
        # Note: We need to reconstruct the features dict here to ensure it uses the casted variables
        # But since 'features' dict construction is below, and uses 'dev_type', 'ward' etc...
        # Wait, the instruction is to replace the WHOLE block or just parts?
        # I'll replace the Transform block and the Predict block.
        
        # 2. Build Feature Vector (Order matters! Must match training)
        features = {
            'criticality_tier': float(data.get('criticality', 5)),
            'life_support': int(data.get('life_support', 0)),
            'device_type_encoded': dev_type,
            'ward_encoded': ward,
            'protocol_encoded': proto,
            'packet_size': float(data.get('packet_size', 500)),
            'packet_rate': float(data.get('packet_rate', 50)),
            'packets_per_sec': float(data.get('packet_rate', 50)) / 60.0,
            'unique_ports': int(data.get('unique_ports', 1)),
            'failed_connections': int(data.get('failed_connections', 0)),
            'bytes_sent': float(data.get('packet_size', 500)) * float(data.get('packet_rate', 50)),
            'bytes_received': float(data.get('packet_size', 500)) * float(data.get('packet_rate', 50)) * 0.5,
            'flow_duration': 30.0,
            'hour_of_day': int(data.get('hour', 12)),
            'day_of_week': int(data.get('day', 0)),
            'is_night': 1 if int(data.get('hour', 12)) < 6 or int(data.get('hour', 12)) > 22 else 0,
            'is_weekend': 0, 
            'attack_type_encoded': attack,
            'attack_severity': float(data.get('attack_severity', 0)),
            'network_anomaly_score': float(data.get('network_anomaly', 0)),
            'behavioral_anomaly_score': float(data.get('behavioral_anomaly', 0)),
            'time_anomaly_score': float(data.get('time_anomaly', 0))
        }

        # Create DataFrame
        X = pd.DataFrame([features])[IOMT_FEATURES]
        
        # Predict
        priority = str(IOMT_MODEL.predict(X)[0])
        probs = IOMT_MODEL.predict_proba(X)[0]
        confidence = float(max(probs) * 100)
        
        return jsonify({
            "priority": priority,
            "confidence": round(confidence, 2),
            "features_processed": features
        })

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/iomt/alerts', methods=['GET'])
def get_iomt_alerts():
    """Returns the history of IoMT alerts."""
    return jsonify(IOMT_ALERTS[-100:]) # Return last 100 alerts



if __name__ == '__main__':
    print(f"🚀 ARS Dashboard Server running on http://localhost:5000")
    print(f"📂 Watching logs at: {LOG_FILE}")
    app.run(port=5000, debug=True)
