import time
import logging
import json
from inference_engine import InferenceEngine
from modules.containment import IsolationManager
from modules.redaction import PHIRedactor
from modules.wazuh_connector import WazuhConnector

# Configure Tamper-Evident Logging
logging.basicConfig(
    filename='ars_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def main():
    print("[SYS_EVENT] STARTING AUTOMATED RESPONSE SYSTEM (ARS) - DEFENSE CORE")
    print("=========================================================")
    
    # 1. Initialize Components
    ai_brain = InferenceEngine()
    isolation_mgr = IsolationManager()
    phi_guard = PHIRedactor() # Uses Regex + AI Hybrid
    
    logging.info("ARS System Startup. Models loaded. Waiting for events...")
    
    # 2. Configure Event Source
    # Check if user wants to use Live Wazuh Data or Simulation
    print("\n[CONFIG] Select Operation Mode:")
    print("   [1] Simulation Mode (Pre-defined scenarios)")
    print("   [2] Live Wazuh Integration (Real-time API)")
    mode = input("Enter selection [1/2]: ").strip()

    event_stream = []
    
    if mode == "2":
        wazuh_ip = "20.239.185.152" # Default from project
        wazuh_user = input("Enter Wazuh Username [wazuh-wui]: ").strip() or "wazuh-wui"
        wazuh_pass = input("Enter Wazuh Password: ").strip()
        
        connector = WazuhConnector(wazuh_ip, wazuh_user, wazuh_pass)
        if connector.authenticate():
            print("[SYS_EVENT] Connected to Wazuh Manager. Listening for alerts...")
            # For this simple loop, we'll wrap get_alerts in a generator or just loop
            # Here we define a simple generator for the main loop
            def live_stream():
                while True:
                    alerts = connector.get_alerts()
                    for alert in alerts:
                        # Convert Wazuh alert format to AR System format
                        # This is a critical mapping step.
                        # Assuming 'alert' has 'agent' and 'rule' fields
                        yield {
                            "device_ip": alert.get('agent', {}).get('ip', '0.0.0.0'),
                            "heart_rate": 0, # Wazuh doesn't give vitals, we imply them or fetch elsewhere?
                            "spo2": 0,      # For security alerts, vitals might not be relevant or we mock them
                            "anomaly_score": 1.0, # Alerts are high confidence
                            "log": alert.get('full_log') or alert.get('rule', {}).get('description', 'Unknown Alert')
                        }
                    time.sleep(2)
            event_stream = live_stream()
        else:
            print("[ERROR] Authentication failed. Falling back to Simulation.")
            mode = "1"

    if mode != "2": 
        # Simulation Mode
        event_stream = [
        # Event 1: Normal Heartbeat
        {"device_ip": "192.168.1.50", "heart_rate": 75, "spo2": 98, "anomaly_score": 0.1, "log": "Patient P-123 stable."},
        # Event 2: Malware Attack Detected (High Anomaly)
        {"device_ip": "192.168.1.50", "heart_rate": 78, "spo2": 97, "anomaly_score": 0.95, "log": "Patient ID P-123. Unauthorized process detected on port 22."},
        # Event 3: Attack Cleared (False Positive Rollback Test)
        {"device_ip": "192.168.1.50", "heart_rate": 76, "spo2": 98, "anomaly_score": 0.05, "log": "System scan complete. No threats."},
        
        # --- NEW TEST: PERMANENT QUARANTINE ---
        # Event 4: Another Device with High Threat
        {"device_ip": "192.168.1.99", "heart_rate": 120, "spo2": 85, "anomaly_score": 0.99, "log": "Ransomware detected."},
        # Event 5: Threat Persists (Should Trigger Quarantine)
        {"device_ip": "192.168.1.99", "heart_rate": 122, "spo2": 84, "anomaly_score": 0.99, "log": "Encryption process active."},
        # Event 6: Ignored Data (Should be skipped)
        # Event 6: Ignored Data (Should be skipped)
        {"device_ip": "192.168.1.99", "heart_rate": 0, "spo2": 0, "anomaly_score": 0.0, "log": "Trying to reconnect..."},
        
        # --- USER VALIDATION TEST ---
        {"device_ip": "10.0.0.5", "heart_rate": 60, "spo2": 99, "anomaly_score": 0.0, "log": "TEST: Patient John Doe (ID P-999) transfer request."}
    ]
    
    
    
    # Track states
    # isolated_devices = {}   # Dictionary: {ip: timestamp_of_isolation}
    isolated_devices = {}
    quarantined_devices = set()   # Permanent Quarantine

    # 3. Processing Loop
    for event in event_stream:
        device_ip = event['device_ip']
        
        # Skip processing if device is already in Permanent Quarantine
        if device_ip in quarantined_devices:
            print(f"\n[SYS_EVENT] IGNORED DATA from {device_ip}: Device is in PERMANENT QUARANTINE.")
            continue

        print(f"\n[INGEST] RECEIVED DATA: IP={device_ip} | Score={event['anomaly_score']}")
        time.sleep(1)
        
        # A. PRIVACY CHECK (PHI Redaction)
        if 'log' in event and phi_guard.has_regex_phi(event['log']):
            print(f"   [DLP] PRIVACY ALERT: Protected Health Information (PHI) detected in logs.")
            redacted_text = phi_guard.redact_log(event['log'])
            print(f"      REDACTED LOG: {redacted_text}")
            logging.info(f"Redacted log for {device_ip}: {redacted_text}")
            
        # B. THREAT RESPONSE (Defense Core)
        action = ai_brain.predict_action(event)
        print(f"   [THREAT_INTEL] AI DECISION: {action}")
        
        if action == "ISOLATE":
             # Case 1: New Threat
             if device_ip not in isolated_devices:
                print(f"   [RESPONSE] EXECUTING CONTAINMENT (Temporary Isolation)...")
                isolation_mgr.isolate_device(device_ip)
                isolated_devices[device_ip] = time.time() # Store timestamp
                logging.warning(f"ISOLATION TRIGGERED for {device_ip}")
                print("      [SYS_EVENT] Deep Monitoring Active... Checking for Persistence...")

             # Case 2: Threat Persists while Isolated -> Move to QUARANTINE
             elif device_ip in isolated_devices:
                print(f"   [ESCALATION] THREAT PERSISTED during Isolation! Risk confirmed.")
                print(f"   [QUARANTINE_OP] ESCALATING to PERMANENT QUARANTINE.")
                quarantined_devices.add(device_ip)
                del isolated_devices[device_ip] # Remove from temp
                logging.critical(f"DEVICE {device_ip} QUARANTINED PERMANENTLY.")
            
        elif action == "MONITOR":
             print("   [SYS_EVENT] Investigating... (Metrics suspicious but not critical)")
        
        elif action == "NO_ACTION":
            # Check if we need to Rollback (False Positive Detected)
            if device_ip in isolated_devices:
                isolation_start = isolated_devices[device_ip]
                elapsed = time.time() - isolation_start
                
                print(f"   [RESOLVED] DETECTED SAFE STATE on Isolated Device {device_ip}!")
                print(f"      [METRIC] Elapsed Time in Isolation: {elapsed:.2f}s (Required: 30s)")
                
                # Enforce 30s Delay
                if elapsed < 30:
                    print(f"      [POLICY_HOLD] WAIT: Policy requires 30s observation. Rollback DEFERRED.")
                else:
                    print(f"   [AUDIT_PASS] False Positive Confirmed. Initiating ROLLBACK...")
                    success = isolation_mgr.rollback(device_ip)
                    if success:
                        del isolated_devices[device_ip]
                        print(f"   [AUDIT_PASS] ROLLBACK COMPLETE. Device {device_ip} rejoined network.")
                        logging.info(f"ROLLBACK EXECUTED for {device_ip}")
            else:
                print("   [RESOLVED] System Normal.")

if __name__ == "__main__":
    main()
