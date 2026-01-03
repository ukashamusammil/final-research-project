import joblib
import pandas as pd
import os
import logging

class InferenceEngine:
    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        # Navigate up two levels from src/core to root, then to models
        self.root_path = os.path.abspath(os.path.join(self.base_path, '..', '..'))
        self.defense_model_path = os.path.join(self.root_path, 'models', 'ars_decision_model_final.pkl')
        self.phi_model_path = os.path.join(self.root_path, 'models', 'ars_phi_model.pkl')
        
        self.defense_model = self._load_model(self.defense_model_path)
        self.phi_model = self._load_model(self.phi_model_path)

    def _load_model(self, path):
        if os.path.exists(path):
            try:
                model = joblib.load(path)
                logging.info(f"✅ Loaded Model: {path}")
                return model
            except Exception as e:
                logging.error(f"[ERROR] Failed to load model {path}: {e}")
                return None
        else:
            logging.warning(f"⚠️ Model not found at {path}. Using fallback logic.")
            return None

    def predict_action(self, event_dict):
        """
        Input: Dict containing either Vitals ('heart_rate') or Network Threats ('threat_type')
        Output: 'ISOLATE', 'MONITOR', 'ROLLBACK', or 'NO_ACTION'
        """
        if not self.defense_model:
            return "MONITOR" # Fallback

        try:
            # 1. NEW MODEL SCHEMA (Network Threats)
            # Check if model expects 'threat_type' (feature of new RF model)
            if hasattr(self.defense_model, 'feature_names_in_') and 'threat_type' in self.defense_model.feature_names_in_:
                 data = {
                    'threat_type': event_dict.get('threat_type', 'Normal_Heartbeat'), 
                    'severity': event_dict.get('severity', 'None'),
                    'confidence_score': event_dict.get('confidence_score', event_dict.get('anomaly_score', 0.0))
                 }
                 df = pd.DataFrame([data])
                 return self.defense_model.predict(df)[0]

            # 2. OLD MODEL SCHEMA (Vitals based)
            # Maps simplified keys (from main.py) to Model's expected verbose keys
            data = {
                'Heart Rate (bpm)': event_dict.get('heart_rate', 0),
                'SpO2 Level (%)': event_dict.get('spo2', 0),
                'Systolic Blood Pressure (mmHg)': event_dict.get('bp_sys', 0),
                'Diastolic Blood Pressure (mmHg)': event_dict.get('bp_dia', 0),
                'Body Temperature (°C)': event_dict.get('temp', 0),
                'Fall Detection': int(event_dict.get('fall_detected', False)),
                'Anomaly_Score': event_dict.get('anomaly_score', 0.0)
            }
            
            # The old model expects specific columns. 
            # If the model uses OneHot or other transformers, this might need adjustment, but for pure RF it's fine.
            expected_features = [
                'Heart Rate (bpm)', 'SpO2 Level (%)', 
                'Systolic Blood Pressure (mmHg)', 'Diastolic Blood Pressure (mmHg)', 
                'Body Temperature (°C)', 'Fall Detection',
                'Anomaly_Score'
            ]
            
            df = pd.DataFrame([data], columns=expected_features)
            return self.defense_model.predict(df)[0]

        except Exception as e:
            logging.error(f"Prediction Error: {e}")
            # Fail-safe logic: If anomaly is high, isolate anyway
            if event_dict.get('anomaly_score', 0) > 0.8: return "ISOLATE"
            return "MONITOR"

    def detect_phi(self, log_text):
        """
        Returns True if log contains PHI, False otherwise
        """
        if not self.phi_model:
            return False
            
        try:
            # Handle case where pickle is a Dict containing the model
            model_to_use = self.phi_model
            if isinstance(self.phi_model, dict):
                # Try to find the actual estimator key, usually 'model' or 'pipeline'
                if 'model' in self.phi_model:
                    model_to_use = self.phi_model['model']
                elif 'pipeline' in self.phi_model:
                    model_to_use = self.phi_model['pipeline']
            
            # Ensure it has a predict method
            if hasattr(model_to_use, 'predict'):
                prediction = model_to_use.predict([log_text])[0]
                return bool(prediction)
            else:
                logging.error(f"PHI Model object {type(model_to_use)} has no predict method.")
                return False
                
        except Exception as e:
            logging.error(f"PHI Detection Error: {e}")
            return False
