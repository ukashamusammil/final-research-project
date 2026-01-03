# AR System (Automated Response System)

The **Automated Response System (ARS)** is an advanced security and privacy framework designed for Healthcare IoT environments. It integrates proactive threat detection, automated response mechanisms, and real-time PHI (Protected Health Information) redaction to ensure compliance with healthcare regulations (like HIPAA/GDPR) while maintaining operational continuity.

## 🚀 Key Features

### 1. 🛡️ AI-Powered Threat Detection
*   **Real-time Analysis:** Monitors device vitals (CPU, Memory, Network) to detect anomalies.
*   **Automated Response:** Uses a Random Forest Classifier to predict immediate actions:
    *   `ISOLATE`: Block network access for high-risk threats (e.g., Ransomware).
    *   `MONITOR`: Flag suspicious activity for admin review.
    *   `NO_ACTION`: Allow normal operations.

### 2. 🔒 PHI Redaction (Privacy Guard)
*   **Sensitive Data Masking:** Automatically detects and redacts patient identifiers (Names, IDs) from system logs before they are stored or transmitted.
*   **Compliance:** Ensures that audit logs remain actionable for security without compromising patient privacy.

### 3. 📝 Compliance Reporting
*   **Daily Dashboards:** Generates comprehensive PDF reports summarizing:
    *   Threat incidents & responses.
    *   System health status.
    *   Data privacy audit trails.
*   **Wazuh Integration:** Designed to complement SIEM dashboards like Wazuh.

## 📂 Project Structure

```
AR System/
├── src/
│   ├── core/           # Main Python application logic
│   │   ├── inference_engine.py  # AIOps decision logic
│   │   ├── modules/             # Redaction & Reporting modules
│   ├── firmware/       # ESP32/IoT Device code
│   └── training/       # Model training scripts & notebooks
├── data/               # Datasets for training & testing
├── models/             # Trained AI models (.pkl)
├── results/            # Generated reports & logs
├── run_full_system_test.py  # Validation suite
└── requirements.txt    # Python dependencies
```

## 🛠️ Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-username/ar-system.git
    cd "AR System"
    ```

2.  **Set up Virtual Environment**
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Linux/Mac
    source .venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## ⚡ Usage

### Running System Validation
To verify that all components (AI models, Redaction, Reporting) are working correctly, run the full system test:

```bash
python run_full_system_test.py
```

### Running the Core System
(Refer to individual module documentation in `src/core` for running specific services).

## 📊 Models
The system uses pre-trained machine learning models located in the `models/` directory:
*   `ars_response_model.pkl`: Predicts response actions.
*   `ars_phi_model.pkl`: Detects sensitive PHI entities.

## 🤝 Contributing
1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## 📜 License
[MIT License](LICENSE)
