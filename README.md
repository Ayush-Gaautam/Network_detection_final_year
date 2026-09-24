# NetGuard AI

AI-Powered Real-Time Network Anomaly Detection and Visitor Security Monitoring System

## 1. Project Overview

NetGuard AI is a hackathon project designed to detect suspicious network behavior in real time using machine learning, packet analysis, and a modern web dashboard. The project focuses on monitoring traffic patterns, identifying abnormal activity such as DDoS attacks and port scanning, and presenting the results on an interactive dashboard for security monitoring.

This project is suitable for a multidisciplinary team:

- Web developers: build the dashboard and monitoring interface
- Data science students: work on datasets, feature engineering, and model evaluation
- AI/ML students: train anomaly detection models and improve classification logic
- Backend/Python students: handle live packet capture, network flow processing, and model integration

The goal is not just to build a model in isolation, but to create a real pipeline:

Network traffic -> flow extraction -> feature engineering -> anomaly detection -> threat alert -> dashboard visualization.

## 2. Problem Statement

Modern networks generate immense amounts of traffic every second. It is difficult for administrators to manually detect unusual patterns, especially when malicious activity is hidden among regular network flows. Attack patterns such as distributed denial-of-service (DDoS) attempts and port scanning can quickly overwhelm a service or reveal system vulnerabilities.

This project addresses the problem by:

- Capturing live or replayed network traffic
- Extracting useful flow-level features from that traffic
- Training a machine learning anomaly detection model to detect suspicious behavior
- Highlighting abnormal traffic patterns on a real-time dashboard
- Providing an understandable security overview for end users

## 3. Core Idea

The system continuously observes network activity and looks for abnormal patterns. Instead of treating network traffic as raw packet events only, it aggregates traffic into time windows and extracts meaningful features such as:

- packets per second
- bytes per second
- unique source IPs
- unique destination ports
- SYN counts
- flow duration
- TCP/UDP distribution
- average packet size

These features are then passed into an anomaly detection model. If the traffic deviates strongly from normal behavior, the system raises an alert such as:

- Potential DDoS
- Potential Port Scan
- Abnormal Traffic Pattern

## 4. Project Goals

### Primary goals

- Detect abnormal network activity using AI/ML
- Recognize suspicious traffic patterns in real time
- Build a user-friendly dashboard for threat monitoring
- Provide educational and demo-friendly network security insight

### Secondary goals

- Add IP-based traffic analytics
- Add visitor monitoring for a hosted website or internal service
- Show approximate geo-distribution of traffic sources
- Display live metrics, threat severity, and event timeline

## 5. High-Level Architecture

```text
Network traffic / website visitors
            │
            ▼
    Packet Capture Layer
    (Scapy / network capture)
            │
            ▼
    Flow Builder / Feature Extraction
    (packets, ports, bytes, timestamps, protocols)
            │
            ▼
    AI / ML Detection Engine
    (Isolation Forest / Autoencoder / rule-based logic)
            │
            ▼
    Threat Classification
    (Normal / Potential DDoS / Potential Port Scan / Anomaly)
            │
            ▼
    Dashboard / Monitoring UI
    (Streamlit / Web interface)
```

## 6. Tools and Technologies

### Backend / network analysis

- Python
- Scapy
- Pandas
- NumPy
- Socket / networking utilities

### AI / ML

- Scikit-learn
- Isolation Forest
- Autoencoder (optional advanced model)
- Model evaluation metrics

### Web dashboard

- Streamlit
- Plotly
- HTML/CSS/JavaScript (optional enhancement)

### Data science

- Jupyter Notebook
- Data cleaning and preprocessing
- Feature engineering
- Model comparison and evaluation

## 7. Attack Types the Project Can Target

### DDoS / traffic flood detection

Detect sudden increases in traffic volume, abnormal request rates, and concentrated destination attacks.

### Port scanning

Identify hosts that try multiple ports in a short span of time, which is a common sign of reconnaissance.

### Anomalous traffic patterns

Flag traffic deviating from normal patterns even when the exact attack category is not known.

## 8. Dataset Strategy

This project should use multiple sources of data in phases.

### 1. CIC-IDS2017

Best for the initial project stage.

- Normal traffic + attack traffic
- Flow-based features
- Suitable for intrusion detection experiments

### 2. CIC-DDoS2019

Useful for DDoS-specific training and evaluation.

- Better for large-scale distributed attack patterns
- Helps test attack-specific model behavior

### 3. UNSW-NB15 (optional)

Used for validation and generalization testing across a different dataset.

### 4. Live traffic or replayed traffic

For the final demo, use:

- your own server or isolated lab environment
- recorded dataset replay
- local packet capture in a safe environment

## 9. Important Security and Ethics Note

This project should be demonstrated responsibly.

- Do not target or scan public IPs or external servers without permission
- Use your own lab environment, virtual machines, or replayed datasets
- Label results as “potential” anomaly or threat, not definitive proof of malicious activity
- Keep all demo traffic inside a controlled environment

## 10. Project Workflow

### Phase 1: Data understanding

- Explore network datasets
- Understand features and labels
- Identify useful statistical properties

### Phase 2: Preprocessing

- Remove missing or invalid values
- Encode categories if needed
- Standardize numeric features
- Build a clean training dataset

### Phase 3: Model training

- Train Isolation Forest for anomaly detection
- Optional: test Autoencoder model
- Save trained models for later use

### Phase 4: Network capture

- Capture packets with Scapy
- Build flow summaries from raw network data
- Extract traffic features from each time window

### Phase 5: Threat detection

- Feed features into the model
- Detect anomalies
- Apply logic for DDoS and port-scan detection
- Generate alerts with timestamps and severity

### Phase 6: Dashboard integration

- Show live metrics and alerts
- Display traffic charts and anomaly timeline
- Include threat summary cards and flow details

### Phase 7: Demo and presentation

- Showcase attack replay or controlled traffic pattern changes
- Show the model responding to abnormal behavior
- Explain how the pipeline works to judges

## 11. Suggested Team Responsibilities

### Web development student

- Build dashboard in Streamlit or Flask
- Design charts, cards, alerts, and UI modules
- Connect backend to frontend
- Display real-time threat status

### Data science student

- Select and clean dataset
- Perform feature engineering
- Analyze normal vs attack traffic behavior
- Evaluate model precision, recall, and false positives

### AI/ML student

- Train and compare models
- Implement Isolation Forest or Autoencoder
- Tune threshold values and scoring logic
- Explain anomaly detection workflow in the presentation

### Python / backend student

- Implement Scapy-based packet capture
- Aggregate packets into flows
- Transform raw traffic into model-ready features
- Send alerts and metrics to the dashboard

## 12. MVP (Minimum Viable Product)

For the first working prototype, keep it practical:

1. Use CIC-IDS2017 or CIC-DDoS2019 dataset
2. Train an Isolation Forest model
3. Extract basic flow features from captured packets
4. Detect suspicious traffic patterns
5. Show alerts on a dashboard

This MVP is enough to demonstrate the core concept clearly.

## 13. Advanced Version

Once the MVP works, the team can extend with:

- multiple models and comparison
- dynamic thresholding
- visitor analytics from a real web app
- IP geolocation estimation
- packet-level analysis with richer features
- attack severity classification
- CSV/JSON logging of events
- database-backed threat history

## 14. Recommended Folder Structure

```text
netguard-ai/
│
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
│
├── data/
│   ├── raw/
│   │   ├── cic_ids_2017/
│   │   ├── cic_ddos_2019/
│   │   └── live_capture/
│   └── processed/
│       ├── cleaned_data.csv
│       ├── feature_matrix.csv
│       └── labels.csv
│
├── notebooks/
│   ├── data_exploration.ipynb
│   ├── model_training.ipynb
│   └── evaluation.ipynb
│
├── src/
│   ├── __init__.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py
│   │   └── packet_parser.py
│   │
│   ├── processing/
│   │   ├── __init__.py
│   │   ├── feature_extraction.py
│   │   ├── flow_builder.py
│   │   └── preprocess.py
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── anomaly_model.py
│   │   ├── threat_detector.py
│   │   └── detection_rules.py
│   │
│   └── dashboard/
│       ├── __init__.py
│       ├── app.py
│       ├── charts.py
│       └── styles.css
│
├── models/
│   ├── isolation_forest_model.pkl
│   └── scaler.pkl
│
├── logs/
│   ├── alerts.log
│   └── network_events.log
│
├── tests/
│   ├── test_feature_extraction.py
│   ├── test_threat_rules.py
│   └── test_pipeline.py
│
└── docs/
    ├── architecture.md
    └── demo_plan.md
```

## 15. Example Data Flow

```text
Raw packets
   │
   ▼
packet_capture.py
   │
   ▼
packet_parser.py
   │
   ▼
flow_builder.py
   │
   ▼
feature_extraction.py
   │
   ▼
preprocess.py
   │
   ▼
anomaly_model.py
   │
   ▼
threat_detector.py
   │
   ▼
app.py dashboard
```

## 16. Example Threat Output

```json
{
  "timestamp": "2026-09-24T10:45:12",
  "src_ip": "192.168.1.50",
  "dst_ip": "192.168.1.20",
  "protocol": "TCP",
  "packet_count": 4500,
  "bytes": 520000,
  "packets_per_sec": 450,
  "unique_ports": 24,
  "anomaly_score": 0.91,
  "threat_type": "Potential DDoS",
  "severity": "HIGH"
}
```

## 17. What This Project Teaches

This project combines multiple skill areas:

- Networking knowledge
- Feature engineering
- Machine learning and anomaly detection
- Visualization and dashboard design
- Real-time system integration
- Team-based project planning

This is exactly the kind of project that is impressive in a hackathon because it shows both practical engineering and AI-based thinking.

## 18. Final Presentation Angle

Use this message in your presentation:

> We built an AI-powered network security monitoring system that identifies suspicious traffic behavior in real time. By combining packet analysis, feature engineering, anomaly detection, and a live dashboard, the platform helps detect abnormal traffic patterns such as DDoS and port scanning before they become severe threats.

## 19. Suggested Hackathon Title Options

- NetGuard AI
- ThreatLens
- Network Sentinel
- Intrusion Insight
- SmartNet Monitor
- CyberFlow AI

## 20. Next Step for the Team

Start with the simplest working version:

1. Download CIC-IDS2017 or CIC-DDoS2019
2. Build a clean feature dataset
3. Train Isolation Forest
4. Capture packets using Scapy
5. Convert traffic into windows/features
6. Connect model to a dashboard
7. Run demos in a safe environment

This step-by-step path makes the project realistic, manageable, and strong enough for a hackathon presentation.

## 21. Developer Notes / Catch Memory

This project should be treated as a staged development system. Do not try to implement everything at once. Keep a clear development memory of what works and what needs improvement.

### Catch memory concept

In a real-world system, “catch memory” refers to a record of recent observations, events, and suspicious patterns that are stored temporarily for pattern detection and alert generation.

In this project, a simple version of catch memory can be a list or data structure storing the latest traffic windows and their features.

Example:

```python
recent_windows = [
    {
        "timestamp": "2026-09-24T10:45:12",
        "packet_count": 3500,
        "bytes": 450000,
        "packets_per_sec": 350,
        "unique_ports": 8,
        "anomaly_score": 0.82,
        "threat_type": "Potential DDoS"
    }
]
```

This memory helps the system:

- compare current behavior with recent history
- detect bursts or sustained abnormal activity
- trigger alerts when traffic stays abnormal over time
- build a timeline for the dashboard

### Why it matters

The detection model alone is not enough. A real security system must remember recent traffic behavior and compare it with the recent baseline. This is where “catch memory” becomes useful.

### Implementation idea

Store the latest N traffic windows in memory and compute:

- current anomaly score
- average recent anomaly score
- traffic spike ratio
- sudden increase over the last 5–10 windows
- persistence of suspicious behavior over time

This makes the system more practical and better for demo presentations.

## 22. Suggested Catch Memory Structure

```text
memory/
├── recent_flows.json
├── alerts.json
├── threat_history.csv
└── model_state.json
```

These files can store:

- recent flow summaries
- model status
- attack events
- dashboard alert snapshots

## 23. Summary

NetGuard AI is a realistic, multi-disciplinary hackathon project that blends:

- web development
- data science
- AI/ML
- networking
- cybersecurity monitoring

It is impressive because it solves a real world problem: quickly identifying suspicious network behavior in large-scale traffic.

The project is best built in phases, starting from a simple dataset-based anomaly model and then expanding into a real-time dashboard and live traffic detection pipeline.

## 24. Quick Start

```bash
pip install -r requirements.txt
python src/capture/packet_capture.py
python src/detection/threat_detector.py
streamlit run src/dashboard/app.py
```

## 25. Contribution Note

This project is intended as a student hackathon solution and can be expanded further with advanced detection logic, deployment features, and deeper security analytics.

---

This README is written to help a student team understand the concept, project flow, and realistic implementation path for a strong hackathon submission.
