# 🔥 Intelligent Firewall — AI-Powered Next Generation Network Security System

![Cyber Security](https://img.shields.io/badge/Cybersecurity-NGFW-blue)
![Python](https://img.shields.io/badge/Python-3.x-yellow)
![Machine Learning](https://img.shields.io/badge/AI-ML%20Powered-green)
![Platform](https://img.shields.io/badge/Platform-Windows/Linux-orange)

## 📌 Overview

**Intelligent Firewall** is an advanced **AI-powered Next Generation Firewall (NGFW)** system that combines traditional firewall security, machine learning-based threat detection, endpoint detection, and Zero Trust security principles into a single integrated security platform.

Unlike traditional firewalls that rely only on predefined rules, this system uses:

* Real-time packet inspection
* Rule-based traffic filtering
* Machine learning threat classification
* Endpoint monitoring
* Process behavior analysis
* Identity-based access control
* Automated incident response

The goal is to provide a complete **multi-layer network defense system** capable of detecting, analyzing, and responding to modern cyber threats.

---

# 🚀 Key Features

## 🔹 Six-Stage Security Architecture

| Stage     | Module           | Purpose                                      |
| --------- | ---------------- | -------------------------------------------- |
| Stage 1   | Packet Capture   | Real-time network traffic monitoring         |
| Stage 2   | Rule Engine      | Firewall rules, IP blocking, flood detection |
| Stage 3/4 | NGFW + ML Engine | AI-based traffic classification              |
| Stage 5   | EDR              | Endpoint threat detection and response       |
| Stage 6   | Zero Trust       | Identity and policy-based security           |
| Core      | Event System     | Central logging and alert management         |

---

# 🏗️ System Architecture

```
                     Internet
                         |
                         |
                Network Traffic
                         |
                         ↓

              Stage 1: Packet Capture
                   (Scapy Sniffer)

                         |
                         ↓

              Stage 2: Rule Engine
          (Firewall Rules + Flood Detection)

                         |
                         ↓

          Stage 3/4: AI Next Generation Firewall
          (ML Detection + Traffic Classification)

                         |
                         ↓

               Stage 5: EDR System
        (Process Monitoring + Threat Response)

                         |
                         ↓

              Stage 6: Zero Trust Layer
       (Identity + Microsegmentation + Policies)

                         |
                         ↓

              Response & Alert System
          (Blocking + Logging + Telegram Alert)
```

---

# 📂 Project Structure

```
IntelligentFirewall/

│
├── run.py
│   └── Main launcher for complete firewall system
│
├── Stage1_PacketCapture/
│   └── packet_capture.py
│       └── Scapy live packet monitoring
│
├── Stage2_RuleEngine/
│   ├── rule_engine.py
│   │   └── Firewall rules and flood detection
│   │
│   └── firewall_rules.json
│       └── Custom security rules
│
├── Stage3_4_NGFW_ML/
│
│   ├── ngfw_engine.py
│   │   └── ML-based traffic classification
│   │
│   ├── combine_ngfw_dataset.py
│   │   └── Dataset preparation
│   │
│   ├── step1_accuracy_model.py
│   │   └── Model evaluation
│   │
│   ├── step2_preprocess_train_model.py
│   │   └── XGBoost training pipeline
│   │
│   └── test_model.py
│       └── ML engine testing
│
├── Stage5_EDR/
│
│   ├── main_stage5.py
│   │
│   ├── sysmon_monitor.py
│   │   └── Windows event monitoring
│   │
│   ├── detection_rules.py
│   │   └── LOLBins and LotL detection
│   │
│   ├── network_monitor.py
│   │   └── Process network tracking
│   │
│   ├── network_mapper.py
│   │
│   └── response_engine.py
│       └── Automated response actions
│
├── Stage6_ZeroTrust/
│
│   ├── main_stage6.py
│   │
│   ├── identity_policy.py
│   │   └── User role access control
│   │
│   ├── microsegmentation.py
│   │   └── Network zone security
│   │
│   ├── default_deny.py
│   │   └── Whitelist enforcement
│   │
│   ├── sandbox.py
│   │   └── File and URL analysis
│   │
│   └── policies.json
│
├── Core/
│
│   ├── orchestrator.py
│   │   └── Multi-stage execution manager
│   │
│   ├── event_bus.py
│   │   └── Central logging system
│   │
│   └── telegram_alert.py
│       └── Security notifications
│
├── GUI/
│
│   └── firewall_gui.py
│       └── PyQt6 security dashboard
│
└── logs/
    └── Generated security logs
```

---

# ⚙️ Installation

## Requirements

* Python 3.10+
* Windows/Linux
* Administrator privileges

## Install Dependencies

```bash
pip install PyQt6 scapy psutil pywin32
```

For Machine Learning module:

```bash
pip install xgboost joblib pandas scikit-learn
```

For NGFW proxy:

```bash
pip install mitmproxy
```

---

# ▶️ Running the Firewall

## Start Complete System

```bash
python run.py
```

This launches:

* GUI Dashboard
* Packet Capture
* Rule Engine
* ML Engine
* EDR
* Zero Trust Monitor

---

## Console Mode

Run without GUI:

```bash
python run.py --cli
```

---

## Stage 6 Testing

```bash
python run.py --test
```

---

# 🤖 Machine Learning Engine

## Dataset Support

The ML model supports:

* CICIDS2017
* UNSW-NB15

## Training Pipeline

### Step 1: Combine Dataset

```bash
python Stage3_4_NGFW_ML/combine_ngfw_dataset.py
```

### Step 2: Train Model

```bash
python Stage3_4_NGFW_ML/step2_preprocess_train_model.py
```

The trained model is stored inside:

```
models/
```

The NGFW engine loads this model for real-time prediction.

---

# 🛡️ Security Detection Capabilities

## Network Attacks

The system can detect:

### Port Scanning

Example:

```
Multiple port requests
from same source IP
```

Action:

```
BLOCK IP
```

---

### Flood / DoS Detection

Detection:

```
High packet rate
Abnormal traffic volume
```

Response:

```
Traffic blocked
Alert generated
```

---

### Suspicious Network Behavior

Detection:

```
Unknown communication patterns
```

Response:

```
ML classification
```

---

# 🖥️ GUI Dashboard Features

## Live Monitor

Features:

* Real-time events
* Packet information
* Action filtering
* IP filtering

## Logs Management

Features:

* Daily logs
* JSON export
* Security event history

## Rules Management

Features:

* Add blocked IPs
* Remove blocked IPs
* Block ports
* Configure thresholds

## Zero Trust Policy Editor

Manage:

* Users
* Roles
* Allowed domains
* Restricted ports

---

# 📢 Telegram Alert Integration

The firewall supports real-time alerts using Telegram Bot API.

Example Alert:

```
🚨 SECURITY ALERT

Threat:
Port Scan Detected

Source:
192.168.1.50

Action:
IP Blocked Automatically
```

---

# 🔐 Zero Trust Security Model

Implemented concepts:

## Identity-Based Access

Example:

```json
{
 "Developer":
 {
  "allowed_domains":
  [
    "github.com"
  ],

  "blocked_ports":
  [
    21,
    23
  ]
 }
}
```

## Default Deny

Unknown access:

```
DENY BY DEFAULT
```

Only approved communication is allowed.

---

# 🔥 Automated Response

The firewall can:

✅ Block malicious IPs
✅ Terminate suspicious processes
✅ Generate security logs
✅ Send administrator alerts
✅ Apply access policies automatically

---

# 📊 Technologies Used

| Category            | Technology             |
| ------------------- | ---------------------- |
| Language            | Python                 |
| Packet Analysis     | Scapy                  |
| Proxy Security      | Mitmproxy              |
| ML Framework        | XGBoost                |
| Dataset             | CICIDS2017 / UNSW-NB15 |
| Endpoint Monitoring | Windows Sysmon         |
| GUI                 | PyQt6                  |
| System Monitoring   | Psutil                 |
| Alerting            | Telegram Bot API       |

---

# 🔮 Future Improvements

## Web Security Dashboard

Add:

* React frontend
* Live graphs
* Threat analytics

## Deep Learning Detection

Possible models:

* LSTM
* Autoencoder
* CNN

## Threat Intelligence Integration

Integrate:

* VirusTotal API
* AbuseIPDB
* MITRE ATT&CK

## Cloud Deployment

Future deployment:

```
Firewall-as-a-Service (FWaaS)
```

---

# 👨‍💻 Authors

## Keshav Sonawane
- Cybersecurity Enthusiast
- AI/ML Developer
- Flutter Developer

## Arya Kadam
- Co-Developer
- Cybersecurity & Software Development Contributor

---

**Project Areas:**  
Cybersecurity | Artificial Intelligence | Machine Learning | Network Security | Flutter Development
---

# ⭐ Project Status

🚧 Active Development

This project demonstrates the integration of:

* Network Security
* Artificial Intelligence
* Endpoint Protection
* Zero Trust Architecture
* Automated Incident Response

⭐ If you find this project useful, consider giving it a star.
