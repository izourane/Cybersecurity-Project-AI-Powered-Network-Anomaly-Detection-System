# 🛡️ AI-Powered Network Intrusion Detection System

Real-time behavioral network anomaly detection using Machine Learning, Scapy, and Streamlit.

---

# 🚀 Overview

This project transforms a basic network traffic analyzer into a complete AI-powered behavioral intrusion detection system capable of:

- Capturing live network traffic
- Extracting behavioral traffic features
- Detecting anomalies using Machine Learning
- Generating real-time threat alerts
- Visualizing suspicious activities through a professional dashboard

The system acts as a lightweight real-time Network Intrusion Detection System (NIDS).

---

# 🔥 Features

## ✅ Real-Time Packet Capture

- Live network traffic monitoring
- Packet parsing with Scapy
- Protocol analysis
- Traffic statistics

---

## ✅ Behavioral Feature Engineering

The system extracts advanced behavioral features such as:

- Packet size
- Protocol frequency
- Packets per source
- Bytes per source
- Unique destinations
- Packet rate
- TCP/UDP/DNS ratios
- Burst score

---

## ✅ Machine Learning Anomaly Detection

Implemented using:

- Isolation Forest
- Unsupervised anomaly detection
- Behavioral traffic analysis
- Real-time inference

---

## ✅ Real-Time Threat Detection

The system detects:

- DNS anomalies
- Burst traffic
- High-frequency communications
- Suspicious host behaviors
- Potential network attacks

---

## ✅ Professional Dashboard

Built using:

- Streamlit
- Plotly
- Pandas

Dashboard capabilities:

- Live anomaly monitoring
- Risk score visualization
- Threat severity analysis
- Top suspicious IPs
- Protocol analytics
- Interactive charts

---

# 🧠 Machine Learning Pipeline

```text
Live Packet Capture
        ↓
Behavioral Feature Extraction
        ↓
Isolation Forest Inference
        ↓
Threat Detection
        ↓
Alert Logging
        ↓
Real-Time Dashboard