# NIDS - Network Intrusion Detection System

## Overview

NIDS (Network Intrusion Detection System) is a Machine Learning based web application designed to detect and classify malicious network traffic using the NSL-KDD dataset.

The system analyzes incoming network traffic features and predicts whether the traffic is:

- Normal
- DOS Attack
- PROBE Attack
- R2L Attack
- U2R Attack

This project combines Machine Learning and Cybersecurity concepts to provide a real-time intrusion detection solution through an interactive web interface.

---

# Features

- Machine Learning based intrusion detection
- Real-time attack prediction
- Multiple attack category classification
- Flask powered web application
- User-friendly frontend interface
- NSL-KDD dataset integration
- Responsive UI design
- Deployable on cloud platforms like Render

---

# Tech Stack

## Frontend
- HTML5
- CSS3

## Backend
- Flask

## Machine Learning
- Scikit-learn
- Pandas
- NumPy
- Joblib

## Deployment
- GitHub
- Render

---

# Project Structure

```text
NIDS/
│
├── app.py
├── train_model.py
├── requirements.txt
├── Procfile
├── runtime.txt
├── model.pkl
├── label_encoder.pkl
├── protocol_encoder.pkl
├── service_encoder.pkl
├── flag_encoder.pkl
│
├── data/
│   ├── Train.txt
│   └── Test.txt
│
├── static/
│   └── style.css
│
├── templates/
│   ├── index.html
│   └── prediction.html
│
└── README.md

LICENSE

This project is licensed under the MIT License.
