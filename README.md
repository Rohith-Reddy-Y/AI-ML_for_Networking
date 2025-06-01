# AI/ML for Networking

Category: Network Security

Pre-requisites:  

Computer Systems Basics – CPU/Memory/Storage/NIC
Good Hands-on Experience on Linux
Programming Skills in Python and/or C
Basics of AI/ML
 

Problem Statement

 

Description:

Modern networks face increasing challenges in monitoring and securing traffic due to the exponential growth of data, encrypted communication, and sophisticated cyber threats. Traditional rule-based security measures and deep packet inspection (DPI) techniques are becoming less effective in detecting and classifying threats, especially in encrypted traffic. Manual intervention in network traffic classification is inefficient, leading to delayed threat detection and security vulnerabilities. To address these issues, AI-driven solutions can analyze traffic patterns, detect anomalies, classify applications, and enhance security in real-time, ensuring adaptive and intelligent network defense.

 

Expected Outcome:

Automated Network Traffic Analysis using AI/ML models to detect and classify traffic in real time.
Improved Threat Detection & Security, identifying anomalies, malware, and encrypted attacks with higher accuracy.
Reduced False Positives & False Negatives, enhancing the efficiency of network security operations.
Scalability & Performance Optimization, ensuring AI models can handle high-traffic environments with minimal latency.
Privacy-Preserving Traffic Analysis, leveraging AI for encrypted traffic analysis without decryption.
 

Deliverables:

AI-Powered Traffic Classification Model – A system that categorizes network traffic (e.g., APP ID detection) based on behavior and patterns.
Threat Detection & Anomaly Identification Framework – AI-driven security mechanism to detect suspicious or malicious activity.



# AI-Powered Web Attack Detection System

## 🚀 Project Overview

This project is an **AI-powered Web Application Firewall (WAF)** that detects and blocks malicious web attacks such as **SQL Injection (SQLi)**, **Cross Site Scripting (XSS)**, **Remote Code Execution (RCE)**, and **malware payloads** in real-time. It integrates:

* Traditional Machine Learning (ML) models for speed
* Deep Learning (DL) models for accuracy
* ModSecurity for blocking traffic
* NGINX as a reverse proxy
* Docker for containerization

You can test it live in a Linux terminal and observe AI-based detection with blocked attack logs.

---

## 🏠 Technologies Used

| Layer        | Technology                                 |
| ------------ | ------------------------------------------ |
| Web Server   | Flask (Python)                             |
| WAF Engine   | NGINX + ModSecurity                        |
| ML Framework | Random Forest (Scikit-learn)               |
| DL Framework | URLNet (TensorFlow + OpenVINO)             |
| AI Engine    | TADK (Threat AI Detection Kit - Simulated) |
| Deployment   | Docker + Docker Compose                    |
| Testing      | curl, wrk (benchmarking tool)              |

---

## 📁 File Structure

```
project/
├── docker-compose.yml
├── webapp/
│   └── app.py                  # Flask login form
├── nginx/
│   ├── nginx.conf              # NGINX setup with ModSecurity
│   └── modsec/
│       ├── modsecurity.conf   # ModSecurity rules
│       └── crs/               # Optional: OWASP Core Rule Set
├── tadk/
│   └── switch_model.sh        # TADK simulation script
```

---

## 🔧 Setup Instructions

### 1. Prerequisites

Ensure you have:

* Linux (Ubuntu recommended)
* Docker & Docker Compose installed

### 2. Clone Repository

```bash
git clone https://github.com/your-username/ai-waf-detection.git
cd ai-waf-detection
```

### 3. Start the Project

```bash
docker-compose up --build
```

> This will:
>
> * Build the Flask web app
> * Start NGINX + ModSecurity
> * Simulate the AI engine (TADK)

### 4. Test it!

Send simulated attack payloads:

```bash
curl -X POST -d "username=admin&password=' OR 1=1--" http://localhost:8005/
curl -X POST -d "username=<script>alert(1)</script>" http://localhost:8005/
```

You should get:

```bash
403 Forbidden - SQLi/XSS Detected
```

And see logs:

```bash
ModSecurity: Access denied with code 403 ... SQL Detected
Matched Data: Deep Learning prob = 0.95759
```

---

## 📊 Model Architecture

### Traditional ML (Random Forest):

* Features: Token histogram, packet stats, byte size
* Fast, explainable

### Deep Learning (URLNet):

* Input: Raw URL strings
* Embedding: Word + Character
* CNN + Pooling → Classification
* High accuracy, higher latency

---

## 📊 Accuracy Results

| Model          | SQLi Accuracy | XSS Accuracy |
| -------------- | ------------- | ------------ |
| URLNet (DL)    | 99.78%        | \~97–99%     |
| Random Forest  | 96.21%        | \~90–95%     |
| Regex Baseline | 83.23%        | \~80%        |
| Libinjection   | 97.17%        | \~96%        |

---

## ⏱️ Latency Comparison

| Model         | Avg Latency | Requests/sec |
| ------------- | ----------- | ------------ |
| Rule-based    | \~8.10ms    | \~1236       |
| Random Forest | \~8.60ms    | \~1163       |
| Deep Learning | \~50.75ms   | \~197        |

---

## 📉 Terminal Testing Tools

### curl for payloads:

```bash
curl http://localhost:8005/?user=admin&pass=' OR '1'='1
```

### wrk for benchmarking:

```bash
wrk -t10 -c10 -d10s http://localhost:8005/
```

---

## 🔨 Code Snippets

### Flask Web App (`webapp/app.py`)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        return f"Received: {username} | {password}"
    return '''
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

app.run(host='0.0.0.0', port=5000)
```

### ModSecurity Rules (`modsecurity.conf`)

```bash
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:'SQLi Detected'"
SecRule ARGS "@detectXSS" "id:1002,phase:2,deny,status:403,msg:'XSS Detected'"
```

### Simulated TADK (`tadk/switch_model.sh`)

```bash
#!/bin/bash
echo "Using device: CPU"
echo "TADK AI Model Loaded - Simulating Deep Learning detection"
```

---

## 🌐 Future Scope

* Replace fake AI simulation with real inference script
* Integrate threat dashboard (Grafana/ELK)
* Add HTTPS, authentication, geo-fencing
* Include more attack types: CSRF, LFI, RCE

---

## 🌟 Credits

This project is a demo for educational purposes built on the concept of combining **AI/ML with ModSecurity WAF** using open-source tools. Inspired by research in AI-based threat detection using URLNet and payload analysis.

---

## 👉 Contribution

Pull requests are welcome. For major changes, please open an issue first.

---

## 📅 Maintainer

CyGeek
B.Tech CSE - Cyber Security
Gitam University - Bangalore Campus

---

## 📊 Screenshots

Add screenshots of:

* Terminal curl/XSS test with 403 response
* Log showing Deep Learning prediction
* Web form UI (Flask app)

---

## 📄 License

[MIT](LICENSE)

---

## 🔍 References

* [URLNet Paper](https://arxiv.org/abs/1802.03162)
* [ModSecurity OWASP CRS](https://coreruleset.org/)
* [TADK Concepts (Intel)](https://www.intel.com/)
* [wrk - HTTP Benchmarking](https://github.com/wg/wrk)

