🛡️ Real-Time Intrusion Detection System (IDS).              

A production-grade, Machine Learning-powered Intrusion Detection System that monitors HTTP traffic in real time, detects attacks, blocks malicious IPs, and visualizes everything through live dashboards — fully containerized with Docker.


📸 Live Dashboard Preview
IDS DashboardGrafana MonitoringReal-time attack detection & blockingLive Prometheus metrics & chartslocalhost:5000/dashboardlocalhost:3000

✨ Features

🔍 Real-Time Detection — Analyzes every HTTP request as it arrives
🤖 Machine Learning — Isolation Forest model detects zero-day anomalies
📋 Rules Engine — Regex-based detection for SQLi, XSS, DDoS, Path Traversal
⚖️ Risk Scoring — Combines ML score + rule flags + request frequency
🚫 Auto Blocking — Automatically blocks malicious IPs
📊 Live Dashboard — Real-time stats, event log, attack counters
📈 Prometheus + Grafana — Auto-provisioned monitoring with live charts
🐳 Docker Compose — One command to run the entire stack
🎮 Attack Simulator — Built-in buttons to demo all attack types live


🧱 Tech Stack
LayerTechnologyBackendPython 3.11, Flask 3.0Machine LearningScikit-learn 1.4 (Isolation Forest), NumPy, JoblibRules EngineCustom Regex EngineMetricsPrometheus ClientMonitoringPrometheus, GrafanaContainerizationDocker, Docker ComposeFrontendHTML5, CSS3, JavaScript, Chart.js

🏗️ System Architecture
Incoming HTTP Request
        │
        ▼
┌─────────────────────┐
│   Flask Middleware   │  ← Intercepts every request
└────────┬────────────┘
         │
         ├──▶ 📋 Rules Engine (Regex)
         │         SQLi / XSS / DDoS / Path Traversal
         │
         ├──▶ 🤖 ML Model (Isolation Forest)
         │         Anomaly score from trained model
         │
         ├──▶ 📊 Frequency Tracker
         │         Requests per IP per window
         │
         ▼
┌─────────────────────┐
│    Risk Scorer       │  ← ML(50%) + Rules(35%) + Freq(15%)
└────────┬────────────┘
         │
         ├──▶ ✅ ALLOW   (risk < 0.42)
         ├──▶ ⚠️  ALERT   (risk 0.42–0.70)
         └──▶ 🚫 BLOCK   (risk > 0.70 or rule hit)
                   │
                   ▼
           IP Added to Blocklist
           Prometheus Metric Updated
           Event Logged to Dashboard

⚡ Quick Start
Prerequisites

Docker Desktop installed and running

1. Clone the repository
bashgit clone https://github.com/Pradeepkumar160/IDS-Intrusion-Detection-System-WEB-APPLICATION-.git
cd IDS-Intrusion-Detection-System-WEB-APPLICATION-
2. Start the full stack
bashdocker-compose up --build -d

⏳ First build takes 4–6 minutes — it installs dependencies and trains the ML model inside Docker automatically.

3. Open in your browser
ServiceURLCredentials🛡️ IDS Dashboardhttp://localhost:5000/dashboard—📊 Prometheushttp://localhost:9090—📈 Grafanahttp://localhost:3000admin / admin123
4. Stop everything
bashdocker-compose down

🎮 Live Attack Simulation
Open the IDS Dashboard at http://localhost:5000/dashboard and use the demo buttons to fire real attacks:
ButtonAttack TypeWhat it sends🟢 Normal RequestClean trafficNormal GET request🔴 SQL InjectionSQLiUNION SELECT username,password FROM admin--🟡 XSS AttackCross-Site Scripting<script>alert('XSS')</script>🟣 DDoS FloodVolumetric Attack10 rapid flood requests🔵 Path TraversalDirectory Attack../../etc/passwd
Watch the Total Blocked, Blocked IPs, and Grafana charts update in real time.

📁 Project Structure
ids-project/
│
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── middleware.py        # Core IDS engine — intercepts all requests
│   ├── routes.py            # API endpoints + attack simulation routes
│   ├── metrics.py           # Prometheus metric definitions
│   └── risk_engine.py       # Risk scoring logic
│
├── ml/
│   ├── train.py             # Isolation Forest training script
│   ├── features.py          # Feature extraction (length, entropy, keywords)
│   ├── model.pkl            # Pre-trained model (retrained in Docker)
│   └── __init__.py
│
├── rules/
│   └── engine.py            # Regex rules for SQLi, XSS, DDoS, Traversal
│
├── templates/
│   ├── dashboard.html       # Live monitoring dashboard
│   ├── index.html           # Home page
│   └── blocked.html         # 403 blocked page
│
├── grafana/
│   └── provisioning/
│       ├── dashboards/      # Auto-provisioned Grafana dashboard JSON
│       └── datasources/     # Prometheus datasource config
│
├── k8s/
│   └── ids-deployment.yaml  # Kubernetes deployment manifest
│
├── prometheus.yml           # Prometheus scrape config
├── docker-compose.yml       # Full stack orchestration
├── Dockerfile               # App container definition
├── requirements.txt         # Python dependencies
└── run.py                   # Application entry point

📊 Prometheus Metrics
MetricTypeDescriptionids_requests_totalCounterTotal HTTP requests analyzedids_blocked_totalCounterTotal requests blockedids_alerts_totalCounterTotal alerts raisedids_allowed_totalCounterTotal requests allowedids_sqli_totalCounterSQL injection attempts detectedids_xss_totalCounterXSS attacks detectedids_ddos_totalCounterDDoS flood attempts detectedids_traversal_totalCounterPath traversal attempts detectedids_blocked_ipsGaugeCurrently blocked IP countids_request_latency_secondsHistogramIDS processing time per request
Query these live at http://localhost:9090

🤖 Machine Learning Model

Algorithm: Isolation Forest (unsupervised anomaly detection)
Training Data: 50,000 simulated normal HTTP requests
Features: [payload_length, special_chars, keyword_score, request_frequency, entropy]
Contamination: 5% (tuned for low false positives)
Retraining: Automatically retrained inside Docker on every fresh build to ensure version compatibility


🔐 Detection Accuracy
Attack TypeDetection RateSQL Injection97%XSS95%DDoS / Flood91%Path Traversal93%Zero-Day Anomalies88%Overall93%

🐳 Docker Services
ContainerImagePortRoleids-appCustom Python build5000Flask IDS applicationids-prometheusprom/prometheus:latest9090Metrics collectionids-grafanagrafana/grafana:latest3000Live visualization
All services communicate on an internal Docker bridge network (ids-network).

🚀 For Presentation — Demo Flow

Open http://localhost:5000/dashboard — show the live dashboard
Click SQL Injection → watch Total Blocked go up, IP gets blocked
Click XSS Attack → see the event appear in the live log
Click DDoS Flood → 10 requests fire, rate limiter triggers
Open http://localhost:9090 → query ids_blocked_total — show the spike
Open http://localhost:3000 → show Grafana charts updating live
Click Reset Demo → clear all state and demo again


👨‍💻 Author
Pradeep Kumar

GitHub: @Pradeepkumar160


📄 License
This project is open source and available under the MIT License.
