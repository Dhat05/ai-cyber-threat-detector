
# 🛡️ AI Cybersecurity Threat Detector

A Python-based cybersecurity research project that combines rule-based authentication threat detection with machine-learning anomaly analysis. It includes a Streamlit dashboard, a FastAPI backend, and Docker deployment.

## Features

- Brute-force login detection
- Password-spraying pattern detection
- Successful login after repeated failures
- IP-based investigation
- Isolation Forest anomaly analysis
- Interactive Streamlit dashboard
- FastAPI endpoints for alerts and anomaly reports
- CSV report downloads
- Docker Compose deployment
- Automated tests with pytest

## Architecture

```text
Synthetic Authentication Logs
             |
       +-----+------+
       |            |
 Rule-Based       Machine Learning
 Detection        Isolation Forest
       |            |
       v            v
 security_alerts.csv
 ml_anomaly_results.csv
       |            |
       +------+-----+
              |
      +-------+--------+
      |                |
      v                v
 Streamlit Dashboard  FastAPI
   Port 8501          Port 8001
```

## Technology Stack

- Python
- Pandas
- Scikit-learn
- Streamlit
- Plotly
- FastAPI
- Uvicorn
- Docker
- pytest

## Project Structure

```text
ai-cyber-threat-detector/
├── data/
├── reports/
├── src/
│   ├── api.py
│   ├── dashboard.py
│   ├── detector.py
│   ├── generate_ml_data.py
│   └── ml_detector.py
├── tests/
│   ├── test_detector.py
│   └── test_ml_detector.py
├── Dockerfile
├── compose.yaml
├── requirements.txt
└── README.md
```

## Run with Docker

Install Docker Engine and Docker Compose first.

Clone or download the repository, then run:

```bash
docker compose up --build -d
```

Check the containers:

```bash
docker compose ps
```

Open the applications:

- Dashboard: http://localhost:8501
- API documentation: http://localhost:8001/docs
- API health: http://localhost:8001/health
- API summary: http://localhost:8001/summary

Stop the services:

```bash
docker compose down
```

## Run Locally Without Docker

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Generate the ML demonstration dataset:

```bash
python src/generate_ml_data.py
```

Generate the reports:

```bash
python src/detector.py
python src/ml_detector.py
```

Run the dashboard:

```bash
streamlit run src/dashboard.py
```

Run the API in another terminal:

```bash
uvicorn src.api:app --reload --port 8001
```

## Run Tests

```bash
python -m pytest -v
```

## Detection Approach

### Rule-Based Detection

The project checks authentication event patterns, including repeated failed logins, failures across multiple usernames, and successful authentication following repeated failures.

### Machine Learning

Isolation Forest identifies unusual IP-level activity based on features such as event counts, failed logins, distinct usernames, and failure ratio.

Anomaly scores are ranking signals, not probabilities of malicious activity.

## Limitations and Responsible Use

- The included datasets are synthetic and intended for research and demonstration.
- Rule thresholds are illustrative and require tuning for real environments.
- Machine-learning anomalies are not proof of an attack.
- The model is exploratory and has not been validated against a representative labeled production dataset.
- IP addresses and login behavior must be interpreted in their operational context.
- This project is not a replacement for a production SIEM or incident-response process.
- The API is intended for local portfolio demonstrations and does not include production authentication or authorization.

## Future Improvements

- Authentication and role-based access control
- Real-time log ingestion
- Alert severity tuning
- Time-series analysis
- Model evaluation with labeled data
- Structured application logging
- CI testing with GitHub Actions

## Author

**Dhatchin Balaji**

Portfolio project focused on Python, data analysis, machine learning, and cybersecurity research.
