
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException

BASE_DIR = Path(__file__).resolve().parent.parent
ALERTS_FILE = BASE_DIR / "reports" / "security_alerts.csv"
ML_FILE = BASE_DIR / "reports" / "ml_anomaly_results.csv"

app = FastAPI(
    title="AI Cybersecurity Threat Detector API",
    description=(
        "Research API for rule-based security alerts "
        "and ML anomaly results."
    ),
    version="1.0.0",
)


def read_report(path: Path) -> list[dict]:
    """Read a CSV report and return JSON-compatible records."""
    if not path.exists():
        return []

    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return []

    # Convert missing values to JSON null.
    df = df.astype(object).where(pd.notna(df), None)
    return df.to_dict(orient="records")


@app.get("/")
def home():
    return {
        "project": "AI Cybersecurity Threat Detector",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "rule_report_exists": ALERTS_FILE.exists(),
        "ml_report_exists": ML_FILE.exists(),
    }


@app.get("/alerts")
def get_alerts():
    """Return rule-based security alerts."""
    return {
        "count": len(read_report(ALERTS_FILE)),
        "alerts": read_report(ALERTS_FILE),
    }


@app.get("/anomalies")
def get_anomalies():
    """Return ML anomaly results, ranked by anomaly score."""
    results = read_report(ML_FILE)

    results.sort(
        key=lambda row: float(row.get("anomaly_score") or 0),
        reverse=True,
    )

    return {
        "count": len(results),
        "results": results,
    }


@app.get("/summary")
def get_summary():
    """Return a compact overview of both reports."""
    alerts = read_report(ALERTS_FILE)
    anomalies = read_report(ML_FILE)

    high_alerts = sum(
        1 for alert in alerts
        if alert.get("severity") == "HIGH"
    )

    anomaly_count = sum(
        1 for result in anomalies
        if result.get("anomaly_status") == "ANOMALOUS_PATTERN"
    )

    return {
        "rule_alert_count": len(alerts),
        "high_severity_alert_count": high_alerts,
        "ml_source_ip_count": len(anomalies),
        "ml_anomaly_count": anomaly_count,
        "data_mode": "synthetic_research_data",
    }
