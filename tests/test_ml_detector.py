
import pandas as pd
import pytest

from src.ml_detector import build_features, detect_anomalies


def test_empty_events_produce_empty_features():
    events = pd.DataFrame(
        columns=[
            "timestamp",
            "source_ip",
            "username",
            "event_type",
            "status",
        ]
    )

    features = build_features(events)

    assert features.empty
    assert "source_ip" in features.columns
    assert "failed_ratio" in features.columns


def test_build_features_calculates_failed_ratio():
    events = pd.DataFrame([
        {
            "source_ip": "192.0.2.10",
            "username": "arun",
            "status": "failed",
        },
        {
            "source_ip": "192.0.2.10",
            "username": "arun",
            "status": "failed",
        },
        {
            "source_ip": "192.0.2.10",
            "username": "priya",
            "status": "success",
        },
    ])

    features = build_features(events)

    assert len(features) == 1
    assert features.iloc[0]["total_events"] == 3
    assert features.iloc[0]["failed_logins"] == 2
    assert features.iloc[0]["successful_logins"] == 1
    assert features.iloc[0]["distinct_usernames"] == 2
    assert features.iloc[0]["failed_ratio"] == pytest.approx(2 / 3)


def test_single_ip_returns_insufficient_data():
    events = pd.DataFrame([
        {
            "source_ip": "192.0.2.10",
            "username": "arun",
            "status": "failed",
        },
    ])

    results = detect_anomalies(events)

    assert len(results) == 1
    assert results.iloc[0]["anomaly_status"] == "INSUFFICIENT_DATA"


def test_empty_events_produce_empty_anomaly_results():
    events = pd.DataFrame(
        columns=["source_ip", "username", "status"]
    )

    results = detect_anomalies(events)

    assert results.empty
    assert "anomaly_status" in results.columns
