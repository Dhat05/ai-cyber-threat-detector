
import pandas as pd

from src.detector import detect_threats


def make_events(records):
    df = pd.DataFrame(
        records,
        columns=[
            "timestamp",
            "source_ip",
            "username",
            "event_type",
            "status",
        ],
    )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        utc=True,
    )

    return df


def test_detects_five_failures_within_five_minutes():
    events = make_events([
        ("2026-10-15T09:00:00Z", "192.0.2.10", "arun", "login", "failed"),
        ("2026-10-15T09:01:00Z", "192.0.2.10", "arun", "login", "failed"),
        ("2026-10-15T09:02:00Z", "192.0.2.10", "arun", "login", "failed"),
        ("2026-10-15T09:03:00Z", "192.0.2.10", "arun", "login", "failed"),
        ("2026-10-15T09:04:00Z", "192.0.2.10", "arun", "login", "failed"),
    ])

    alerts = detect_threats(events)

    assert len(alerts) == 1
    assert alerts.iloc[0]["source_ip"] == "192.0.2.10"
    assert alerts.iloc[0]["event_count"] == 5


def test_does_not_flag_four_failures():
    events = make_events([
        ("2026-10-15T09:00:00Z", "192.0.2.20", "priya", "login", "failed"),
        ("2026-10-15T09:01:00Z", "192.0.2.20", "priya", "login", "failed"),
        ("2026-10-15T09:02:00Z", "192.0.2.20", "priya", "login", "failed"),
        ("2026-10-15T09:03:00Z", "192.0.2.20", "priya", "login", "failed"),
    ])

    alerts = detect_threats(events)

    assert alerts.empty


def test_does_not_flag_successful_logins():
    events = make_events([
        ("2026-10-15T09:00:00Z", "192.0.2.30", "vignesh", "login", "success"),
        ("2026-10-15T09:01:00Z", "192.0.2.30", "vignesh", "login", "success"),
    ])

    alerts = detect_threats(events)

    assert alerts.empty
