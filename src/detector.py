
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "data" / "sample_auth_logs.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "security_alerts.csv"

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

PASSWORD_SPRAY_USER_THRESHOLD = 5
PASSWORD_SPRAY_WINDOW_MINUTES = 10


def load_events():
    """Load and validate authentication events."""
    df = pd.read_csv(INPUT_FILE)

    required = {
        "timestamp",
        "source_ip",
        "username",
        "event_type",
        "status",
    }

    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True
    )

    for column in ["source_ip", "username", "event_type", "status"]:
        df[column] = df[column].astype("string").str.strip()

    df["event_type"] = df["event_type"].str.lower()
    df["status"] = df["status"].str.lower()

    df = df.dropna(
        subset=["timestamp", "source_ip", "username"]
    )

    df = df[
        (df["source_ip"] != "") &
        (df["username"] != "")
    ].copy()

    return df.sort_values("timestamp").reset_index(drop=True)


def detect_brute_force(df):
    """Flag IPs with repeated failed logins in a rolling window."""
    failed = df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    alerts = []

    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        times = group["timestamp"]

        for end_idx, end_time in enumerate(times):
            start_time = end_time - pd.Timedelta(
                minutes=BRUTE_FORCE_WINDOW_MINUTES
            )
            start_idx = times.searchsorted(start_time, side="left")
            count = end_idx - start_idx + 1

            if count >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "timestamp": end_time,
                    "source_ip": ip,
                    "threat_type": "Possible Brute-Force Login",
                    "username": group.iloc[end_idx]["username"],
                    "event_count": int(count),
                    "severity": "HIGH",
                    "risk_score": 85,
                    "description": (
                        f"{count} failed logins from {ip} "
                        f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes."
                    ),
                })
                break

    return alerts


def detect_password_spraying(df):
    """Flag many distinct usernames failing from one IP in 10 minutes."""
    failed = df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    alerts = []

    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)

        for end_idx, end_row in group.iterrows():
            start_time = end_row["timestamp"] - pd.Timedelta(
                minutes=PASSWORD_SPRAY_WINDOW_MINUTES
            )

            window = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] <= end_row["timestamp"])
            ]

            unique_users = window["username"].nunique()

            if unique_users >= PASSWORD_SPRAY_USER_THRESHOLD:
                alerts.append({
                    "timestamp": end_row["timestamp"],
                    "source_ip": ip,
                    "threat_type": "Possible Password Spraying",
                    "username": "multiple",
                    "event_count": int(len(window)),
                    "severity": "HIGH",
                    "risk_score": 80,
                    "description": (
                        f"Failed logins against {unique_users} "
                        f"distinct usernames from {ip} within "
                        f"{PASSWORD_SPRAY_WINDOW_MINUTES} minutes."
                    ),
                })
                break

    return alerts


def detect_success_after_failures(df):
    """Flag success after at least 3 recent failed logins from the IP."""
    login_events = df[
        (df["event_type"] == "login")
    ].sort_values("timestamp")

    alerts = []

    for ip, group in login_events.groupby("source_ip"):
        group = group.reset_index(drop=True)

        for _, row in group[group["status"] == "success"].iterrows():
            start_time = row["timestamp"] - pd.Timedelta(minutes=5)

            previous_failures = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] < row["timestamp"]) &
                (group["status"] == "failed")
            ]

            if len(previous_failures) >= 3:
                alerts.append({
                    "timestamp": row["timestamp"],
                    "source_ip": ip,
                    "threat_type": "Success After Repeated Failures",
                    "username": row["username"],
                    "event_count": int(len(previous_failures)),
                    "severity": "HIGH",
                    "risk_score": 90,
                    "description": (
                        f"A successful login followed "
                        f"{len(previous_failures)} failed attempts "
                        f"from {ip} within the previous 5 minutes."
                    ),
                })
                break

    return alerts


def detect_threats(df):
    """Run all rules and return a unified alert table."""
    alerts = []
    alerts.extend(detect_brute_force(df))
    alerts.extend(detect_password_spraying(df))
    alerts.extend(detect_success_after_failures(df))

    columns = [
        "timestamp",
        "source_ip",
        "threat_type",
        "username",
        "event_count",
        "severity",
        "risk_score",
        "description",
    ]

    result = pd.DataFrame(alerts, columns=columns)

    if not result.empty:
        result = result.sort_values("timestamp").reset_index(drop=True)

    return result


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = load_events()
    alerts = detect_threats(events)

    alerts.to_csv(OUTPUT_FILE, index=False)

    print("\n===== AI CYBERSECURITY THREAT DETECTOR =====")
    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    if alerts.empty:
        print("No events matched the detection rules.")
    else:
        print(alerts.to_string(index=False))

    print(f"\nReport saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
