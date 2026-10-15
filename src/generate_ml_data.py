
from pathlib import Path
import random
import pandas as pd

random.seed(42)

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "ml_auth_logs.csv"

rows = []
start = pd.Timestamp("2026-10-15T08:00:00Z")

# Generate ordinary login activity from 40 synthetic IPs.
for ip_num in range(40):
    ip = f"10.10.{ip_num // 250}.{ip_num % 250 + 1}"
    username = f"user_{ip_num:02d}"

    for _ in range(20):
        timestamp = start + pd.Timedelta(
            seconds=random.randint(0, 3600)
        )
        status = random.choices(
            ["success", "failed"], weights=[0.90, 0.10]
        )[0]

        rows.append({
            "timestamp": timestamp,
            "source_ip": ip,
            "username": username,
            "event_type": "login",
            "status": status,
        })

# Add a burst of failed logins from one synthetic IP.
for attempt in range(30):
    rows.append({
        "timestamp": start + pd.Timedelta(
            minutes=20, seconds=attempt * 5
        ),
        "source_ip": "198.51.100.200",
        "username": "target_user",
        "event_type": "login",
        "status": "failed",
    })

# Add failed logins against multiple usernames from another IP.
for index in range(12):
    rows.append({
        "timestamp": start + pd.Timedelta(
            minutes=30, seconds=index * 20
        ),
        "source_ip": "198.51.100.201",
        "username": f"target_{index}",
        "event_type": "login",
        "status": "failed",
    })

df = pd.DataFrame(rows).sort_values("timestamp")
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print(f"Generated {len(df)} synthetic events.")
print(f"Saved to: {OUTPUT_FILE}")
print("Dataset is simulated; it is not real-world security telemetry.")
