
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "ml_auth_logs.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "ml_anomaly_results.csv"

FEATURE_COLUMNS = [
    "total_events",
    "failed_logins",
    "successful_logins",
    "distinct_usernames",
    "failed_ratio",
]


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """Build numeric features grouped by source IP."""

    output_columns = ["source_ip", *FEATURE_COLUMNS]

    if events is None or events.empty:
        return pd.DataFrame(columns=output_columns)

    required = {"source_ip", "username", "status"}
    missing = required - set(events.columns)

    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df = events.copy()

    df["source_ip"] = df["source_ip"].astype("string")
    df["username"] = df["username"].astype("string")
    df["status"] = df["status"].astype("string").str.strip().str.lower()

    df = df.dropna(subset=["source_ip"])

    if df.empty:
        return pd.DataFrame(columns=output_columns)

    df["_failed"] = df["status"].eq("failed").astype("int64")
    df["_success"] = df["status"].eq("success").astype("int64")

    features = (
        df.groupby("source_ip")
        .agg(
            total_events=("status", "size"),
            failed_logins=("_failed", "sum"),
            successful_logins=("_success", "sum"),
            distinct_usernames=("username", "nunique"),
        )
        .reset_index()
    )

    numeric_columns = [
        "total_events",
        "failed_logins",
        "successful_logins",
        "distinct_usernames",
    ]

    for column in numeric_columns:
        features[column] = pd.to_numeric(
            features[column],
            errors="coerce",
        ).fillna(0)

    denominator = features["total_events"].where(
        features["total_events"] != 0
    )

    features["failed_ratio"] = (
        features["failed_logins"].div(denominator).fillna(0.0)
    )

    features[FEATURE_COLUMNS] = (
        features[FEATURE_COLUMNS]
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0.0)
    )

    return features[output_columns]


def detect_anomalies(
    events: pd.DataFrame,
    contamination: float = 0.10,
    random_state: int = 42,
) -> pd.DataFrame:
    """Flag unusual IP activity patterns for further investigation."""

    features = build_features(events)

    output_columns = [
        *features.columns,
        "anomaly_score",
        "anomaly_status",
    ]

    if features.empty:
        return pd.DataFrame(columns=output_columns)

    result = features.copy()
    X = result[FEATURE_COLUMNS].astype("float64")

    if len(result) < 2:
        result["anomaly_score"] = 0.0
        result["anomaly_status"] = "INSUFFICIENT_DATA"
        return result

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )

    model.fit(X)

    result["anomaly_score"] = -model.score_samples(X)

    predictions = model.predict(X)

    result["anomaly_status"] = [
        "ANOMALOUS_PATTERN" if value == -1 else "NORMAL_PATTERN"
        for value in predictions
    ]

    return result


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {INPUT_FILE}")

    events = pd.read_csv(INPUT_FILE)
    results = detect_anomalies(events)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_FILE, index=False)

    print(f"Input events: {len(events)}")
    print(f"IP patterns analysed: {len(results)}")
    print(f"Results saved to: {OUTPUT_FILE}")

    if not results.empty:
        print("\nAnomaly status counts:")
        print(results["anomaly_status"].value_counts())


if __name__ == "__main__":
    main()
