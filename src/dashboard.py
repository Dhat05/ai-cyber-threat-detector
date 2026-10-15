
from pathlib import Path
import ipaddress
import subprocess
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
ALERTS_FILE = BASE_DIR / "reports" / "security_alerts.csv"
ML_FILE = BASE_DIR / "reports" / "ml_anomaly_results.csv"

st.set_page_config(
    page_title="AI Cybersecurity SOC",
    page_icon="🛡️",
    layout="wide",
)

# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def load_csv(path):
    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return pd.DataFrame()


def to_number(df, columns):
    for column in columns:
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce")
    return df


def run_detection(script_name):
    script_path = BASE_DIR / "src" / script_name

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr or result.stdout or f"{script_name} failed"
        )


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

alerts = load_csv(ALERTS_FILE)
anomalies = load_csv(ML_FILE)

alerts = to_number(alerts, ["risk_score", "event_count"])
anomalies = to_number(
    anomalies,
    [
        "anomaly_score",
        "failed_logins",
        "successful_logins",
        "total_events",
        "distinct_usernames",
        "failed_ratio",
    ],
)

# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ AI Cybersecurity Threat Detection")
st.caption(
    "Security Operations Center (SOC) | "
    "Rule-Based Detection + Machine-Learning Analysis"
)

st.warning(
    "Research demo using synthetic data. Alerts and anomaly flags "
    "are signals for investigation, not proof of malicious activity."
)

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("🎛️ SOC Controls")

if st.sidebar.button("🔄 Rerun Detection", use_container_width=True):
    try:
        with st.spinner("Running detection engines..."):
            run_detection("detector.py")
            run_detection("ml_detector.py")

        st.sidebar.success("Detection completed.")
        st.rerun()

    except (RuntimeError, subprocess.TimeoutExpired) as error:
        st.sidebar.error("Detection failed.")
        st.sidebar.code(str(error))

# --------------------------------------------------
# FILTERS
# --------------------------------------------------

severity_filter = "All"
threat_filter = "All"

if not alerts.empty and "severity" in alerts.columns:
    severity_options = sorted(
        alerts["severity"].dropna().astype(str).unique().tolist()
    )

    severity_filter = st.sidebar.selectbox(
        "Severity",
        ["All"] + severity_options,
    )

if not alerts.empty and "threat_type" in alerts.columns:
    threat_options = sorted(
        alerts["threat_type"].dropna().astype(str).unique().tolist()
    )

    threat_filter = st.sidebar.selectbox(
        "Threat Type",
        ["All"] + threat_options,
    )

filtered_alerts = alerts.copy()

if not filtered_alerts.empty:
    if severity_filter != "All" and "severity" in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[
            filtered_alerts["severity"].astype(str) == severity_filter
        ]

    if threat_filter != "All" and "threat_type" in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[
            filtered_alerts["threat_type"].astype(str) == threat_filter
        ]

# --------------------------------------------------
# KPI METRICS
# --------------------------------------------------

high_count = 0
if not alerts.empty and "severity" in alerts.columns:
    high_count = int(
        (alerts["severity"].astype(str).str.upper() == "HIGH").sum()
    )

anomaly_count = 0
if not anomalies.empty and "anomaly_status" in anomalies.columns:
    anomaly_count = int(
        (
            anomalies["anomaly_status"].astype(str)
            == "ANOMALOUS_PATTERN"
        ).sum()
    )

unique_ips = 0
if not filtered_alerts.empty and "source_ip" in filtered_alerts.columns:
    unique_ips = filtered_alerts["source_ip"].nunique()

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Total Rule Alerts", len(alerts))
metric2.metric("High Severity Alerts", high_count)
metric3.metric("ML Anomaly Patterns", anomaly_count)
metric4.metric("Unique Alert IPs", unique_ips)

st.divider()

# --------------------------------------------------
# RULE-BASED ALERTS
# --------------------------------------------------

st.header("🚨 Rule-Based Security Alerts")

if filtered_alerts.empty:
    st.info("No alerts match your filters, or the report is empty.")

else:
    left, right = st.columns(2)

    if "severity" in filtered_alerts.columns:
        severity_data = (
            filtered_alerts["severity"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Count")
        )

        fig = px.bar(
            severity_data,
            x="Severity",
            y="Count",
            text="Count",
            title="Alerts by Severity",
        )
        left.plotly_chart(fig, use_container_width=True)

    if "threat_type" in filtered_alerts.columns:
        threat_data = (
            filtered_alerts["threat_type"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis("Threat Type")
            .reset_index(name="Count")
        )

        fig = px.bar(
            threat_data,
            x="Threat Type",
            y="Count",
            text="Count",
            title="Alerts by Threat Type",
        )
        right.plotly_chart(fig, use_container_width=True)

    if (
        "source_ip" in filtered_alerts.columns
        and "risk_score" in filtered_alerts.columns
    ):
        risk_data = filtered_alerts.dropna(subset=["risk_score"])

        if not risk_data.empty:
            fig = px.bar(
                risk_data,
                x="source_ip",
                y="risk_score",
                color=(
                    "severity"
                    if "severity" in risk_data.columns
                    else None
                ),
                hover_data=[
                    column
                    for column in [
                        "threat_type",
                        "description",
                        "event_count",
                    ]
                    if column in risk_data.columns
                ],
                title="Alert Risk Scores",
            )
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Alert Details")
    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "⬇️ Download Filtered Alerts",
        data=filtered_alerts.to_csv(index=False).encode("utf-8"),
        file_name="filtered_security_alerts.csv",
        mime="text/csv",
    )

# --------------------------------------------------
# IP INVESTIGATION
# --------------------------------------------------

st.divider()
st.header("🔎 IP Investigation")

st.write(
    "Enter an IP address to inspect matching rule alerts "
    "and machine-learning results."
)

ip_input = st.text_input(
    "Source IP address",
    placeholder="Example: 192.0.2.10",
).strip()

investigation_ip = None

if ip_input:
    try:
        investigation_ip = str(ipaddress.ip_address(ip_input))
    except ValueError:
        st.error("Please enter a valid IPv4 or IPv6 address.")

if investigation_ip:
    ip_alerts = pd.DataFrame()
    ip_anomalies = pd.DataFrame()

    if not alerts.empty and "source_ip" in alerts.columns:
        ip_alerts = alerts[
            alerts["source_ip"].astype(str).str.strip()
            == investigation_ip
        ]

    if not anomalies.empty and "source_ip" in anomalies.columns:
        ip_anomalies = anomalies[
            anomalies["source_ip"].astype(str).str.strip()
            == investigation_ip
        ]

    c1, c2, c3 = st.columns(3)

    c1.metric("Matching Rule Alerts", len(ip_alerts))
    c2.metric("Matching ML Records", len(ip_anomalies))

    anomaly_flag = (
        not ip_anomalies.empty
        and "anomaly_status" in ip_anomalies.columns
        and (
            ip_anomalies["anomaly_status"].astype(str)
            == "ANOMALOUS_PATTERN"
        ).any()
    )

    c3.metric(
        "ML Pattern Flag",
        "Anomalous" if anomaly_flag else "No anomaly flag",
    )

    if not ip_alerts.empty:
        st.subheader("Rule-Based Findings")
        st.dataframe(
            ip_alerts,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No matching rule alerts were found for this IP.")

    if not ip_anomalies.empty:
        st.subheader("Machine-Learning Findings")
        st.dataframe(
            ip_anomalies,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No matching IP record was found in the ML report.")

    st.caption(
        "No matching record does not mean an IP is safe. "
        "These reports contain only the events and IPs in the dataset."
    )

# --------------------------------------------------
# MACHINE-LEARNING ANOMALIES
# --------------------------------------------------

st.divider()
st.header("🤖 Machine-Learning Anomaly Analysis")

if anomalies.empty:
    st.info("No ML report found. Run detection to generate one.")

else:
    if "anomaly_status" in anomalies.columns:
        status_data = (
            anomalies["anomaly_status"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis("Pattern Status")
            .reset_index(name="Count")
        )

        fig = px.bar(
            status_data,
            x="Pattern Status",
            y="Count",
            text="Count",
            title="Normal vs Anomalous Patterns",
        )

        st.plotly_chart(fig, use_container_width=True)

    if (
        "source_ip" in anomalies.columns
        and "anomaly_score" in anomalies.columns
    ):
        ranked = anomalies.sort_values(
            "anomaly_score",
            ascending=False,
        ).head(15)

        fig = px.bar(
            ranked,
            x="source_ip",
            y="anomaly_score",
            color=(
                "anomaly_status"
                if "anomaly_status" in ranked.columns
                else None
            ),
            title="Top 15 IPs by Anomaly Score",
            hover_data=[
                column
                for column in [
                    "total_events",
                    "failed_logins",
                    "successful_logins",
                    "distinct_usernames",
                    "failed_ratio",
                ]
                if column in ranked.columns
            ],
        )

        st.plotly_chart(fig, use_container_width=True)

    st.subheader("All ML Results")
    st.dataframe(
        anomalies,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "⬇️ Download ML Results",
        data=anomalies.to_csv(index=False).encode("utf-8"),
        file_name="ml_anomaly_results.csv",
        mime="text/csv",
    )

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "AI Cybersecurity Threat Detector | Portfolio Research Project | "
    "Synthetic data only"
)
