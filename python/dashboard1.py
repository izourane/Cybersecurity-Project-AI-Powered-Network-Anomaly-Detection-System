import streamlit as st
import pandas as pd
import plotly.express as px
import time
import json
from pathlib import Path


# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(

    page_title=
        "AI Network IDS",

    page_icon=
        "🛡️",

    layout=
        "wide",
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

st_autorefresh = st.empty()

# ---------------------------------------------------
# TITLE
# ---------------------------------------------------

st.title(
    "🛡️ AI-Powered Network Detection System"
)

st.markdown(
    """
Real-time behavioral anomaly detection
using Isolation Forest.
"""
)

# ---------------------------------------------------
# LOAD ALERTS
# ---------------------------------------------------

alerts_file = Path(
    "alerts.json"
)

if alerts_file.exists():

    with open(
        alerts_file,
        "r"
    ) as f:

        alerts = json.load(f)

else:

    alerts = []

# ---------------------------------------------------
# DATAFRAME
# ---------------------------------------------------

df = pd.DataFrame(alerts)

# ---------------------------------------------------
# EMPTY CASE
# ---------------------------------------------------

if df.empty:

    st.warning(
        "No anomalies detected yet."
    )

    st.stop()

# ---------------------------------------------------
# METRICS
# ---------------------------------------------------

metric1, metric2, metric3, metric4 = (
    st.columns(4)
)

metric1.metric(
    "Total Alerts",
    len(df)
)

metric2.metric(
    "Critical Alerts",
    len(
        df[df["severity"] == "CRITICAL"]
    )
)

metric3.metric(
    "High Alerts",
    len(
        df[df["severity"] == "HIGH"]
    )
)

metric4.metric(
    "Latest Risk Score",
    df.iloc[-1]["risk_score"]
)

# ---------------------------------------------------
# CHARTS
# ---------------------------------------------------

col1, col2 = st.columns(2)

# Risk score timeline
fig_risk = px.line(

    df,

    x="timestamp",

    y="risk_score",

    color="severity",

    title=
        "Anomaly Risk Timeline",
)

col1.plotly_chart(
    fig_risk,
    use_container_width=True
)

# Protocol distribution
proto_count = (

    df["protocol"]
    .value_counts()
    .reset_index()

)

proto_count.columns = [
    "Protocol",
    "Count"
]

fig_proto = px.pie(

    proto_count,

    names="Protocol",

    values="Count",

    title=
        "Threat Protocol Distribution",
)

col2.plotly_chart(
    fig_proto,
    use_container_width=True
)

# ---------------------------------------------------
# TOP ATTACKERS
# ---------------------------------------------------

st.subheader(
    "🌐 Top Suspicious Source IPs"
)

top_ips = (

    df["src_ip"]
    .value_counts()
    .head(10)
    .reset_index()

)

top_ips.columns = [
    "Source IP",
    "Alerts"
]

fig_ips = px.bar(

    top_ips,

    x="Source IP",

    y="Alerts",

    title=
        "Top Suspicious Hosts",
)

st.plotly_chart(
    fig_ips,
    use_container_width=True
)

# ---------------------------------------------------
# ALERT TABLE
# ---------------------------------------------------

st.subheader(
    "🚨 Threat Alerts"
)

st.dataframe(

    df.sort_values(
        by="timestamp",
        ascending=False
    ),

    use_container_width=True
)

# ---------------------------------------------------
# SEVERITY COLORS
# ---------------------------------------------------

severity_count = (

    df["severity"]
    .value_counts()
    .reset_index()

)

severity_count.columns = [
    "Severity",
    "Count"
]

fig_severity = px.bar(

    severity_count,

    x="Severity",

    y="Count",

    title=
        "Threat Severity Levels",
)

st.plotly_chart(
    fig_severity,
    use_container_width=True
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

time.sleep(2)

st.rerun()