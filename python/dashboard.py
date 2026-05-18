import streamlit as st
import pandas as pd
import random
import time
from collections import deque
import plotly.express as px


# ---------------------------------------------------
# Streamlit config
# ---------------------------------------------------

st.set_page_config(
    page_title="AI Network IDS",
    layout="wide"
)

st.title("🛡️ AI-Powered Network Anomaly Detection")

st.markdown(
    "Real-time behavioral network monitoring"
)

# ---------------------------------------------------
# Live data storage
# ---------------------------------------------------

if "scores" not in st.session_state:
    st.session_state.scores = deque(maxlen=100)

if "packets" not in st.session_state:
    st.session_state.packets = 0

if "anomalies" not in st.session_state:
    st.session_state.anomalies = 0

if "protocols" not in st.session_state:
    st.session_state.protocols = []

# ---------------------------------------------------
# Metrics
# ---------------------------------------------------

col1, col2, col3 = st.columns(3)

metric_packets = col1.empty()
metric_anomalies = col2.empty()
metric_ratio = col3.empty()

# ---------------------------------------------------
# Charts placeholders
# ---------------------------------------------------

score_chart = st.empty()

protocol_chart = st.empty()

alerts_box = st.empty()

# ---------------------------------------------------
# Simulated live feed
# ---------------------------------------------------

while True:

    # Fake traffic data
    packet_count = random.randint(50, 150)

    anomaly_score = random.uniform(-0.05, 0.1)

    protocol = random.choice(
        ["TCP", "UDP", "DNS", "HTTPS", "ARP"]
    )

    # Update stats
    st.session_state.packets += packet_count

    st.session_state.scores.append(
        anomaly_score
    )

    st.session_state.protocols.append(
        protocol
    )

    # Detect anomaly
    is_anomaly = anomaly_score < 0

    if is_anomaly:
        st.session_state.anomalies += 1

    # ---------------------------------------------------
    # Update metrics
    # ---------------------------------------------------

    ratio = (
        st.session_state.anomalies
        / max(st.session_state.packets, 1)
    ) * 100

    metric_packets.metric(
        "Packets",
        st.session_state.packets
    )

    metric_anomalies.metric(
        "Anomalies",
        st.session_state.anomalies
    )

    metric_ratio.metric(
        "Anomaly Ratio",
        f"{ratio:.2f}%"
    )

    # ---------------------------------------------------
    # Risk score chart
    # ---------------------------------------------------

    df_scores = pd.DataFrame({

        "Index":
            list(range(
                len(st.session_state.scores)
            )),

        "Score":
            list(
                st.session_state.scores
            )
    })

    fig_scores = px.line(

        df_scores,

        x="Index",

        y="Score",

        title="Live Anomaly Scores"
    )

    score_chart.plotly_chart(
        fig_scores,
        use_container_width=True
    )

    # ---------------------------------------------------
    # Protocol distribution
    # ---------------------------------------------------

    proto_df = pd.DataFrame({

        "Protocol":
            st.session_state.protocols
    })

    proto_count = (
        proto_df["Protocol"]
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

        title="Protocol Distribution"
    )

    protocol_chart.plotly_chart(
        fig_proto,
        use_container_width=True
    )

    # ---------------------------------------------------
    # Alerts
    # ---------------------------------------------------

    if is_anomaly:

        alerts_box.warning(

            f"⚠️ Anomaly detected "
            f"(score={anomaly_score:.4f}) "
            f"Protocol={protocol}"
        )

    else:

        alerts_box.success(
            "Traffic normal"
        )

    # ---------------------------------------------------
    # Refresh
    # ---------------------------------------------------

    time.sleep(1)