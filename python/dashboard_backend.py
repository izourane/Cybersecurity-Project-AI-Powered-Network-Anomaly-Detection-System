import random
import time
from datetime import datetime


PROTOCOLS = [
    "TCP",
    "UDP",
    "DNS",
    "HTTPS",
    "ARP"
]


SEVERITIES = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]


def generate_live_data():

    anomaly_score = round(
        random.uniform(-0.05, 0.1),
        4
    )

    is_anomaly = anomaly_score < 0

    protocol = random.choice(
        PROTOCOLS
    )

    packet_size = random.randint(
        40,
        1500
    )

    src_ip = (
        f"192.168.1."
        f"{random.randint(1,254)}"
    )

    dst_ip = (
        f"172.22.106."
        f"{random.randint(1,254)}"
    )

    severity = "NORMAL"

    if anomaly_score < -0.04:
        severity = "CRITICAL"

    elif anomaly_score < -0.02:
        severity = "HIGH"

    elif anomaly_score < -0.01:
        severity = "MEDIUM"

    elif anomaly_score < 0:
        severity = "LOW"

    return {

        "timestamp":
            datetime.now()
            .strftime("%H:%M:%S"),

        "packet_size":
            packet_size,

        "protocol":
            protocol,

        "src_ip":
            src_ip,

        "dst_ip":
            dst_ip,

        "anomaly_score":
            anomaly_score,

        "is_anomaly":
            is_anomaly,

        "severity":
            severity,
    }