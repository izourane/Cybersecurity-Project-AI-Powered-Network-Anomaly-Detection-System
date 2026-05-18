"""
prepare_dataset.py

Generate behavioral features
from packet-level traffic.
"""

import pandas as pd


df = pd.read_csv("src/netanal/network_traffic.csv")


# ---------------------------------------------------
# Basic features
# ---------------------------------------------------

df["packet_size"] = df["Length"]

# Encode protocol frequency
protocol_counts = df["Protocol"].value_counts()

df["protocol_frequency"] = (
    df["Protocol"]
    .map(protocol_counts)
)

# Packets per source
source_counts = df["Source"].value_counts()

df["packets_per_source"] = (
    df["Source"]
    .map(source_counts)
)

# Unique destinations per source
unique_destinations = (
    df.groupby("Source")["Destination"]
    .nunique()
)

df["unique_destinations"] = (
    df["Source"]
    .map(unique_destinations)
)

# ARP detection
df["is_arp"] = (
    df["Protocol"] == "ARP"
).astype(int)

# DNS detection
df["is_dns"] = (
    df["Protocol"] == "DNS"
).astype(int)

# TCP detection
df["is_tcp"] = (
    df["Protocol"] == "TCP"
).astype(int)


# ---------------------------------------------------
# Save enriched dataset
# ---------------------------------------------------

df.to_csv(
    "src/netanal/behavioral_dataset.csv",
    index=False
)

print("Behavioral dataset generated.")