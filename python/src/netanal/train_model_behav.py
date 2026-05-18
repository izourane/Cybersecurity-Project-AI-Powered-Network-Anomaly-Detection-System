"""
train_model.py

Train Isolation Forest model using
behavioral network traffic features.
"""

import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------
# Load behavioral dataset
# ---------------------------------------------------

df = pd.read_csv("src/netanal/behavioral_dataset.csv")

print("\nDataset loaded.")
print(f"Samples: {len(df)}")


# ---------------------------------------------------
# Select behavioral features
# ---------------------------------------------------

FEATURE_COLUMNS = [

    # Basic traffic
    "packet_size",

    # Protocol behavior
    "protocol_frequency",

    # Source behavior
    "packets_per_source",
    "unique_destinations",

    # Protocol indicators
    "is_arp",
    "is_dns",
    "is_tcp",
]

X = df[FEATURE_COLUMNS]


# ---------------------------------------------------
# Handle missing values
# ---------------------------------------------------

imputer = SimpleImputer(strategy="median")

X = imputer.fit_transform(X)


# ---------------------------------------------------
# Feature scaling
# ---------------------------------------------------

scaler = StandardScaler()

X = scaler.fit_transform(X)


# ---------------------------------------------------
# Train Isolation Forest
# ---------------------------------------------------

print("\nTraining Isolation Forest model...")

model = IsolationForest(

    n_estimators=150,

    contamination=0.01,

    random_state=42,

    n_jobs=-1,
)

model.fit(X)


# ---------------------------------------------------
# Predict anomalies
# ---------------------------------------------------

predictions = model.predict(X)

scores = model.decision_function(X)

df["anomaly"] = predictions
df["anomaly_score"] = scores


# ---------------------------------------------------
# Extract anomalies
# ---------------------------------------------------

anomalies = df[df["anomaly"] == -1]

print("\n=== TRAINING COMPLETE ===")

print(f"Total samples: {len(df)}")

print(f"Detected anomalies: {len(anomalies)}")

print(
    f"Anomaly percentage: "
    f"{(len(anomalies)/len(df))*100:.2f}%"
)


# ---------------------------------------------------
# Show top suspicious traffic
# ---------------------------------------------------

print("\nTop suspicious traffic:\n")

print(

    anomalies[
        [
            "packet_size",
            "packets_per_source",
            "unique_destinations",
            "anomaly_score",
        ]
    ].head(10)

)


# ---------------------------------------------------
# Save trained artifacts
# ---------------------------------------------------

joblib.dump(
    model,
    "src/netanal/isolation_forest_model.pkl"
)

joblib.dump(
    scaler,
    "src/netanal/scaler.pkl"
)

joblib.dump(
    imputer,
    "src/netanal/imputer.pkl"
)

print("\nModel saved successfully.")