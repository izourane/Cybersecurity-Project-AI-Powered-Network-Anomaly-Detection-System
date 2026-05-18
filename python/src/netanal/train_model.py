"""
train_model.py

Train Isolation Forest model for
network anomaly detection.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
import joblib


# ---------------------------------------------------
# Load dataset
# ---------------------------------------------------

df = pd.read_csv("src/netanal/network_traffic.csv")


# ---------------------------------------------------
# Keep useful columns
# ---------------------------------------------------

df = df[
    [
        "Protocol",
        "Length",
        "Source",
        "Destination",
    ]
]


# ---------------------------------------------------
# Encode categorical data
# ---------------------------------------------------

protocol_encoder = LabelEncoder()
source_encoder = LabelEncoder()
dest_encoder = LabelEncoder()

df["Protocol"] = protocol_encoder.fit_transform(
    df["Protocol"].astype(str)
)

df["Source"] = source_encoder.fit_transform(
    df["Source"].astype(str)
)

df["Destination"] = dest_encoder.fit_transform(
    df["Destination"].astype(str)
)


# ---------------------------------------------------
# Feature matrix
# ---------------------------------------------------

X = df.values


# ---------------------------------------------------
# Handle missing values
# ---------------------------------------------------

imputer = SimpleImputer(strategy="mean")
X = imputer.fit_transform(X)


# ---------------------------------------------------
# Train Isolation Forest
# ---------------------------------------------------

model = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42,
)

model.fit(X)


# ---------------------------------------------------
# Generate anomaly scores
# ---------------------------------------------------

scores = model.decision_function(X)
predictions = model.predict(X)

df["anomaly"] = predictions
df["anomaly_score"] = scores


# ---------------------------------------------------
# Save results
# ---------------------------------------------------

joblib.dump(model, "src/netanal/isolation_forest_model.pkl")
joblib.dump(protocol_encoder, "src/netanal/protocol_encoder.pkl")
joblib.dump(source_encoder, "src/netanal/source_encoder.pkl")
joblib.dump(dest_encoder, "src/netanal/dest_encoder.pkl")
joblib.dump(imputer, "src/netanal/imputer.pkl")


# ---------------------------------------------------
# Show statistics
# ---------------------------------------------------

anomalies = df[df["anomaly"] == -1]

print("\n=== TRAINING COMPLETE ===")
print(f"Total samples: {len(df)}")
print(f"Anomalies detected: {len(anomalies)}")

print("\nTop anomalies:")
print(
    anomalies[
        [
            "Length",
            "anomaly_score",
        ]
    ].head(10)
)