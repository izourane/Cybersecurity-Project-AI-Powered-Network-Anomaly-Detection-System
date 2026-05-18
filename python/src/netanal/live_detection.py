"""
live_detection.py

Real-time anomaly detection engine.
"""

import joblib
import numpy as np
import pandas as pd


class LiveAnomalyDetector:

    def __init__(self):

        self.model = joblib.load(
            "src/netanal/isolation_forest_model.pkl"
        )

        self.scaler = joblib.load(
            "src/netanal/scaler.pkl"
        )

        self.imputer = joblib.load(
            "src/netanal/imputer.pkl"
        )

    def predict(self, feature_dict):

        features = pd.DataFrame([{

            "packet_size":
                feature_dict["packet_size"],

            "protocol_frequency":
                feature_dict["protocol_frequency"],

            "packets_per_source":
                feature_dict["packets_per_source"],

            "unique_destinations":
                feature_dict["unique_destinations"],

            "is_arp":
                feature_dict["is_arp"],

            "is_dns":
                feature_dict["is_dns"],

            "is_tcp":
                feature_dict["is_tcp"],
        }])

        # preprocessing
        features = self.imputer.transform(features)

        features = self.scaler.transform(features)

        # prediction
        prediction = self.model.predict(features)[0]

        score = self.model.decision_function(
            features
        )[0]

        return prediction, score