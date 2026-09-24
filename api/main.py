from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import joblib
from pathlib import Path


app = FastAPI(title="Network Detection API")


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_FILE = BASE_DIR / "data" / "raw" / "final_detection_results.csv"

RF_MODEL = BASE_DIR / "models" / "random_forest_classifier.pkl"
IF_MODEL = BASE_DIR / "models" / "isolation_forest.pkl"


# =========================================================
# LOAD MODELS
# =========================================================

random_forest = joblib.load(RF_MODEL)
isolation_forest = joblib.load(IF_MODEL)


# =========================================================
# FEATURES
# =========================================================

FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "smean",
    "dmean",
]


# =========================================================
# LOAD DATA
# =========================================================

def load_results():
    return pd.read_csv(RESULTS_FILE)


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return {
        "message": "Network Detection API",
        "status": "running"
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "random_forest": "loaded",
        "isolation_forest": "loaded"
    }


# =========================================================
# STATS
# =========================================================

@app.get("/stats")
def get_stats():

    df = load_results()

    total = len(df)

    attack_count = int(
        (
            df["prediction_label"]
            .astype(str)
            .str.lower()
            == "attack"
        ).sum()
    )

    normal_count = total - attack_count

    critical_count = 0

    if "attack_probability" in df.columns:
        probabilities = pd.to_numeric(
            df["attack_probability"],
            errors="coerce"
        ).fillna(0)

        critical_count = int(
            (probabilities >= 0.90).sum()
        )

    return {
        "totalPackets": total,
        "normalTraffic": normal_count,
        "anomalies": attack_count,
        "criticalThreats": critical_count
    }


# =========================================================
# ANOMALIES
# =========================================================

@app.get("/anomalies")
def get_anomalies():

    df = load_results()

    df = df[
        df["prediction_label"]
        .astype(str)
        .str.lower()
        .eq("attack")
    ]

    results = []

    for index, row in df.head(100).iterrows():

        probability = float(
            row.get("attack_probability", 0)
        )

        score = round(probability * 100)

        if score >= 90:
            severity = "Critical"
        elif score >= 75:
            severity = "High"
        elif score >= 50:
            severity = "Medium"
        else:
            severity = "Low"

        attack_type = str(
            row.get(
                "attack_type",
                "Other ML Attack"
            )
        )

        results.append({
            "id": int(index + 1),
            "time": "--",
            "timestamp": "--",

            "source": str(
                row.get("src_ip", "")
            ),

            "destination": str(
                row.get("dst_ip", "")
            ),

            "protocol": str(
                row.get("proto", "")
            ).upper(),

            "type": attack_type,

            "score": score,

            "severity": severity,

            "status": "Detected",

            "srcPort": int(
                row.get("src_port", 0)
            ),

            "dstPort": int(
                row.get("dst_port", 0)
            ),

            "packetSize": int(
                row.get("sbytes", 0)
                +
                row.get("dbytes", 0)
            ),

            "reason": (
                "Random Forest classified "
                "this flow as an attack."
            )
        })

    return results


# =========================================================
# PACKETS / FLOWS
# =========================================================

@app.get("/packets")
def get_packets():

    df = load_results()

    results = []

    # IMPORTANT:
    # Return ALL flows, not only first 100.
    for index, row in df.iterrows():

        probability = float(
            row.get(
                "attack_probability",
                0
            )
        )

        score = round(
            probability * 100
        )

        prediction = str(
            row.get(
                "prediction_label",
                "Normal"
            )
        )

        status = (
            "Anomaly"
            if prediction.lower() == "attack"
            else "Normal"
        )

        results.append({
            "id": int(index + 1),

            "timestamp": "--",

            "src_ip": str(
                row.get("src_ip", "")
            ),

            "dst_ip": str(
                row.get("dst_ip", "")
            ),

            "protocol": str(
                row.get("proto", "")
            ).upper(),

            "src_port": int(
                row.get("src_port", 0)
            ),

            "dst_port": int(
                row.get("dst_port", 0)
            ),

            "packet_size": int(
                row.get("sbytes", 0)
                +
                row.get("dbytes", 0)
            ),

            "status": status,

            "score": score
        })

    return results


# =========================================================
# ANALYTICS
# =========================================================

@app.get("/analytics")
def get_analytics():

    df = load_results()

    total = len(df)

    attacks = int(
        (
            df["prediction_label"]
            .astype(str)
            .str.lower()
            == "attack"
        ).sum()
    )

    normal = total - attacks


    # -----------------------------------------------------
    # PROTOCOL DATA
    # -----------------------------------------------------

    protocol_data = []

    if "proto" in df.columns:

        protocol_counts = (
            df["proto"]
            .astype(str)
            .str.upper()
            .value_counts()
        )

        for protocol, count in protocol_counts.items():

            protocol_data.append({
                "name": protocol,
                "value": int(count)
            })


    # -----------------------------------------------------
    # SEVERITY DATA
    # -----------------------------------------------------

    severity_data = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    if "prediction_label" in df.columns:

        attack_df = df[
            df["prediction_label"]
            .astype(str)
            .str.lower()
            .eq("attack")
        ]

        for probability in pd.to_numeric(
            attack_df["attack_probability"],
            errors="coerce"
        ).fillna(0):

            score = probability * 100

            if score >= 90:
                severity_data["Critical"] += 1

            elif score >= 75:
                severity_data["High"] += 1

            elif score >= 50:
                severity_data["Medium"] += 1

            else:
                severity_data["Low"] += 1


    severity_list = [
        {
            "name": key,
            "value": value
        }
        for key, value in severity_data.items()
    ]


    # -----------------------------------------------------
    # TRAFFIC DATA
    # -----------------------------------------------------

    traffic = [
        {
            "time": "PCAP",
            "packets": total,
            "normal": normal,
            "anomaly": attacks
        }
    ]


    return {
        "traffic": traffic,

        "anomalies": attacks,

        "protocolData": protocol_data,

        "severityData": severity_list
    }


# =========================================================
# NETWORK STATS
# =========================================================

@app.get("/network-stats")
def network_stats():

    return get_stats()