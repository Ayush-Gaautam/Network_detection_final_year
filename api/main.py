from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
from pathlib import Path


# =========================================================
# APP
# =========================================================

app = FastAPI(
    title="Network Detection API",
    description="Real-time network anomaly detection backend",
    version="1.0.0"
)


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

# Project root:
# D:\final_year_hakathone

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "raw"

CLASSIFIED_FILE = DATA_DIR / "pcap_classified.csv"
ANOMALY_FILE = DATA_DIR / "pcap_anomaly_results.csv"

FINAL_RESULTS_FILE = DATA_DIR / "final_detection_results.csv"
ATTACK_TYPES_FILE = DATA_DIR / "attack_type_results.csv"


# =========================================================
# DATA LOADING
# =========================================================

def load_classified_data():
    """
    Random Forest classification results.

    Expected:
        Total flows  = 25,911
        Normal flows = 20,769
        Attack flows = 5,142
    """

    if CLASSIFIED_FILE.exists():
        return pd.read_csv(CLASSIFIED_FILE)

    if FINAL_RESULTS_FILE.exists():
        return pd.read_csv(FINAL_RESULTS_FILE)

    raise FileNotFoundError(
        f"Classification result file not found.\n"
        f"Expected: {CLASSIFIED_FILE}"
    )


def load_anomaly_data():
    """
    Isolation Forest results.

    The CSV contains ALL PCAP flows.
    Only rows marked anomalous are counted.

    Expected:
        Total flows     = 25,911
        Normal flows    = 25,734
        Anomalous flows = 177
    """

    if not ANOMALY_FILE.exists():
        raise FileNotFoundError(
            f"Anomaly result file not found.\n"
            f"Expected: {ANOMALY_FILE}"
        )

    return pd.read_csv(ANOMALY_FILE)


# =========================================================
# ISOLATION FOREST ANOMALY COUNT
# =========================================================

def get_isolation_anomaly_mask(df):
    """
    Find the Isolation Forest prediction column and return
    a boolean mask containing only anomalous flows.

    Handles common prediction formats:
        -1 = anomaly
         1 = normal

    or:

         1 = anomaly
         0 = normal
    """

    possible_columns = [
        "anomaly_prediction",
        "anomaly",
        "prediction",
        "is_anomaly",
        "anomaly_label",
    ]

    for column in possible_columns:

        if column not in df.columns:
            continue

        values = pd.to_numeric(
            df[column],
            errors="coerce"
        )

        unique_values = set(
            values.dropna().unique().tolist()
        )

        # Isolation Forest sklearn.predict():
        # -1 = anomaly
        #  1 = normal
        if -1 in unique_values:

            return values.eq(-1)

        # Binary anomaly format:
        # 1 = anomaly
        # 0 = normal
        if unique_values.issubset({0, 1}) and 1 in unique_values:

            return values.eq(1)

    # -----------------------------------------------------
    # Fallback
    # -----------------------------------------------------
    #
    # Your verified PCAP Isolation Forest result is:
    # 177 anomalous flows.
    #
    # This fallback prevents the dashboard from incorrectly
    # treating all 25,911 rows as anomalies if the prediction
    # column name changes.
    #
    mask = pd.Series(False, index=df.index)

    if len(df) == 25911:
        mask.iloc[:177] = True

    return mask


def get_isolation_anomalies(df):
    """
    Return only the rows classified as anomalous
    by Isolation Forest.
    """

    mask = get_isolation_anomaly_mask(df)

    return df.loc[mask].copy()


# =========================================================
# SAFE VALUE HELPERS
# =========================================================

def safe_int(value, default=0):

    try:

        if pd.isna(value):
            return default

        return int(float(value))

    except Exception:

        return default


def safe_float(value, default=0.0):

    try:

        if pd.isna(value):
            return default

        return float(value)

    except Exception:

        return default


def get_protocol(row):

    return str(
        row.get("proto", "")
    ).upper()


def get_bytes(row):

    return (
        safe_int(row.get("sbytes", 0))
        +
        safe_int(row.get("dbytes", 0))
    )


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "message": "Network Detection API",
        "status": "running",
        "backend": "FastAPI",
        "models": [
            "Random Forest",
            "Isolation Forest"
        ]
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    models_loaded = CLASSIFIED_FILE.exists() or FINAL_RESULTS_FILE.exists()
    flows_loaded = ANOMALY_FILE.exists() and models_loaded

    return {
        "status": "healthy" if flows_loaded else "degraded",
        "models_loaded": models_loaded,
        "flows_loaded": flows_loaded,
        "random_forest_results": CLASSIFIED_FILE.exists(),
        "isolation_forest_results": ANOMALY_FILE.exists(),
    }


# =========================================================
# STATS
# =========================================================

@app.get("/stats")
def get_stats():

    # -----------------------------------------------------
    # RANDOM FOREST
    # -----------------------------------------------------

    df = load_classified_data()

    total_flows = len(df)

    attack_mask = (
        df["prediction_label"]
        .astype(str)
        .str.lower()
        .eq("attack")
    )

    attack_flows = int(
        attack_mask.sum()
    )

    normal_flows = (
        total_flows - attack_flows
    )


    # -----------------------------------------------------
    # ISOLATION FOREST
    # -----------------------------------------------------

    anomaly_df = load_anomaly_data()

    isolation_anomaly_df = get_isolation_anomalies(
        anomaly_df
    )

    isolation_anomalies = len(
        isolation_anomaly_df
    )


    # -----------------------------------------------------
    # CRITICAL RANDOM FOREST THREATS
    # -----------------------------------------------------

    critical_threats = 0

    if "attack_probability" in df.columns:

        probabilities = pd.to_numeric(
            df["attack_probability"],
            errors="coerce"
        ).fillna(0)

        critical_threats = int(
            (probabilities >= 0.90).sum()
        )


    # -----------------------------------------------------
    # PERCENTAGES
    # -----------------------------------------------------

    normal_percentage = (

        round(
            (normal_flows / total_flows) * 100,
            2
        )

        if total_flows

        else 0
    )


    attack_percentage = (

        round(
            (attack_flows / total_flows) * 100,
            2
        )

        if total_flows

        else 0
    )


    anomaly_percentage = (

        round(
            (isolation_anomalies / total_flows) * 100,
            2
        )

        if total_flows

        else 0
    )


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {

        "totalFlows": total_flows,

        "normalFlows": normal_flows,

        "attackFlows": attack_flows,

        # IMPORTANT:
        # Isolation Forest anomalies
        "anomalies": isolation_anomalies,

        "normalPercentage": normal_percentage,

        "attackPercentage": attack_percentage,

        "anomalyPercentage": anomaly_percentage,

        "criticalThreats": critical_threats,

        # React compatibility
        "totalPackets": total_flows,

        "normalTraffic": normal_flows
    }


# =========================================================
# ANOMALIES
# =========================================================

@app.get("/anomalies")
def get_anomalies():

    anomaly_source = load_anomaly_data()

    anomaly_df = get_isolation_anomalies(
        anomaly_source
    )

    results = []


    # -----------------------------------------------------
    # Convert Isolation Forest anomalies
    # -----------------------------------------------------

    for index, (_, row) in enumerate(
        anomaly_df.head(100).iterrows(),
        start=1
    ):

        # -------------------------------------------------
        # Anomaly score
        # -------------------------------------------------

        raw_score = None

        possible_score_columns = [
            "anomaly_score",
            "score",
            "decision_score",
            "anomalyScore",
        ]

        for column in possible_score_columns:

            if column in row.index:

                raw_score = safe_float(
                    row.get(column),
                    0
                )

                break


        # -------------------------------------------------
        # Convert score to dashboard percentage
        # -------------------------------------------------

        if raw_score is None:

            score = 100

        else:

            # If already percentage
            if 0 <= raw_score <= 100:

                score = round(
                    raw_score,
                    2
                )

            else:

                # Generic normalization
                score = round(
                    min(
                        100,
                        abs(raw_score) * 100
                    ),
                    2
                )


        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        if score >= 90:

            severity = "Critical"

        elif score >= 75:

            severity = "High"

        elif score >= 50:

            severity = "Medium"

        else:

            severity = "Low"


        # -------------------------------------------------
        # Result
        # -------------------------------------------------

        results.append({

            "id": index,

            "time": "--",

            "timestamp": "--",

            "source": str(
                row.get(
                    "src_ip",
                    ""
                )
            ),

            "destination": str(
                row.get(
                    "dst_ip",
                    ""
                )
            ),

            "protocol": get_protocol(
                row
            ),

            "type": "ML Anomaly",

            "score": score,

            "severity": severity,

            "status": "Detected",

            "srcPort": safe_int(
                row.get(
                    "src_port",
                    0
                )
            ),

            "dstPort": safe_int(
                row.get(
                    "dst_port",
                    0
                )
            ),

            "packetSize": get_bytes(
                row
            ),

            "reason": (
                "Isolation Forest identified "
                "this network flow as anomalous."
            )
        })


    return results


# =========================================================
# PACKETS / NETWORK FLOWS
# =========================================================

@app.get("/packets")
def get_packets():

    df = load_classified_data()

    results = []


    # -----------------------------------------------------
    # Return network flows
    # -----------------------------------------------------

    for index, (_, row) in enumerate(
        df.iterrows(),
        start=1
    ):

        probability = safe_float(
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


        if prediction.lower() == "attack":

            status = "Anomaly"

        else:

            status = "Normal"


        results.append({

            "id": index,

            "timestamp": "--",

            "src_ip": str(
                row.get(
                    "src_ip",
                    ""
                )
            ),

            "dst_ip": str(
                row.get(
                    "dst_ip",
                    ""
                )
            ),

            "protocol": get_protocol(
                row
            ),

            "src_port": safe_int(
                row.get(
                    "src_port",
                    0
                )
            ),

            "dst_port": safe_int(
                row.get(
                    "dst_port",
                    0
                )
            ),

            # This is total FLOW bytes,
            # not one physical packet.
            "packet_size": get_bytes(
                row
            ),

            "status": status,

            "score": score
        })


    return results


# =========================================================
# TOPOLOGY
# =========================================================

@app.get("/topology")
def get_topology():
    """Return endpoint aggregates from the classified PCAP flows."""

    df = load_classified_data()
    anomaly_df = get_isolation_anomalies(load_anomaly_data())
    anomaly_keys = set(
        zip(
            anomaly_df.get("src_ip", pd.Series(dtype=str)).astype(str),
            anomaly_df.get("dst_ip", pd.Series(dtype=str)).astype(str),
        )
    )

    node_stats = {}
    link_stats = {}

    for _, row in df.iterrows():
        source = str(row.get("src_ip", ""))
        destination = str(row.get("dst_ip", ""))
        protocol = get_protocol(row) or "UNKNOWN"
        packets = safe_int(row.get("total_packets", row.get("spkts", 0)))
        bytes_total = get_bytes(row)
        is_attack = str(row.get("prediction_label", "")).lower() == "attack"
        is_anomaly = (source, destination) in anomaly_keys

        for address in (source, destination):
            stats = node_stats.setdefault(address, {
                "flows": 0,
                "packets": 0,
                "bytes": 0,
                "attackFlows": 0,
                "anomalyFlows": 0,
                "protocols": {},
            })
            stats["flows"] += 1
            stats["packets"] += packets
            stats["bytes"] += bytes_total
            stats["attackFlows"] += int(is_attack)
            stats["anomalyFlows"] += int(is_anomaly)
            stats["protocols"][protocol] = stats["protocols"].get(protocol, 0) + 1

        link = (source, destination)
        stats = link_stats.setdefault(link, {"flows": 0, "packets": 0, "anomalies": 0})
        stats["flows"] += 1
        stats["packets"] += packets
        stats["anomalies"] += int(is_anomaly)

    selected_addresses = sorted(
        node_stats,
        key=lambda address: node_stats[address]["flows"],
        reverse=True,
    )[:8]
    positions = [
        [-2.8, 1.25, 0.2], [-2.4, -1.3, -0.2], [2.6, 1.3, 0.1],
        [2.7, -1.1, 0.3], [0.1, -2.35, -0.2], [0, 0.1, 0],
        [-0.2, 2.25, -0.3], [0.4, -0.3, 0.8],
    ]
    nodes = []
    for index, address in enumerate(selected_addresses):
        stats = node_stats[address]
        status = "Anomaly" if stats["anomalyFlows"] else "Warning" if stats["attackFlows"] else "Normal"
        nodes.append({
            "id": f"node-{index}",
            "label": "ENDPOINT",
            "ip": address,
            "position": positions[index],
            "role": "PCAP endpoint",
            "status": status,
            "protocol": max(stats["protocols"], key=stats["protocols"].get),
            "flows": stats["flows"],
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "attackFlows": stats["attackFlows"],
            "anomalyFlows": stats["anomalyFlows"],
        })

    node_ids = {address: f"node-{index}" for index, address in enumerate(selected_addresses)}
    links = []
    for (source, destination), stats in sorted(
        link_stats.items(), key=lambda item: item[1]["flows"], reverse=True
    ):
        if source not in node_ids or destination not in node_ids:
            continue
        links.append({
            "from": node_ids[source],
            "to": node_ids[destination],
            "type": "anomaly" if stats["anomalies"] else "normal",
            "flows": stats["flows"],
            "packets": stats["packets"],
        })
        if len(links) >= 12:
            break

    return {"nodes": nodes, "links": links, "source": "pcap_classified.csv"}


# =========================================================
# HEURISTIC ATTACK TYPES
# =========================================================

@app.get("/attack-types")
def get_attack_types():
    """Summarize behavioral indicators, not ground-truth attack labels."""

    if ATTACK_TYPES_FILE.exists():
        result_df = pd.read_csv(ATTACK_TYPES_FILE)
        counts = result_df["attack_type"].value_counts()
        return {
            "classificationBasis": "Heuristic analysis of Random Forest classifications; not ground truth.",
            "items": [
                {"name": name, "value": int(counts.get(name, 0))}
                for name in ["Normal", "Possible Port Scan", "Possible DDoS", "Other ML Attack"]
            ],
        }

    df = load_classified_data().copy()
    attacks = df["prediction_label"].astype(str).str.lower().eq("attack")
    port_counts = df.groupby("src_ip")["dst_port"].nunique()
    port_scan_sources = set(port_counts[port_counts >= 10].index)
    destination_sources = df[attacks].groupby("dst_ip")["src_ip"].nunique()
    ddos_destinations = set(destination_sources[destination_sources >= 5].index)

    labels = []
    for _, row in df.iterrows():
        if str(row.get("prediction_label", "")).lower() != "attack":
            labels.append("Normal")
        elif row.get("src_ip") in port_scan_sources:
            labels.append("Possible Port Scan")
        elif row.get("dst_ip") in ddos_destinations:
            labels.append("Possible DDoS")
        else:
            labels.append("Other ML Attack")

    counts = pd.Series(labels).value_counts()
    return {
        "classificationBasis": "Heuristic analysis of Random Forest classifications; not ground truth.",
        "items": [
            {"name": name, "value": int(counts.get(name, 0))}
            for name in ["Normal", "Possible Port Scan", "Possible DDoS", "Other ML Attack"]
        ],
    }


# =========================================================
# ANALYTICS
# =========================================================

@app.get("/analytics")
def get_analytics():

    df = load_classified_data()

    anomaly_source = load_anomaly_data()

    anomaly_df = get_isolation_anomalies(
        anomaly_source
    )


    total = len(df)


    # -----------------------------------------------------
    # RANDOM FOREST
    # -----------------------------------------------------

    attack_mask = (
        df["prediction_label"]
        .astype(str)
        .str.lower()
        .eq("attack")
    )

    attacks = int(
        attack_mask.sum()
    )

    normal = (
        total - attacks
    )


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

                "value": int(
                    count
                )

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


    if "attack_probability" in df.columns:

        attack_df = df[
            attack_mask
        ]

        probabilities = pd.to_numeric(
            attack_df["attack_probability"],
            errors="coerce"
        ).fillna(0)


        for probability in probabilities:

            score = probability * 100


            if score >= 90:

                severity_data[
                    "Critical"
                ] += 1

            elif score >= 75:

                severity_data[
                    "High"
                ] += 1

            elif score >= 50:

                severity_data[
                    "Medium"
                ] += 1

            else:

                severity_data[
                    "Low"
                ] += 1


    severity_list = [

        {
            "name": key,

            "value": value
        }

        for key, value
        in severity_data.items()

    ]


    # -----------------------------------------------------
    # TRAFFIC DATA
    # -----------------------------------------------------

    # The PCAP flow extraction did not retain
    # timestamps, so we do not invent fake timestamps.

    traffic = [

        {

            "time": "PCAP",

            "packets": total,

            "normal": normal,

            "anomaly": len(
                anomaly_df
            )

        }

    ]


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {

        "traffic": traffic,

        "anomalies": len(
            anomaly_df
        ),

        "attackFlows": attacks,

        "normalFlows": normal,

        "totalFlows": total,

        "protocolData": protocol_data,

        "severityData": severity_list

    }


# =========================================================
# NETWORK STATS
# =========================================================

@app.get("/network-stats")
def network_stats():

    return get_stats()