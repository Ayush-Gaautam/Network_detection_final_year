import joblib
import pandas as pd


MODEL_FILE = "models/isolation_forest.pkl"
PCAP_FLOWS = "data/raw/pcap_flows.csv"


# ============================================================
# 1. LOAD MODEL
# ============================================================

print("Loading trained model...")

model_data = joblib.load(MODEL_FILE)

model = model_data["model"]
features = model_data["features"]
threshold = model_data["threshold"]

print("Model loaded.")
print("Features used by model:")
print(features)


# ============================================================
# 2. LOAD PCAP FLOWS
# ============================================================

print("\nLoading PCAP flows...")

df = pd.read_csv(PCAP_FLOWS)

print("PCAP flow shape:", df.shape)


# ============================================================
# 3. CHECK FEATURES
# ============================================================

missing = [
    feature
    for feature in features
    if feature not in df.columns
]

if missing:

    print("\nMissing features:")
    print(missing)

    raise ValueError(
        "PCAP does not contain all required features."
    )


print("\nAll required features found.")


# ============================================================
# 4. PREPARE DATA
# ============================================================

X = df[features].copy()

X = X.apply(pd.to_numeric, errors="coerce")

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)


# ============================================================
# 5. RUN ISOLATION FOREST
# ============================================================

print("\nRunning anomaly detection...")

scores = model.decision_function(X)

predictions = (scores < threshold).astype(int)


# ============================================================
# 6. ADD RESULTS
# ============================================================

df["anomaly_score"] = scores

df["anomaly"] = predictions


# ============================================================
# 7. SUMMARY
# ============================================================

normal = (predictions == 0).sum()

anomalies = (predictions == 1).sum()

print("\n========================================")
print("PCAP ANOMALY DETECTION RESULTS")
print("========================================")

print("Total flows:", len(df))

print("Normal flows:", normal)

print("Anomalous flows:", anomalies)

print(
    "Anomaly percentage:",
    round(anomalies / len(df) * 100, 2),
    "%"
)


# ============================================================
# 8. SAVE RESULTS
# ============================================================

OUTPUT_FILE = "data/raw/pcap_anomaly_results.csv"

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nResults saved to:")
print(OUTPUT_FILE)