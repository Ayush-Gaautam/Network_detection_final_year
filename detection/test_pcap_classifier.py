import joblib
import pandas as pd


# ============================================================
# FILES
# ============================================================

MODEL_FILE = "models/random_forest_classifier.pkl"

PCAP_FILE = "data/raw/pcap_flows.csv"

OUTPUT_FILE = "data/raw/pcap_classified.csv"


# ============================================================
# 1. LOAD MODEL
# ============================================================

print("Loading Random Forest model...")

model_data = joblib.load(MODEL_FILE)

model = model_data["model"]

features = model_data["features"]

print("Model loaded.")

print("\nFeatures used:")

print(features)


# ============================================================
# 2. LOAD PCAP FLOWS
# ============================================================

print("\nLoading PCAP flows...")

df = pd.read_csv(PCAP_FILE)

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
# 4. PREPARE FEATURES
# ============================================================

X = df[features].copy()


X = X.apply(
    pd.to_numeric,
    errors="coerce"
)


X = X.replace(
    [float("inf"), float("-inf")],
    0
)


X = X.fillna(0)


# ============================================================
# 5. PREDICT
# ============================================================

print("\nRunning Random Forest classification...")

predictions = model.predict(X)


# ============================================================
# 6. PROBABILITY
# ============================================================

probabilities = model.predict_proba(X)

attack_probability = probabilities[:, 1]


# ============================================================
# 7. ADD RESULTS
# ============================================================

df["prediction"] = predictions

df["attack_probability"] = attack_probability


# Convert numerical prediction into readable text

df["prediction_label"] = df["prediction"].map({

    0: "Normal",

    1: "Attack"

})


# ============================================================
# 8. RESULTS
# ============================================================

normal = (predictions == 0).sum()

attacks = (predictions == 1).sum()


print("\n========================================")

print("PCAP RANDOM FOREST RESULTS")

print("========================================")


print("Total flows:", len(df))

print("Normal flows:", normal)

print("Attack flows:", attacks)


print(
    "Attack percentage:",
    round(
        attacks / len(df) * 100,
        2
    ),
    "%"
)


# ============================================================
# 9. SHOW HIGH-CONFIDENCE ATTACKS
# ============================================================

print("\n========================================")

print("TOP SUSPICIOUS FLOWS")

print("========================================")


suspicious = df[
    df["prediction"] == 1
].sort_values(
    "attack_probability",
    ascending=False
)


columns_to_show = [

    "src_ip",

    "dst_ip",

    "src_port",

    "dst_port",

    "proto",

    "spkts",

    "dpkts",

    "sbytes",

    "dbytes",

    "rate",

    "attack_probability",

    "prediction_label"

]


print(
    suspicious[
        columns_to_show
    ].head(20).to_string(
        index=False
    )
)


# ============================================================
# 10. SAVE
# ============================================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n========================================")

print("CLASSIFICATION COMPLETE")

print("========================================")


print("Results saved to:")

print(OUTPUT_FILE)