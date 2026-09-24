import os
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix


# ============================================================
# 1. FILE PATHS
# ============================================================

TRAIN_FILE = "data/raw/UNSW_NB15_training-set.csv"
TEST_FILE = "data/raw/UNSW_NB15_testing-set.csv"

MODEL_DIR = "models"
MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest.pkl")


# ============================================================
# 2. FEATURES
# ============================================================
# These are flow-level features that we can later calculate
# from PCAP packets using Scapy.

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


# ============================================================
# 3. LOAD DATA
# ============================================================

print("Loading training dataset...")

train_df = pd.read_csv(TRAIN_FILE)

print("Training shape:", train_df.shape)


print("\nLoading testing dataset...")

test_df = pd.read_csv(TEST_FILE)

print("Testing shape:", test_df.shape)


# ============================================================
# 4. CHECK FEATURES
# ============================================================

print("\nChecking selected features...")

missing_features = [
    feature for feature in FEATURES
    if feature not in train_df.columns
]

if missing_features:
    print("Missing features:", missing_features)
    raise ValueError("Some required features are missing.")

print("All features available.")


# ============================================================
# 5. SELECT ONLY NORMAL TRAINING DATA
# ============================================================

normal_train = train_df[train_df["label"] == 0].copy()

print("\n========== NORMAL TRAINING DATA ==========")
print("Normal rows:", len(normal_train))


# ============================================================
# 6. PREPARE FEATURES
# ============================================================

X_train = normal_train[FEATURES].copy()

X_test = test_df[FEATURES].copy()

y_test = test_df["label"].copy()


# Convert everything to numeric
X_train = X_train.apply(pd.to_numeric, errors="coerce")
X_test = X_test.apply(pd.to_numeric, errors="coerce")


# Replace invalid values
X_train = X_train.replace([float("inf"), float("-inf")], 0)
X_test = X_test.replace([float("inf"), float("-inf")], 0)


# Fill missing values
X_train = X_train.fillna(0)
X_test = X_test.fillna(0)


# ============================================================
# 7. TRAIN ISOLATION FOREST
# ============================================================

print("\nTraining Isolation Forest...")

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train)

print("Model training completed.")


# ============================================================
# 8. CALCULATE THRESHOLD USING NORMAL TRAINING DATA
# ============================================================

print("\nCalculating anomaly threshold...")

train_scores = model.decision_function(X_train)

# Approximately 1% of normal training traffic is allowed
# to be considered anomalous.
threshold = pd.Series(train_scores).quantile(0.01)

print("Threshold:", threshold)


# ============================================================
# 9. TEST THE MODEL
# ============================================================

print("\nTesting model...")

test_scores = model.decision_function(X_test)

predictions = (test_scores < threshold).astype(int)


# ============================================================
# 10. RESULTS
# ============================================================

print("\n========== CONFUSION MATRIX ==========")

print(confusion_matrix(y_test, predictions))


print("\n========== CLASSIFICATION REPORT ==========")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"]
    )
)


# ============================================================
# 11. SAVE MODEL
# ============================================================

os.makedirs(MODEL_DIR, exist_ok=True)

model_data = {
    "model": model,
    "features": FEATURES,
    "threshold": threshold
}

joblib.dump(model_data, MODEL_FILE)

print("\n========================================")
print("MODEL SAVED")
print("========================================")
print(MODEL_FILE)