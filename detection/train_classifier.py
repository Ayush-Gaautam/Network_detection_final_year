import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix
)


# ============================================================
# FILES
# ============================================================

TRAIN_FILE = "data/raw/UNSW_NB15_training-set.csv"
TEST_FILE = "data/raw/UNSW_NB15_testing-set.csv"

MODEL_DIR = "models"
MODEL_FILE = os.path.join(
    MODEL_DIR,
    "random_forest_classifier.pkl"
)


# ============================================================
# COMMON FEATURES
# ============================================================
# These are features that we can calculate from the PCAP.

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
    "dmean"
]


# ============================================================
# LOAD DATA
# ============================================================

print("Loading training dataset...")

train_df = pd.read_csv(TRAIN_FILE)

print("Training shape:", train_df.shape)


print("\nLoading testing dataset...")

test_df = pd.read_csv(TEST_FILE)

print("Testing shape:", test_df.shape)


# ============================================================
# CHECK FEATURES
# ============================================================

missing = [
    f for f in FEATURES
    if f not in train_df.columns
]

if missing:
    raise ValueError(
        f"Missing training features: {missing}"
    )


# ============================================================
# PREPARE X
# ============================================================

X_train = train_df[FEATURES].copy()
X_test = test_df[FEATURES].copy()


X_train = X_train.apply(
    pd.to_numeric,
    errors="coerce"
)

X_test = X_test.apply(
    pd.to_numeric,
    errors="coerce"
)


X_train = X_train.replace(
    [float("inf"), float("-inf")],
    0
)

X_test = X_test.replace(
    [float("inf"), float("-inf")],
    0
)


X_train = X_train.fillna(0)
X_test = X_test.fillna(0)


# ============================================================
# TARGET
# ============================================================

y_train = train_df["label"]
y_test = test_df["label"]


print("\n========== TRAIN LABELS ==========")
print(y_train.value_counts())


print("\n========== TEST LABELS ==========")
print(y_test.value_counts())


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
    max_depth=None
)

model.fit(X_train, y_train)

print("Training completed.")


# ============================================================
# PREDICTION
# ============================================================

print("\nRunning predictions...")

predictions = model.predict(X_test)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\n========================================")
print("CONFUSION MATRIX")
print("========================================")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n========================================")
print("CLASSIFICATION REPORT")
print("========================================")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Normal",
            "Attack"
        ]
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\n========================================")
print("FEATURE IMPORTANCE")
print("========================================")

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": model.feature_importances_
})

importance = importance.sort_values(
    "importance",
    ascending=False
)

print(
    importance.to_string(
        index=False
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

model_data = {
    "model": model,
    "features": FEATURES
}

joblib.dump(
    model_data,
    MODEL_FILE
)


print("\n========================================")
print("MODEL SAVED")
print("========================================")

print(MODEL_FILE)