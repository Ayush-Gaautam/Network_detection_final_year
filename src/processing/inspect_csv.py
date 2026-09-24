import pandas as pd

file = "data/raw/UNSW_NB15_training-set.csv"

df = pd.read_csv(file)

print("\n========== DATASET SHAPE ==========")
print(df.shape)

print("\n========== COLUMNS ==========")
for column in df.columns:
    print(column)

print("\n========== FIRST 5 ROWS ==========")
print(df.head())

print("\n========== LABEL COUNTS ==========")
print(df["label"].value_counts())

print("\n========== ATTACK CATEGORIES ==========")
if "attack_cat" in df.columns:
    print(df["attack_cat"].value_counts(dropna=False))

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())