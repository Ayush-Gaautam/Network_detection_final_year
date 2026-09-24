import pandas as pd


INPUT_FILE = "data/raw/pcap_classified.csv"
OUTPUT_FILE = "data/raw/attack_type_results.csv"


print("Loading classified PCAP...")

df = pd.read_csv(INPUT_FILE)

print("Total flows:", len(df))


# ============================================================
# INITIAL LABEL
# ============================================================

df["attack_type"] = "Normal"


# ============================================================
# ONLY ANALYZE FLOWS CLASSIFIED AS ATTACK
# ============================================================

attacks = df["prediction"] == 1


# ============================================================
# PORT SCAN INDICATOR
# ============================================================
#
# A source contacting many different destination ports
# can indicate reconnaissance / port scanning.
#
# This is a behavioral indicator, NOT proof of a port scan.
# ============================================================

source_port_counts = (
    df.groupby("src_ip")["dst_port"]
    .nunique()
)

port_scan_sources = source_port_counts[
    source_port_counts >= 10
].index


port_scan_mask = (
    attacks
    & df["src_ip"].isin(port_scan_sources)
)


df.loc[
    port_scan_mask,
    "attack_type"
] = "Possible Port Scan"


# ============================================================
# DDOS-LIKE INDICATOR
# ============================================================
#
# Many different source IPs sending suspicious flows
# toward the same destination can indicate DDoS-like behavior.
# ============================================================

destination_source_counts = (
    df[attacks]
    .groupby("dst_ip")["src_ip"]
    .nunique()
)


ddos_destinations = destination_source_counts[
    destination_source_counts >= 5
].index


ddos_mask = (
    attacks
    & df["dst_ip"].isin(ddos_destinations)
    & (df["attack_type"] == "Normal")
)


df.loc[
    ddos_mask,
    "attack_type"
] = "Possible DDoS"


# ============================================================
# OTHER ATTACKS
# ============================================================

other_attack_mask = (
    attacks
    & (df["attack_type"] == "Normal")
)


df.loc[
    other_attack_mask,
    "attack_type"
] = "Other ML Attack"


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("FINAL ATTACK TYPE SUMMARY")
print("========================================")

print(
    df["attack_type"]
    .value_counts()
)


# ============================================================
# HIGH CONFIDENCE ATTACKS
# ============================================================

print("\n========================================")
print("HIGH CONFIDENCE ATTACKS")
print("========================================")


high_confidence = df[
    (df["prediction"] == 1)
    &
    (df["attack_probability"] >= 0.90)
].copy()


print(
    "High-confidence attack flows:",
    len(high_confidence)
)


columns = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "rate",
    "attack_probability",
    "attack_type"
]


print(
    high_confidence[
        columns
    ]
    .head(30)
    .to_string(index=False)
)


# ============================================================
# SAVE FINAL RESULTS
# ============================================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n========================================")
print("FINAL RESULTS SAVED")
print("========================================")

print(OUTPUT_FILE)