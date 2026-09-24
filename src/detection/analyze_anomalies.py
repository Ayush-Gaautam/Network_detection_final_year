import pandas as pd


INPUT_FILE = "data/raw/pcap_anomaly_results.csv"


print("Loading anomaly results...")

df = pd.read_csv(INPUT_FILE)

print("Total flows:", len(df))


# ============================================================
# ONLY ANALYZE FLOWS FLAGGED BY ISOLATION FOREST
# ============================================================

anomalies = df[df["anomaly"] == 1].copy()

print("\n========================================")
print("ANOMALOUS FLOW ANALYSIS")
print("========================================")

print("Anomalous flows:", len(anomalies))


# ============================================================
# 1. BASIC STATISTICS
# ============================================================

print("\n========== PROTOCOLS ==========")

print(
    anomalies["proto"]
    .value_counts()
)


# ============================================================
# 2. TOP DESTINATION IPS
# ============================================================

print("\n========== TOP DESTINATION IPs ==========")

print(
    anomalies["dst_ip"]
    .value_counts()
    .head(20)
)


# ============================================================
# 3. TOP SOURCE IPS
# ============================================================

print("\n========== TOP SOURCE IPs ==========")

print(
    anomalies["src_ip"]
    .value_counts()
    .head(20)
)


# ============================================================
# 4. PORT-SCAN INDICATORS
# ============================================================

print("\n========== PORT SCAN ANALYSIS ==========")

port_scan_candidates = []

for src_ip, group in anomalies.groupby("src_ip"):

    unique_ports = group["dst_port"].nunique()

    unique_destinations = group["dst_ip"].nunique()

    flow_count = len(group)

    # A simple behavioral indicator.
    # Many destination ports from one source
    # can indicate reconnaissance / port scanning.

    if unique_ports >= 10:

        port_scan_candidates.append({

            "src_ip": src_ip,

            "unique_destination_ports": unique_ports,

            "unique_destinations": unique_destinations,

            "flows": flow_count

        })


port_scan_df = pd.DataFrame(
    port_scan_candidates
)


if len(port_scan_df) > 0:

    port_scan_df = port_scan_df.sort_values(
        "unique_destination_ports",
        ascending=False
    )

    print(port_scan_df.to_string(index=False))

else:

    print("No strong port-scan candidates found.")


# ============================================================
# 5. DDOS-LIKE BEHAVIOR
# ============================================================

print("\n========== DDOS-LIKE ANALYSIS ==========")

ddos_candidates = []

for dst_ip, group in anomalies.groupby("dst_ip"):

    unique_sources = group["src_ip"].nunique()

    flow_count = len(group)

    total_packets = group["total_packets"].sum()

    total_bytes = group["total_bytes"].sum()

    max_rate = group["rate"].max()

    # Many different sources attacking
    # the same destination can be a DDoS indicator.

    if unique_sources >= 5 and flow_count >= 10:

        ddos_candidates.append({

            "dst_ip": dst_ip,

            "unique_sources": unique_sources,

            "flows": flow_count,

            "total_packets": total_packets,

            "total_bytes": total_bytes,

            "max_packet_rate": max_rate

        })


ddos_df = pd.DataFrame(
    ddos_candidates
)


if len(ddos_df) > 0:

    ddos_df = ddos_df.sort_values(
        "unique_sources",
        ascending=False
    )

    print(ddos_df.to_string(index=False))

else:

    print("No strong DDoS-like candidates found.")


# ============================================================
# 6. SAVE RESULTS
# ============================================================

if len(port_scan_df) > 0:

    port_scan_df.to_csv(
        "data/raw/port_scan_candidates.csv",
        index=False
    )


if len(ddos_df) > 0:

    ddos_df.to_csv(
        "data/raw/ddos_candidates.csv",
        index=False
    )


print("\n========================================")
print("ANALYSIS COMPLETE")
print("========================================")