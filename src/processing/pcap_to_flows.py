import os
import csv
from scapy.all import PcapReader, IP, TCP, UDP


PCAP_FILE = "data/raw/1.pcap"
OUTPUT_FILE = "data/raw/pcap_flows.csv"


# ------------------------------------------------------------
# Store information about each network flow
# ------------------------------------------------------------

flows = {}


def get_packet_info(packet):

    if IP not in packet:
        return None

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst

    # TCP
    if TCP in packet:
        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # UDP
    elif UDP in packet:
        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        return None

    timestamp = float(packet.time)
    packet_length = len(packet)

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        timestamp,
        packet_length
    )


# ------------------------------------------------------------
# Read PCAP packet by packet
# ------------------------------------------------------------

print("Reading PCAP...")
print("This may take some time because the file contains")
print("approximately 1.9 million packets.\n")


packet_count = 0
used_packets = 0


with PcapReader(PCAP_FILE) as packets:

    for packet in packets:

        packet_count += 1

        info = get_packet_info(packet)

        if info is None:
            continue

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            timestamp,
            packet_length
        ) = info

        used_packets += 1

        # ----------------------------------------------------
        # Create bidirectional flow key
        # ----------------------------------------------------

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        if endpoint1 <= endpoint2:

            flow_key = (
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol
            )

        else:

            flow_key = (
                dst_ip,
                dst_port,
                src_ip,
                src_port,
                protocol
            )

        # ----------------------------------------------------
        # Create new flow
        # ----------------------------------------------------

        if flow_key not in flows:

            flows[flow_key] = {

                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,

                "start_time": timestamp,
                "last_time": timestamp,

                "spkts": 0,
                "dpkts": 0,

                "sbytes": 0,
                "dbytes": 0,

                "src_times": [],
                "dst_times": [],

            }

        flow = flows[flow_key]

        # ----------------------------------------------------
        # Determine direction
        # ----------------------------------------------------

        if (
            src_ip == flow["src_ip"]
            and src_port == flow["src_port"]
        ):

            flow["spkts"] += 1
            flow["sbytes"] += packet_length
            flow["src_times"].append(timestamp)

        else:

            flow["dpkts"] += 1
            flow["dbytes"] += packet_length
            flow["dst_times"].append(timestamp)

        flow["last_time"] = timestamp


        # Progress message
        if packet_count % 100000 == 0:

            print(
                f"Processed packets: {packet_count:,} | "
                f"Flows: {len(flows):,}"
            )


# ------------------------------------------------------------
# Convert flows into ML features
# ------------------------------------------------------------

print("\nPCAP processing complete.")
print("Total packets:", packet_count)
print("IP/TCP/UDP packets:", used_packets)
print("Total flows:", len(flows))

print("\nCreating flow features...")


rows = []


for flow in flows.values():

    duration = flow["last_time"] - flow["start_time"]

    if duration <= 0:
        duration = 0.000001


    total_packets = flow["spkts"] + flow["dpkts"]

    total_bytes = flow["sbytes"] + flow["dbytes"]


    # Packet rate
    rate = total_packets / duration


    # Bytes per second
    total_load = total_bytes / duration


    # Source packet rate
    sload = flow["sbytes"] * 8 / duration


    # Destination packet rate
    dload = flow["dbytes"] * 8 / duration


    # Mean packet size
    if flow["spkts"] > 0:
        smean = flow["sbytes"] / flow["spkts"]
    else:
        smean = 0


    if flow["dpkts"] > 0:
        dmean = flow["dbytes"] / flow["dpkts"]
    else:
        dmean = 0


    # Average inter-packet time
    src_times = flow["src_times"]
    dst_times = flow["dst_times"]


    if len(src_times) > 1:

        src_intervals = [
            src_times[i] - src_times[i - 1]
            for i in range(1, len(src_times))
        ]

        sinpkt = sum(src_intervals) / len(src_intervals)

    else:

        sinpkt = 0


    if len(dst_times) > 1:

        dst_intervals = [
            dst_times[i] - dst_times[i - 1]
            for i in range(1, len(dst_times))
        ]

        dinpkt = sum(dst_intervals) / len(dst_intervals)

    else:

        dinpkt = 0


    rows.append({

        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],
        "proto": flow["protocol"],

        "dur": duration,

        "spkts": flow["spkts"],
        "dpkts": flow["dpkts"],

        "sbytes": flow["sbytes"],
        "dbytes": flow["dbytes"],

        "rate": rate,

        "sload": sload,
        "dload": dload,

        "sinpkt": sinpkt,
        "dinpkt": dinpkt,

        "smean": smean,
        "dmean": dmean,

        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_load": total_load
    })


# ------------------------------------------------------------
# Save CSV
# ------------------------------------------------------------

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)


fieldnames = rows[0].keys()


with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    writer.writerows(rows)


print("\n========================================")
print("PCAP FLOW EXTRACTION COMPLETE")
print("========================================")

print("Flows:", len(rows))
print("Saved to:")
print(OUTPUT_FILE)