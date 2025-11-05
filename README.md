📘 Overview

This project explores how Large Language Models (LLMs) can generate realistic network packet traces without fine-tuning.
Instead of relying on diffusion or GAN models such as NetDiffusion
 or NetShare
, this work evaluates whether general-purpose LLMs (ChatGPT, Gemini, Llama 3.1) can synthesize valid, protocol-compliant traces through prompt engineering and in-context learning.

Generated traces are first produced in JSON format for interpretability and validation, then converted into PCAP for visualization and quantitative analysis.

🎯 Goals

✅ Trace Correctness: Ensure LLM-generated traces obey protocol rules (e.g., TCP handshake, ACK matching).

📊 Quality Evaluation: Quantitatively measure realism vs real traces (IMC10 dataset).

⚙️ Format Conversion: Automate JSON → PCAP conversion for Wireshark/tcpdump.

💡 Use Cases: Simulation, network stress testing, and ML data augmentation.
📂 Project Structure
llm_packet_trace/
├── generated_trace.json        # LLM textual output (intermediate)
├── generated_trace.pcap        # Converted PCAP file (final output)
├── trace_validator.py          # Protocol correctness checker
├── json_to_pcap.py             # Scapy-based converter
├── metrics_eval.py             # Optional: quality metrics
└── README.md

🧩 Input Format (JSON)
[
  {
    "timestamp": 0.0001,
    "protocol": "TCP",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 12345,
    "dst_port": 80,
    "flags": "SYN",
    "seq": 0,
    "ack": 0,
    "payload": ""
  },
  {
    "timestamp": 0.0002,
    "protocol": "TCP",
    "src_ip": "10.0.0.2",
    "dst_ip": "10.0.0.1",
    "src_port": 80,
    "dst_port": 12345,
    "flags": "SYN-ACK",
    "seq": 500,
    "ack": 1,
    "payload": ""
  }
]

⚙️ Conversion and Validation
1️⃣ Validate Trace
python trace_validator.py generated_trace.json


Checks include TCP flag sequence (SYN → SYN-ACK → ACK), IP/Port pair consistency, SEQ/ACK matching, timestamp ordering.

2️⃣ Convert to PCAP
python json_to_pcap.py generated_trace.json generated_trace.pcap


Example – json_to_pcap.py:

from scapy.all import *
import json, sys

infile, outfile = sys.argv[1], sys.argv[2]
with open(infile) as f:
    packets = json.load(f)

pkts = []
for p in packets:
    ip = IP(src=p["src_ip"], dst=p["dst_ip"])
    if p["protocol"] == "TCP":
        l4 = TCP(sport=p["src_port"], dport=p["dst_port"],
                 flags=p["flags"], seq=p["seq"], ack=p["ack"])
    elif p["protocol"] == "UDP":
        l4 = UDP(sport=p["src_port"], dport=p["dst_port"])
    else:
        continue
    pkt = ip / l4 / Raw(load=p["payload"])
    pkts.append(pkt)

wrpcap(outfile, pkts)
print(f"✅ {outfile} created successfully")

3️⃣ Visualize and Compare

Open generated_trace.pcap in Wireshark or use CLI:

tshark -r generated_trace.pcap -T json > parsed_trace.json

📊 Evaluation Metrics

Quantify trace quality using:

Packet size distribution

Inter-arrival time

Flag sequence probability

Protocol field entropy

Distance to real trace (KL / Wasserstein)
