# 🧠 LLM-Generated Network Packet Traces
Cornell ECE 6960 — Fall 2025  
**Author:** Hubery Yin (hy668)

---

## 📘 Overview
This project explores how **Large Language Models (LLMs)** can generate realistic **network packet traces** without fine-tuning.  
Instead of relying on diffusion or GAN models such as [NetDiffusion](https://dl.acm.org/doi/10.1145/3639037) or [NetShare](https://github.com/netsharecmu/NetShare), this work evaluates whether general-purpose LLMs (ChatGPT, Gemini, Llama 3.1) can synthesize valid, protocol-compliant traces through **prompt engineering** and **in-context learning**.

Generated traces are first produced in **JSON format** for interpretability and validation, then converted into **PCAP** for visualization and quantitative analysis.

---

## 🎯 Goals
- ✅ **Trace Correctness:** Ensure LLM-generated traces obey protocol rules (e.g., TCP handshake, ACK matching).
- 📊 **Quality Evaluation:** Quantitatively measure realism vs real traces (IMC10 dataset).
- ⚙️ **Format Conversion:** Automate JSON → PCAP conversion for Wireshark/tcpdump.
- 💡 **Use Cases:** Simulation, network stress testing, and ML data augmentation.

---

## 📂 Project Structure

```text
llm_packet_trace/
├── generated_trace.json        # LLM textual output (intermediate)
├── generated_trace.pcap        # Converted PCAP file (final output)
├── trace_validator.py          # Protocol correctness checker
├── json_to_pcap.py             # Scapy-based converter
├── metrics_eval.py             # Optional: quality metrics
└── README.md
```

> Tip: keep filenames in `snake_case` to avoid Markdown escaping issues.

---

## 🧩 Input Format (JSON)

```json
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
```

---

## ⚙️ Conversion and Validation

### 1️⃣ Validate Trace

```bash
python trace_validator.py generated_trace.json
```

Checks include: TCP flag sequence (SYN → SYN-ACK → ACK), IP/Port pair consistency, SEQ/ACK matching, timestamp ordering.

### 2️⃣ Convert to PCAP

```bash
python json_to_pcap.py generated_trace.json generated_trace.pcap
```

**Example – `json_to_pcap.py`:**

```python
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
    payload = p.get("payload", "")
    pkt = ip / l4 / Raw(load=payload)
    pkts.append(pkt)

wrpcap(outfile, pkts)
print(f"✅ {outfile} created successfully")
```

### 3️⃣ Visualize and Compare

Open the PCAP in Wireshark, or use CLI:

```bash
tshark -r generated_trace.pcap -T json > parsed_trace.json
```

---

## 📊 Evaluation Metrics
- Packet size distribution
- Inter-arrival time
- Flag sequence probability
- Protocol field entropy
- Distance to real trace (KL / Wasserstein)

---

## 📚 References
1. NetShare – Practical GAN-based Synthetic IP Header Trace Generation ([GitHub](https://github.com/netsharecmu/NetShare))  
2. NetDiffusion – Protocol-Constrained Traffic Generation ([ACM DOI 10.1145/3639037](https://dl.acm.org/doi/10.1145/3639037))  
3. T. Benson et al., *Network Traffic Characteristics of Data Centers*, IMC 2010 ([Dataset](https://pages.cs.wisc.edu/~tbenson/IMC10_Data.html))

---

## 🧠 Key Difference vs Previous Work

|  | Traditional Models (GAN/Diffusion) | This LLM Project |
|:-|:-|:-|
| Generation Basis | Statistical distributions | Protocol semantics + prompt control |
| Interpretability | Low | High (JSON readable) |
| Protocol Compliance | Mask/constraint based | LLM reasoning based |
| Zero-shot Adaptability | Weak | Strong |

---

## 💡 Formatting Notes (if your GitHub view looks broken)
- Make sure **code blocks are fenced** with triple backticks and a language hint (e.g., `json`, `python`, `bash`).
- Leave a **blank line** before and after lists, code blocks, and headings.
- Avoid mixing tabs and spaces; use **LF** line endings on macOS/Linux (or let Git normalize endings).
- Save as **UTF-8**; GitHub handles emoji automatically.
