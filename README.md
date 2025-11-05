# 🧠 LLM-Generated Network Packet Traces
Cornell ECE 6960 — Fall 2025  
**Author:** Hubery Yin (hy668)

---

## 📘 Overview
This project explores how **Large Language Models (LLMs)** can generate realistic **network packet traces** without fine-tuning.  
Instead of relying on diffusion or GAN models such as [NetDiffusion](https://dl.acm.org/doi/10.1145/3639037) or [NetShare](https://github.com/netsharecmu/NetShare), this work evaluates whether general-purpose LLMs (ChatGPT, Gemini, Llama 3.1) can synthesize valid, protocol-compliant traces through **prompt engineering** and **in-context learning**.

Generated traces are first produced in **JSON format** for interpretability and validation, then converted into **PCAP** for quantitative analysis.

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
├── generated/                 # LLM gnerated data
│   ├── trace_001.json
│   ├── trace_001.pcap
│   └── ...
├── baseline/                  # baseline
│   ├── sample.json
│   └── sample.pcap
├── validator/                 # validity 
│   └── validate_trace.py
├── evaluator/                 # quality/utility evaluating
│   └── evaluator.py
├── utils/
│   └── json_to_pcap.py        # JSON→PCAP
├── llm_generate.py
├── prompt.txt
└── README.md
```

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

### 1️⃣ Generate network packet trace

```bash
python llm_generate.py generated_trace.json
```

Checks include: TCP flag sequence (SYN → SYN-ACK → ACK), IP/Port pair consistency, SEQ/ACK matching, timestamp ordering.

### 2️⃣ Convert to PCAP

```bash
python json_to_pcap.py generated_trace.json generated_trace.pcap
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

