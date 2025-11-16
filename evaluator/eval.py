#!/usr/bin/env python3
"""
evaluator/evaluator.py

High-level evaluation for LLM-generated network packet traces (PCAP).
Implements the Evaluation Metrics described in README:

1. Statistical Fidelity
2. Temporal Dynamics
3. Protocol Behavior Consistency
4. Semantic Realism
5. Distance to Real Trace
"""

from typing import Dict, Any, List, Tuple

import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP  # type: ignore


FlowKey = Tuple[str, int, str, int, str]


# -------------------- PCAP Parsing & Feature Extraction -------------------- #

def _get_flow_key(ip_src: str, ip_dst: str, sport: int, dport: int, proto: str) -> FlowKey:
    """
    Normalize 5-tuple as a flow key:
    (min_ip, min_port, max_ip, max_port, proto)
    so that both directions share the same key.
    """
    a = (ip_src, int(sport))
    b = (ip_dst, int(dport))
    (ip1, p1), (ip2, p2) = sorted([a, b], key=lambda x: (x[0], x[1]))
    return (ip1, p1, ip2, p2, proto)


def _parse_pcap(path: str) -> Dict[str, Any]:
    """
    Load a PCAP file and extract basic statistics needed for evaluation:

    - packet lengths
    - timestamps + inter-arrival times
    - per-flow statistics (pkt count, duration)
    - simple TCP handshake stats
    - protocol counts (TCP/UDP/OTHER)
    """
    pkts = rdpcap(path)

    lengths: List[float] = []
    timestamps: List[float] = []
    protocol_counts = {"TCP": 0, "UDP": 0, "OTHER": 0}

    flows: Dict[FlowKey, Dict[str, Any]] = {}
    tcp_handshake_total = 0
    tcp_handshake_ok = 0

    for pkt in pkts:
        # PCAP timestamp
        ts = float(getattr(pkt, "time", 0.0))
        timestamps.append(ts)

        # Packet length
        lengths.append(float(len(pkt)))

        # Check if the packet has IP layer
        if IP not in pkt:
            protocol_counts["OTHER"] += 1
            continue

        ip = pkt[IP]
        ip_src = ip.src
        ip_dst = ip.dst

        proto = "OTHER"
        sport = 0
        dport = 0

        tcp_layer = None
        udp_layer = None

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            proto = "TCP"
            sport = int(tcp_layer.sport)
            dport = int(tcp_layer.dport)
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            proto = "UDP"
            sport = int(udp_layer.sport)
            dport = int(udp_layer.dport)

        if proto in protocol_counts:
            protocol_counts[proto] += 1
        else:
            protocol_counts["OTHER"] += 1

        flow_key = _get_flow_key(ip_src, ip_dst, sport, dport, proto)
        flow = flows.get(
            flow_key,
            {
                "pkt_count": 0,
                "first_ts": ts,
                "last_ts": ts,
                "tcp_syn": False,
                "tcp_syn_ack": False,
                "tcp_ack_after_syn": False,
            },
        )

        flow["pkt_count"] += 1
        flow["first_ts"] = min(flow["first_ts"], ts)
        flow["last_ts"] = max(flow["last_ts"], ts)

        # Track simple TCP handshake flags
        if proto == "TCP" and tcp_layer is not None:
            flags = int(tcp_layer.flags)
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            if syn and not ack:
                flow["tcp_syn"] = True
            elif syn and ack:
                flow["tcp_syn_ack"] = True
            elif ack and not syn and flow.get("tcp_syn") and flow.get("tcp_syn_ack"):
                flow["tcp_ack_after_syn"] = True

        flows[flow_key] = flow

    # Compute TCP handshake stats per flow
    for key, f in flows.items():
        if key[4] != "TCP":
            continue
        if f["tcp_syn"] or f["tcp_syn_ack"] or f["tcp_ack_after_syn"]:
            tcp_handshake_total += 1
        if f["tcp_syn"] and f["tcp_syn_ack"] and f["tcp_ack_after_syn"]:
            tcp_handshake_ok += 1

    # Sort timestamps & compute IATs
    timestamps_sorted = sorted(timestamps)
    iats: List[float] = []
    for i in range(1, len(timestamps_sorted)):
        dt = timestamps_sorted[i] - timestamps_sorted[i - 1]
        if dt >= 0:
            iats.append(dt)

    return {
        "lengths": np.array(lengths, dtype=float),
        "timestamps": np.array(timestamps_sorted, dtype=float),
        "iat": np.array(iats, dtype=float),
        "flows": flows,
        "protocol_counts": protocol_counts,
        "tcp_handshake_total": tcp_handshake_total,
        "tcp_handshake_ok": tcp_handshake_ok,
    }


# -------------------- Helper: 1D KS Distance -------------------- #

def _ks_distance(x: np.ndarray, y: np.ndarray, bins: int = 32) -> float:
    """
    Simple 1D Kolmogorov–Smirnov-like distance between two samples.
    We approximate CDFs via histograms on a shared range.
    """
    if x.size == 0 or y.size == 0:
        return float("nan")

    lo = min(x.min(), y.min())
    hi = max(x.max(), y.max())
    if lo == hi:
        return 0.0

    hist_x, bin_edges = np.histogram(x, bins=bins, range=(lo, hi), density=True)
    hist_y, _ = np.histogram(y, bins=bins, range=(lo, hi), density=True)

    cdf_x = np.cumsum(hist_x) * (bin_edges[1] - bin_edges[0])
    cdf_y = np.cumsum(hist_y) * (bin_edges[1] - bin_edges[0])

    return float(np.max(np.abs(cdf_x - cdf_y)))


# -------------------- Metric Computation -------------------- #

def _compute_statistical_fidelity(gen: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    x = gen["lengths"]
    y = base["lengths"]

    return {
        "gen_pkt_len_mean": float(np.mean(x)) if x.size > 0 else float("nan"),
        "gen_pkt_len_std": float(np.std(x)) if x.size > 0 else float("nan"),
        "base_pkt_len_mean": float(np.mean(y)) if y.size > 0 else float("nan"),
        "base_pkt_len_std": float(np.std(y)) if y.size > 0 else float("nan"),
        "pkt_len_ks_distance": _ks_distance(x, y),
        "gen_num_packets": int(x.size),
        "base_num_packets": int(y.size),
    }


def _compute_temporal_dynamics(gen: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    x = gen["iat"]
    y = base["iat"]

    return {
        "gen_iat_mean": float(np.mean(x)) if x.size > 0 else float("nan"),
        "gen_iat_std": float(np.std(x)) if x.size > 0 else float("nan"),
        "base_iat_mean": float(np.mean(y)) if y.size > 0 else float("nan"),
        "base_iat_std": float(np.std(y)) if y.size > 0 else float("nan"),
        "iat_ks_distance": _ks_distance(x, y),
        "gen_num_iat": int(x.size),
        "base_num_iat": int(y.size),
    }


def _compute_protocol_behavior_consistency(gen: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    pc_gen = gen["protocol_counts"]
    pc_base = base["protocol_counts"]

    # Simple TCP handshake success ratio
    gen_total = gen["tcp_handshake_total"]
    gen_ok = gen["tcp_handshake_ok"]
    base_total = base["tcp_handshake_total"]
    base_ok = base["tcp_handshake_ok"]

    def _ratio(ok: int, total: int) -> float:
        if total == 0:
            return float("nan")
        return float(ok / total)

    return {
        "gen_protocol_counts": pc_gen,
        "base_protocol_counts": pc_base,
        "gen_tcp_handshake_total": int(gen_total),
        "gen_tcp_handshake_ok": int(gen_ok),
        "gen_tcp_handshake_success_ratio": _ratio(gen_ok, gen_total),
        "base_tcp_handshake_total": int(base_total),
        "base_tcp_handshake_ok": int(base_ok),
        "base_tcp_handshake_success_ratio": _ratio(base_ok, base_total),
    }


def _compute_semantic_realism(gen: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    flows_gen: Dict[FlowKey, Dict[str, Any]] = gen["flows"]
    flows_base: Dict[FlowKey, Dict[str, Any]] = base["flows"]

    def _flow_stats(flows: Dict[FlowKey, Dict[str, Any]]) -> Dict[str, float]:
        num_flows = len(flows)
        if num_flows == 0:
            return {
                "num_flows": 0,
                "avg_pkts_per_flow": float("nan"),
                "avg_flow_duration": float("nan"),
            }

        pkt_counts = []
        durations = []
        for f in flows.values():
            pkt_counts.append(f["pkt_count"])
            durations.append(max(0.0, f["last_ts"] - f["first_ts"]))

        return {
            "num_flows": num_flows,
            "avg_pkts_per_flow": float(np.mean(pkt_counts)),
            "avg_flow_duration": float(np.mean(durations)),
        }

    stats_gen = _flow_stats(flows_gen)
    stats_base = _flow_stats(flows_base)

    return {
        "gen": stats_gen,
        "base": stats_base,
    }


def _compute_distance_to_real_trace(stat_fid: Dict[str, Any],
                                    temp_dyn: Dict[str, Any]) -> Dict[str, Any]:
    """
    Summarize key distance metrics between generated and real trace.

    Here we re-use:
      - pkt_len_ks_distance
      - iat_ks_distance
    as principled distribution-level distances.
    """
    return {
        "pkt_len_ks_distance": float(stat_fid.get("pkt_len_ks_distance", float("nan"))),
        "iat_ks_distance": float(temp_dyn.get("iat_ks_distance", float("nan"))),
    }


# -------------------- Public API -------------------- #

def evaluate_pcap(generated_pcap: str, baseline_pcap: str) -> Dict[str, Any]:
    """
    Main entrypoint used by llm_generate.py.

    Arguments:
      generated_pcap: path to the PCAP produced from LLM-generated JSON.
      baseline_pcap:  path to a real-world baseline PCAP trace.

    Returns:
      A dictionary with five top-level sections:

        {
          "statistical_fidelity": {...},
          "temporal_dynamics": {...},
          "protocol_behavior_consistency": {...},
          "semantic_realism": {...},
          "distance_to_real_trace": {...}
        }
    """
    gen_stats = _parse_pcap(generated_pcap)
    base_stats = _parse_pcap(baseline_pcap)

    stat_fid = _compute_statistical_fidelity(gen_stats, base_stats)
    temp_dyn = _compute_temporal_dynamics(gen_stats, base_stats)
    proto_cons = _compute_protocol_behavior_consistency(gen_stats, base_stats)
    sem_real = _compute_semantic_realism(gen_stats, base_stats)
    dist_real = _compute_distance_to_real_trace(stat_fid, temp_dyn)

    return {
        "statistical_fidelity": stat_fid,
        "temporal_dynamics": temp_dyn,
        "protocol_behavior_consistency": proto_cons,
        "semantic_realism": sem_real,
        "distance_to_real_trace": dist_real,
    }
