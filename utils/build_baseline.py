#!/usr/bin/env python3
"""
utils/build_baseline.py

从 baseline/ 下的原始多主机 PCAP 中，自动为每个文件选出
“通信包数最多的一对 IP（host pair）”，只保留这两个主机之间的
TCP/UDP 包，并输出：

  baseline/processed/<pcap名>_pair.pcap   # 过滤后的两主机 PCAP
  baseline/demo/<pcap名>.json             # 对应 JSON baseline

JSON packet 格式（与项目统一）：

{
  "timestamp": <float>,
  "protocol": "TCP" or "UDP",
  "src_ip": "<string>",
  "dst_ip": "<string>",
  "src_port": <int>,
  "dst_port": <int>,
  "flags": "<string>",
  "seq": <int>,
  "ack": <int>,
  "payload": "<string>"
}
"""

from pathlib import Path
from typing import Dict, Any, List, Tuple
from collections import Counter
import json

from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, Raw  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "baseline"
DEMO_DIR = BASELINE_DIR / "demo"
PROCESSED_DIR = BASELINE_DIR / "processed"

PacketJSON = Dict[str, Any]
HostPair = Tuple[str, str]


def _normalize_pair(ip1: str, ip2: str) -> HostPair:
    """无向 host pair（排序后），方便把 A↔B 两个方向合并统计。"""
    return tuple(sorted((ip1, ip2)))


def _find_top_host_pair(pcap_path: Path) -> HostPair:
    """在一个 PCAP 里找到通信包数最多的一对 IP。"""
    pkts = rdpcap(str(pcap_path))
    counter: Counter[HostPair] = Counter()

    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        pair = _normalize_pair(ip.src, ip.dst)
        counter[pair] += 1

    if not counter:
        raise RuntimeError(f"No IP packets found in {pcap_path}")

    best_pair, _ = counter.most_common(1)[0]
    return best_pair


def _flags_to_string(tcp) -> str:
    """scapy TCP flags → 'SYN-ACK' 这种字符串。"""
    flags = int(tcp.flags)
    parts = []
    if flags & 0x02: parts.append("SYN")
    if flags & 0x10: parts.append("ACK")
    if flags & 0x01: parts.append("FIN")
    if flags & 0x08: parts.append("PSH")
    if flags & 0x04: parts.append("RST")
    return "-".join(parts) if parts else ""


def _pcap_to_pair_json(pcap_path: Path, pair: HostPair) -> List[PacketJSON]:
    """只保留指定 host pair 的 TCP/UDP 包，转成 JSON 列表。"""
    pkts = rdpcap(str(pcap_path))
    out: List[PacketJSON] = []

    for pkt in pkts:
        if IP not in pkt:
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        if _normalize_pair(src, dst) != pair:
            continue

        ts = float(getattr(pkt, "time", 0.0))

        proto = "OTHER"
        sport = 0
        dport = 0
        flags_str = ""
        seq = 0
        ack = 0
        payload = ""

        if TCP in pkt:
            tcp = pkt[TCP]
            proto = "TCP"
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            flags_str = _flags_to_string(tcp)
            seq = int(tcp.seq)
            ack = int(tcp.ack)
        elif UDP in pkt:
            udp = pkt[UDP]
            proto = "UDP"
            sport = int(udp.sport)
            dport = int(udp.dport)
        else:
            # 项目只支持 TCP/UDP，其他协议直接跳过
            continue

        if Raw in pkt:
            raw = bytes(pkt[Raw].load)
            try:
                payload = raw.decode("utf-8", errors="ignore")
            except Exception:
                payload = ""

        out.append({
            "timestamp": ts,
            "protocol": proto,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "flags": flags_str,
            "seq": seq,
            "ack": ack,
            "payload": payload,
        })

    out.sort(key=lambda p: p["timestamp"])
    return out


def _filter_pcap_for_pair(pcap_path: Path, pair: HostPair, out_pcap: Path) -> None:
    """把只属于该 host pair 的 IP 包写到新的 pcap 里。"""
    pkts = rdpcap(str(pcap_path))
    selected = []

    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if _normalize_pair(ip.src, ip.dst) == pair:
            selected.append(pkt)

    if not selected:
        raise RuntimeError(f"No packets for host pair {pair} in {pcap_path}")

    wrpcap(str(out_pcap), selected)


def build_baselines_for_all_pcaps() -> None:
    """对 baseline/ 下所有 .pcap 文件自动生成 baseline。"""
    if not BASELINE_DIR.is_dir():
        raise SystemExit(f"baseline directory not found: {BASELINE_DIR}")

    DEMO_DIR.mkdir(exist_ok=True)
    PROCESSED_DIR.mkdir(exist_ok=True)

    pcap_files = sorted(BASELINE_DIR.glob("*.pcap"))
    if not pcap_files:
        raise SystemExit(f"No .pcap files found in {BASELINE_DIR}")

    print(f"[info] Found {len(pcap_files)} pcap files in {BASELINE_DIR}")

    for pcap_path in pcap_files:
        print(f"\n[info] Processing {pcap_path.name} ...")

        # 1. 找这个文件里最活跃的 host pair
        pair = _find_top_host_pair(pcap_path)
        print(f"[info]   Most active host pair: {pair[0]} <-> {pair[1]}")

        # 2. 过滤出该 pair 的 pcap
        out_pcap = PROCESSED_DIR / f"{pcap_path.stem}_pair.pcap"
        _filter_pcap_for_pair(pcap_path, pair, out_pcap)
        print(f"[info]   Filtered PCAP written to {out_pcap}")

        # 3. 把这个 pair 的流量转成 JSON baseline
        json_packets = _pcap_to_pair_json(pcap_path, pair)
        out_json = DEMO_DIR / f"{pcap_path.stem}.json"
        out_json.write_text(json.dumps(json_packets, indent=2), encoding="utf-8")
        print(f"[info]   JSON baseline written to {out_json} (packets={len(json_packets)})")

    print("\n[done] All baselines built.")


def main() -> None:
    build_baselines_for_all_pcaps()


if __name__ == "__main__":
    main()

