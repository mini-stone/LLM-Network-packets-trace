#!/usr/bin/env python3
"""
baseline/build_baseline_from_pcap.py

从老师给的大 PCAP 中自动抽取“通信最频繁的一对主机”，
生成项目需要的 baseline 文件：

- baseline/sample.pcap             # 只包含这两台主机的流量（给 evaluator 用）
- baseline/demo/two_hosts_demo.json  # 同样数据的 JSON 版本（给 LLM 做 in-context 示例）
"""

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Any, List, Tuple

from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, Raw  # type: ignore

ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo"
DEMO_DIR.mkdir(exist_ok=True)

PacketJSON = Dict[str, Any]
HostPair = Tuple[str, str]


def _normalize_pair(ip1: str, ip2: str) -> HostPair:
    """无向主机对（小的在前），方便统计 A<->B 的总流量。"""
    return tuple(sorted((ip1, ip2)))


def _find_top_host_pair(pcap_path: Path) -> HostPair:
    """在 PCAP 中找到出现包数最多的一对主机 (IP, IP)。"""
    pkts = rdpcap(str(pcap_path))
    counter: Counter[HostPair] = Counter()

    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        pair = _normalize_pair(ip.src, ip.dst)
        counter[pair] += 1

    if not counter:
        raise RuntimeError("No IP packets found in the PCAP.")

    (best_pair, _count) = counter.most_common(1)[0]
    return best_pair


def _pcap_to_json_for_pair(
    pcap_path: Path,
    pair: HostPair,
) -> List[PacketJSON]:
    """
    只保留指定 host pair 的 TCP/UDP 包，生成 JSON packet 列表。
    时间戳使用 PCAP 原始 timestamp。
    """
    pkts = rdpcap(str(pcap_path))
    result: List[PacketJSON] = []

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
        payload_str = ""

        if TCP in pkt:
            tcp = pkt[TCP]
            proto = "TCP"
            sport = int(tcp.sport)
            dport = int(tcp.dport)

            flags = int(tcp.flags)
            parts = []
            if flags & 0x02:
                parts.append("SYN")
            if flags & 0x10:
                parts.append("ACK")
            if flags & 0x01:
                parts.append("FIN")
            if flags & 0x08:
                parts.append("PSH")
            if flags & 0x04:
                parts.append("RST")
            flags_str = "-".join(parts) if parts else ""

            seq = int(tcp.seq)
            ack = int(tcp.ack)
        elif UDP in pkt:
            udp = pkt[UDP]
            proto = "UDP"
            sport = int(udp.sport)
            dport = int(udp.dport)
        else:
            # 非 TCP/UDP 就忽略（你的项目本来只支持这两个协议）
            continue

        # 负载：尽量 decode 成字符串
        if Raw in pkt:
            raw_bytes: bytes = bytes(pkt[Raw].load)
            try:
                payload_str = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                payload_str = ""

        pkt_json: PacketJSON = {
            "timestamp": ts,
            "protocol": proto,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "flags": flags_str,
            "seq": seq,
            "ack": ack,
            "payload": payload_str,
        }
        result.append(pkt_json)

    # 保证按时间排序（一般 PCAP 本来就是按时间，但这里再稳一遍）
    result.sort(key=lambda p: p["timestamp"])
    return result


def _filter_pcap_for_pair(pcap_path: Path, pair: HostPair, out_pcap: Path) -> None:
    """把只包含这两台主机的 IP 包写入新的 PCAP 文件。"""
    pkts = rdpcap(str(pcap_path))
    selected = []

    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if _normalize_pair(ip.src, ip.dst) == pair:
            selected.append(pkt)

    if not selected:
        raise RuntimeError(f"No packets for host pair {pair} in PCAP.")

    wrpcap(str(out_pcap), selected)


def main() -> None:
    # 你老师给的大 PCAP 文件名，自行改成真实文件名
    # 比如 baseline/teacher_trace.pcap
    teacher_pcap = ROOT / "teacher_trace.pcap"
    if not teacher_pcap.is_file():
        raise SystemExit(
            f"Teacher PCAP not found: {teacher_pcap}\n"
            "请把老师给的 pcap 放到 baseline/ 目录，并改名为 teacher_trace.pcap，"
            "或者直接改脚本里的文件名。"
        )

    print(f"[info] Using teacher PCAP: {teacher_pcap}")

    # 1. 找到通信最多的那一对主机
    top_pair = _find_top_host_pair(teacher_pcap)
    print(f"[info] Most active host pair: {top_pair[0]} <-> {top_pair[1]}")

    # 2. 生成 JSON baseline demo
    json_packets = _pcap_to_json_for_pair(teacher_pcap, top_pair)
    demo_json_path = DEMO_DIR / "two_hosts_demo.json"
    demo_json_path.write_text(json.dumps(json_packets, indent=2), encoding="utf-8")
    print(f"[info] JSON baseline demo written to {demo_json_path}")

    # 3. 生成只包含该 host pair 的 PCAP → sample.pcap
    sample_pcap_path = ROOT / "sample.pcap"
    _filter_pcap_for_pair(teacher_pcap, top_pair, sample_pcap_path)
    print(f"[info] Baseline sample PCAP written to {sample_pcap_path}")

    print("[done] Baseline construction finished.")


if __name__ == "__main__":
    main()
