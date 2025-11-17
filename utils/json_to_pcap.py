
#!/usr/bin/env python3
"""
utils/json_to_pcap.py

Convert a validated JSON trace (LLM output) into a PCAP file.

JSON packet format (see README):

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

import json
from typing import Any, Dict, List, Optional

from scapy.all import (  # type: ignore
    Ether,
    IP,
    TCP,
    UDP,
    Raw,
    wrpcap,
    rdpcap,
)

PacketJSON = Dict[str, Any]


def _map_tcp_flags(flags_str: str) -> str:
    """
    Map human-readable flag strings like 'SYN-ACK' to scapy's flag letters.

    Examples:
      'SYN'      -> 'S'
      'ACK'      -> 'A'
      'SYN-ACK'  -> 'SA'
      'FIN'      -> 'F'
      'FIN-ACK'  -> 'FA'
      'PSH-ACK'  -> 'PA'
      'RST'      -> 'R'
    """
    s = flags_str.upper().replace(" ", "").replace("_", "").replace("-", "")
    mapping = {
        "SYN": "S",
        "ACK": "A",
        "SYNACK": "SA",
        "FIN": "F",
        "FINACK": "FA",
        "PSH": "P",
        "PSHACK": "PA",
        "RST": "R",
        "RSTACK": "RA",
    }
    return mapping.get(s, "")  # unknown -> no flags


def _load_l2_template(reference_pcap: Optional[str]):
    """
    If a reference PCAP is provided and has an Ethernet header,
    we reuse its src/dst MAC addresses so that generated packets
    look more realistic at L2. Otherwise we return None.
    """
    if not reference_pcap:
        return None

    try:
        pkts = rdpcap(reference_pcap)
    except Exception:
        return None

    for pkt in pkts:
        if Ether in pkt:
            return pkt[Ether]  # use its src/dst
    return None


def _build_scapy_packet(pkt_json: PacketJSON, l2_template) -> Any:
    """
    Build a single scapy packet from one JSON packet description.
    """
    ts = float(pkt_json["timestamp"])
    proto = str(pkt_json["protocol"]).upper()
    src_ip = pkt_json["src_ip"]
    dst_ip = pkt_json["dst_ip"]
    src_port = int(pkt_json["src_port"])
    dst_port = int(pkt_json["dst_port"])
    flags_str = str(pkt_json.get("flags", ""))
    seq = int(pkt_json.get("seq", 0))
    ack = int(pkt_json.get("ack", 0))
    payload = pkt_json.get("payload", "")

    # L3 / L4
    ip_layer = IP(src=src_ip, dst=dst_ip)

    if proto == "TCP":
        tcp_flags = _map_tcp_flags(flags_str)
        l4 = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=tcp_flags)
    elif proto == "UDP":
        l4 = UDP(sport=src_port, dport=dst_port)
    else:
        # Unknown protocol, just create bare IP
        l4 = None

    # Payload
    if isinstance(payload, str) and payload != "":
        try:
            raw = Raw(load=payload.encode("utf-8"))
        except Exception:
            raw = Raw(load=str(payload))
    else:
        raw = None

    if l4 is not None:
        pkt = ip_layer / l4
    else:
        pkt = ip_layer

    if raw is not None:
        pkt = pkt / raw

    # If we have a L2 template (Ether), prepend it so we get src/dst MAC.
    if l2_template is not None:
        ether = Ether(src=l2_template.src, dst=l2_template.dst)
        pkt = ether / pkt

    # Set timestamp
    pkt.time = ts
    return pkt


def json_to_pcap(
    json_path: str,
    pcap_path: str,
    reference_pcap: Optional[str] = None,
) -> None:
    """
    Convert a JSON trace file into a PCAP file.

    Args:
        json_path:      Path to the JSON trace (LLM output).
        pcap_path:      Path to the PCAP to be written.
        reference_pcap: Optional path to a reference PCAP whose Ethernet
                        header (MAC addresses) will be reused. Can be None.

    This function assumes the JSON has already passed validator checks.
    """
    # Load JSON packets
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Top-level JSON must be a list of packet objects.")

    # Load L2 template if provided
    l2_template = _load_l2_template(reference_pcap)

    # Build scapy packets
    scapy_pkts: List[Any] = []
    for pkt_json in data:
        if not isinstance(pkt_json, dict):
            continue
        pkt = _build_scapy_packet(pkt_json, l2_template)
        scapy_pkts.append(pkt)

    if not scapy_pkts:
        raise ValueError("No valid packets parsed from JSON.")

    # Write to PCAP
    wrpcap(pcap_path, scapy_pkts)
