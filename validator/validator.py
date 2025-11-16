#!/usr/bin/env python3
"""
validator/validate_trace.py

Validation Metrics (see README):
- Timestamp consistency
- IP / Port pairing
- TCP state-machine validity
- SEQ / ACK continuity
- Payload and field sanity
"""

import argparse
import json
import sys
import ipaddress
from typing import List, Dict, Tuple, Any

Packet = Dict[str, Any]


# -------------------- Loader -------------------- #

def load_trace(path: str) -> List[Packet]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Top-level JSON must be a list of packet objects.")

    if not data:
        raise ValueError("Trace is empty (no packets).")

    return data


def get_flow_key(pkt: Packet) -> Tuple[str, int, str, int, str]:
    """
    Normalize a 5-tuple as a flow key:
    (min_ip, min_port, max_ip, max_port, protocol)

    Both directions of the same flow share one key.
    """
    proto = str(pkt.get("protocol", "")).upper()
    src_ip, dst_ip = pkt.get("src_ip"), pkt.get("dst_ip")
    src_port, dst_port = pkt.get("src_port"), pkt.get("dst_port")

    a = (src_ip, int(src_port))
    b = (dst_ip, int(dst_port))
    (ip1, p1), (ip2, p2) = sorted([a, b], key=lambda x: (x[0], x[1]))
    return (ip1, p1, ip2, p2, proto)


# -------------------- Individual Checks -------------------- #

def check_timestamp_consistency(packets: List[Packet]) -> List[str]:
    errors = []
    prev_ts = None

    for i, pkt in enumerate(packets):
        ts = pkt.get("timestamp", None)
        if not isinstance(ts, (int, float)):
            errors.append(f"[timestamp] Packet {i}: timestamp not a number ({ts!r})")
            continue

        if ts < 0:
            errors.append(f"[timestamp] Packet {i}: timestamp is negative ({ts})")

        if prev_ts is not None and ts <= prev_ts:
            errors.append(
                f"[timestamp] Packet {i}: timestamp {ts} not strictly increasing "
                f"(previous {prev_ts})"
            )

        prev_ts = ts

    return errors


def check_ip_port_pairing(packets: List[Packet]) -> List[str]:
    """
    - IP must be syntactically valid.
    - Port must be in [1, 65535].
    - Optionally warn if the trace has too many distinct hosts.
    """
    errors = []
    ips = set()

    for i, pkt in enumerate(packets):
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")

        # IP validity
        for role, ip in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            try:
                ipaddress.ip_address(ip)
            except Exception:
                errors.append(f"[ip/port] Packet {i}: {role} invalid ({ip!r})")
            else:
                ips.add(ip)

        # Port validity
        for role, port in (("src_port", src_port), ("dst_port", dst_port)):
            try:
                p = int(port)
            except (TypeError, ValueError):
                errors.append(f"[ip/port] Packet {i}: {role} not an integer ({port!r})")
                continue

            if not (1 <= p <= 65535):
                errors.append(
                    f"[ip/port] Packet {i}: {role} out of range 1–65535 ({p})"
                )

    if len(ips) > 10:
        errors.append(
            f"[ip/port] Trace has {len(ips)} distinct IPs (>10). "
            f"This may indicate unintended extra hosts."
        )

    return errors


def check_payload_and_field_sanity(packets: List[Packet]) -> List[str]:
    """
    Basic schema & type checks:
    - Required keys present
    - Types of protocol / flags / seq / ack / payload
    """
    errors = []
    required_keys = [
        "timestamp",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "flags",
        "seq",
        "ack",
        "payload",  # README uses payload as string
    ]

    for i, pkt in enumerate(packets):
        # Required fields
        for k in required_keys:
            if k not in pkt:
                errors.append(f"[fields] Packet {i}: missing required field '{k}'")

        protocol = pkt.get("protocol")
        if not isinstance(protocol, str):
            errors.append(f"[fields] Packet {i}: 'protocol' not a string ({protocol!r})")
        else:
            proto_upper = protocol.upper()
            if proto_upper not in {"TCP", "UDP"}:
                errors.append(
                    f"[fields] Packet {i}: unsupported protocol '{protocol}', "
                    f"expected 'TCP' or 'UDP'"
                )

        # Flags free-form string
        flags = pkt.get("flags")
        if not isinstance(flags, str):
            errors.append(f"[fields] Packet {i}: 'flags' should be string ({flags!r})")

        # SEQ / ACK must be integers
        for role in ("seq", "ack"):
            val = pkt.get(role)
            try:
                int(val)
            except (TypeError, ValueError):
                errors.append(
                    f"[fields] Packet {i}: '{role}' is not a valid integer ({val!r})"
                )

        # Payload should be string (we will derive payload_size from its length)
        payload = pkt.get("payload")
        if not isinstance(payload, str):
            errors.append(
                f"[fields] Packet {i}: 'payload' should be a string ({payload!r})"
            )

    return errors


def _payload_size_from_packet(pkt: Packet) -> int:
    """
    Derive a payload size from the 'payload' field.
    If payload is not a string or missing, treat as 0.
    """
    payload = pkt.get("payload", "")
    if isinstance(payload, str):
        try:
            return len(payload.encode("utf-8"))
        except Exception:
            return len(payload)
    return 0


def check_tcp_state_machine(packets: List[Packet]) -> List[str]:
    """
    Lightweight TCP state-machine check per flow.
    """
    errors = []

    # Group TCP packets by flow key
    flows = {}
    for i, pkt in enumerate(packets):
        proto = str(pkt.get("protocol", "")).upper()
        if proto != "TCP":
            continue
        key = get_flow_key(pkt)
        flows.setdefault(key, []).append((i, pkt))

    for key, pkts in flows.items():
        pkts_sorted = sorted(pkts, key=lambda x: x[1].get("timestamp", 0.0))

        syn_seen = False
        syn_ack_seen = False
        ack_seen = False

        for idx, (i, pkt) in enumerate(pkts_sorted):
            flags = str(pkt.get("flags", "")).upper()
            payload_size = _payload_size_from_packet(pkt)

            # SYN
            if "SYN" in flags and "ACK" not in flags:
                if syn_seen:
                    errors.append(
                        f"[tcp-sm] Flow {key}: duplicate SYN at packet {i}"
                    )
                syn_seen = True

            # SYN-ACK
            if "SYN" in flags and "ACK" in flags:
                syn_ack_seen = True

            # pure ACK (after SYN, SYN-ACK)
            if "ACK" in flags and "SYN" not in flags and syn_seen and syn_ack_seen and not ack_seen:
                ack_seen = True

            # Data before handshake completion?
            if payload_size > 0 and not ack_seen:
                errors.append(
                    f"[tcp-sm] Flow {key}: data before 3-way handshake completes (pkt {i})"
                )

        if syn_seen and not (syn_ack_seen and ack_seen):
            errors.append(
                f"[tcp-sm] Flow {key}: SYN seen but 3-way handshake not completed"
            )

        fin_seen = False
        fin_ack_seen = False
        for i, pkt in pkts_sorted:
            flags = str(pkt.get("flags", "")).upper()
            if "FIN" in flags:
                fin_seen = True
            if "FIN" in flags and "ACK" in flags:
                fin_ack_seen = True

        if fin_seen and not fin_ack_seen:
            errors.append(
                f"[tcp-sm] Flow {key}: FIN seen but no FIN-ACK in opposite direction"
            )

    return errors


def check_seq_ack_continuity(packets: List[Packet]) -> List[str]:
    """
    For each TCP flow & direction:
    - SEQ non-decreasing, advances on payload
    - ACK non-decreasing
    """
    errors = []

    flows = {}
    for i, pkt in enumerate(packets):
        proto = str(pkt.get("protocol", "")).upper()
        if proto != "TCP":
            continue
        key = get_flow_key(pkt)
        flows.setdefault(key, []).append((i, pkt))

    for key, pkts in flows.items():
        pkts_sorted = sorted(pkts, key=lambda x: x[1].get("timestamp", 0.0))
        per_dir_state = {}

        for i, pkt in pkts_sorted:
            dir_key = (
                pkt.get("src_ip"),
                int(pkt.get("src_port")),
                pkt.get("dst_ip"),
                int(pkt.get("dst_port")),
            )

            try:
                seq = int(pkt.get("seq"))
                ack = int(pkt.get("ack"))
                payload_size = _payload_size_from_packet(pkt)
            except (TypeError, ValueError):
                # Already caught by field_sanity
                continue

            state = per_dir_state.get(dir_key, {"last_seq": None, "last_ack": None})
            last_seq = state["last_seq"]
            last_ack = state["last_ack"]

            if last_seq is not None:
                if seq < last_seq:
                    errors.append(
                        f"[seq/ack] Flow {key}, dir {dir_key}: "
                        f"SEQ decreased at pkt {i} ({seq} < {last_seq})"
                    )
                if payload_size > 0 and seq == last_seq:
                    errors.append(
                        f"[seq/ack] Flow {key}, dir {dir_key}: "
                        f"payload_size={payload_size} but SEQ did not advance at pkt {i}"
                    )

            if last_ack is not None and ack < last_ack:
                errors.append(
                    f"[seq/ack] Flow {key}, dir {dir_key}: "
                    f"ACK decreased at pkt {i} ({ack} < {last_ack})"
                )

            state["last_seq"] = seq
            state["last_ack"] = ack
            per_dir_state[dir_key] = state

    return errors


# -------------------- Public API -------------------- #

def validate_trace(packets: List[Packet]) -> List[str]:
    """
    Main validator: return a list of error strings.
    If list is empty -> validation PASSED.
    """
    errors: List[str] = []
    errors.extend(check_timestamp_consistency(packets))
    errors.extend(check_ip_port_pairing(packets))
    errors.extend(check_payload_and_field_sanity(packets))
    errors.extend(check_tcp_state_machine(packets))
    errors.extend(check_seq_ack_continuity(packets))
    return errors


def validate_trace_file(path: str) -> List[str]:
    packets = load_trace(path)
    return validate_trace(packets)


# -------------------- CLI entrypoint -------------------- #

def _main_cli() -> None:
    parser = argparse.ArgumentParser(
        description="Validate an LLM-generated network packet trace (JSON)."
    )
    parser.add_argument("json_path", help="Path to JSON trace file.")
    args = parser.parse_args()

    try:
        errors = validate_trace_file(args.json_path)
    except Exception as e:
        print(f"[fatal] Failed to load/validate JSON trace: {e}", file=sys.stderr)
        sys.exit(1)

    if errors:
        print("Validation FAILED.")
        print(f"Total errors: {len(errors)}")
        for err in errors:
            print(" -", err)
        sys.exit(1)
    else:
        print("Validation PASSED.")
        sys.exit(0)


if __name__ == "__main__":
    _main_cli()

