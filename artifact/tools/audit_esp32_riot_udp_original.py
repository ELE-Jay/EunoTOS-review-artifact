#!/usr/bin/env python3
"""Replay original RIOT UDP counters, units and recursive RTT from independent wire records."""
import argparse
from collections import deque
from datetime import datetime
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics
import struct

from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_riot_udp_readiness import audit as readiness
from audit_esp32_zephyr_thread import read_raw_capture

HOST, BOARD = "fd00:dead:beef::1", "fd00:dead:beef::2"
PROFILES = {"default": (100000, 32, []), "payload1024-interval1000": (1000, 1024, ["-i", "1000", "-s", "1024"])}
FIREWALL = ["-i", "wlxa41a3ad16459", "-s", BOARD + "/128", "-d", HOST + "/128", "-p", "udp",
            "--sport", "12345", "--dport", "12345", "-m", "comment", "--comment", "esp32-riot-udp-original", "-j", "ACCEPT"]
STAT = re.compile(r"fd00:dead:beef::2\s+(\d+) b/s\s+(\d+)\s+(\d+) \((\d+)%\)\s+(\d+) \((\d+)%\)\s+(\d+) \u00b5s\s+(\d+)")


def records(directory, name):
    rows = read_raw_capture(directory, "", prefix=name, allow_legacy=True)
    raw = (directory / (name + ".raw")).read_bytes().decode("utf-8", errors="replace")
    expected = [line.rstrip("\r") for line in raw.split("\n")]
    if expected[-1] == "":
        expected.pop()
    times = [datetime.fromisoformat(row["utc"]).timestamp() for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if [row["line"] for row in rows] != expected or not rows or \
            any(datetime.fromisoformat(row["utc"]).utcoffset() is None for row in rows) or \
            any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(x) or x < 0 for x in elapsed) or \
            any(b < a for a, b in zip(elapsed, elapsed[1:])) or \
            abs((times[-1] - times[0]) - (elapsed[-1] - elapsed[0])) > 0.1:
        raise ValueError("raw/parsed capture or physical chronology differs")
    return rows


def packets(path):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", data, 20)[0] != 1:
        raise ValueError("unsupported pcap link/timestamp format")
    position, result, previous, directional = 24, [], 0, {}
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated pcap record")
        sec, usec, captured, actual = struct.unpack_from("<4I", data, position)
        position += 16
        if usec >= 1000000 or not 54 <= captured <= min(96, actual) or position + captured > len(data):
            raise ValueError("pcap length/time bounds differ")
        frame = data[position:position + captured]
        position += captured
        stamp_us = sec * 1000000 + usec
        backstep = max(0, previous - stamp_us)
        if frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6:
            raise ValueError("non-native IPv6 frame")
        previous = stamp_us
        if actual != 54 + struct.unpack_from("!H", frame, 18)[0]:
            raise ValueError("IPv6/frame length differs")
        if frame[20] == 58:
            continue  # Native neighbor-discovery and the separate echo admission probe.
        if frame[20] != 17 or len(frame) < 74:
            raise ValueError("unsupported IPv6 extension/fragment/non-UDP frame")
        source, destination = (str(ipaddress.IPv6Address(frame[a:b])) for a, b in ((22, 38), (38, 54)))
        srcport, dstport, length, checksum = struct.unpack_from("!4H", frame, 54)
        if {source, destination} != {HOST, BOARD} or srcport != 12345 or dstport != 12345 or \
                length != actual - 54 or length < 20 or not checksum:
            raise ValueError("original peer/port/datagram bounds differ")
        # Ingress and egress can be queued to pcap in a different timestamp order.
        # Preserve file order, check each direction, then pair echo headers below.
        direction = source, destination
        if stamp_us < directional.get(direction, 0) - 1:
            raise ValueError("unordered timestamps within one UDP direction")
        directional[direction] = stamp_us
        result.append({"time": stamp_us / 1000000, "tx": source == BOARD, "size": length - 8,
                       "header": frame[62:78], "timestamp_backstep_us": backstep})
    if not result:
        raise ValueError("original traffic missing")
    return result


def replay_wire(wire, profile):
    interval, payload, _ = PROFILES[profile]
    commands = [packet for packet in wire if not packet["tx"] and packet["size"] == 12]
    cookies = set()
    for packet in commands:
        flags, delay, size = struct.unpack_from("<IIH", packet["header"])
        if flags & 0xff != 1 or delay != interval or size != payload:
            raise ValueError("original peer configuration handshake differs")
        cookies.add(flags & 0xffffff00)
    if len(cookies) != 1 or not next(iter(cookies), 0):
        raise ValueError("original session cookie missing/ambiguous")
    cookie = next(iter(cookies))
    pending, seen = deque(), False
    for packet in wire:
        if packet["tx"]:
            flags = struct.unpack_from("<I", packet["header"])[0]
            config = not seen or flags & 0xffffff00 != cookie
            seen = True
            pending.append((packet, config))
        else:
            if not pending:
                raise ValueError("original response without a captured request")
            request, config = pending.popleft()
            if packet["time"] < request["time"] or (config and packet["size"] != 12) or \
                    (not config and (packet["size"] != request["size"] or packet["header"] != request["header"])):
                raise ValueError("original echo/header response differs")
    if pending:
        raise ValueError("uncounted native socket loss or undrained peer requests")
    incoming = [packet for packet in wire if packet["tx"]]
    states, count, rtt, first = [], 0, 0, None
    for packet in incoming:
        if packet["size"] < 16 or len(packet["header"]) != 16:
            raise ValueError("original little-endian ping header missing")
        flags, seq, replies, sample = struct.unpack("<4I", packet["header"])
        if flags & 0xff:
            raise ValueError("configuration flag in original ping")
        count += 1
        if first is None or flags & 0xffffff00 != cookie:
            count, first = 0, packet["time"]
        else:
            if packet["size"] != payload + 16:
                raise ValueError("configured original packet size differs")
            if sample:
                rtt = (rtt + sample) // 2 if rtt else sample
        states.append({"time": packet["time"], "first": first, "tx": seq + 1, "rx": count,
                       "rt": replies, "rtt": rtt, "size": packet["size"]})
    if not states or not any(state["rx"] > 0 and state["rt"] > 0 for state in states):
        raise ValueError("native bidirectional test not established")
    return states


def capture(directory, profile, seconds=60, *, board_bssid="84:1f:e8:8f:55:dd"):
    from run_esp32_native_network_b1 import link_local
    address = link_local(board_bssid)
    uart, host = records(directory, "uart"), records(directory, "host")
    text = "\n".join(row["line"] for row in uart)
    if text.count("Single core mode") != 1 or text.count("RIOT UDP stress-test application") != 1 or \
            "HWaddr: " + board_bssid.upper() not in text or \
            re.search(r"panic|Guru Meditation|ASSERT|Exception|Error sending|Error receiving|can't resolve", text):
        raise ValueError("native boot/interface/failure witness differs")
    actions = json.loads((directory / "actions.json").read_text())
    times = [datetime.fromisoformat(row["utc"]).timestamp() for row in actions]
    if any(b < a for a, b in zip(times, times[1:])) or sum("hardware_reset" in row for row in actions) != 1 or \
            sum(row.get("capture_complete") is True and row.get("requested_seconds") == seconds for row in actions) != 1:
        raise ValueError("independent reset/window completion absent")
    board_commands = [row for row in actions if "board_command" in row]
    start = [row for row in board_commands if row["board_command"] == "bench_udp start " + HOST + " 12345"]
    end = [row for row in board_commands if row["board_command"] == "bench_udp stop"]
    if len(start) != 1 or len(end) != 1 or not seconds <= end[0]["elapsed_s"] - start[0]["elapsed_s"] <= seconds + 1 or \
            abs((datetime.fromisoformat(end[0]["utc"]) - datetime.fromisoformat(start[0]["utc"])).total_seconds() - seconds) > 1:
        raise ValueError("original workload physical window differs")
    commands = [row["board_command"] for row in board_commands]
    for command in ("ifconfig 8 add " + BOARD + "/64", "ifconfig 8 add " + address + "/64",
                    "nib prefix add 8 fd00:dead:beef::/64", "nib neigh show", "ps"):
        if command not in commands or command not in text:
            raise ValueError("native address/neighbor/termination setup absent")
    peers = [row["host_command"] for row in actions if "host_command" in row]
    if len(peers) != 1 or not peers[0][0].endswith("/riot-benchmark-udp-original-v2/host-source/bin/benchmark_server") or \
            peers[0][1:] != [*PROFILES[profile][2], HOST, "12345"]:
        raise ValueError("original host executable/arguments differ")
    links = [row["output"] for row in actions if row.get("arguments", [])[:2] == ["iw", "dev"]]
    if len(links) != 2 or any("Connected to " + board_bssid not in line or "freq: 2412" not in line for line in links):
        raise ValueError("original RF/interface identity differs")
    if "0 packets dropped by kernel" not in (directory / "pcap.log").read_text() or \
            not any(row.get("process") == "packet" and row.get("returncode") == 0 for row in actions):
        raise ValueError("independent wire capture lost data/failed")
    wire = packets(directory / "udp.pcap")
    states = replay_wire(wire, profile)
    indexed = {}
    for state in states:
        key = tuple(state[key] for key in ("tx", "rx", "rt", "rtt", "size"))
        indexed.setdefault(key, []).append(state)
    printed = []
    for row in host:
        match = STAT.fullmatch(row["line"].strip())
        if not match:
            continue
        bandwidth, tx, rx, rxpercent, rt, rtpercent, rtt, size = map(int, match.groups())
        if rxpercent != (100 * rx // tx if tx else 0) or rtpercent != (100 * rt // tx if tx else 0):
            raise ValueError("original integer percentage formula differs")
        stamp = datetime.fromisoformat(row["utc"]).timestamp()
        candidates = indexed.get((tx, rx, rt, rtt, size), [])
        # recvfrom/gettimeofday occur just after the kernel capture; allow only a boundary crossed within 250 ms.
        valid = [state for state in candidates if -0.01 <= stamp - state["time"] <= 0.5 and any(
            denominator > 0 and rx * size // denominator == bandwidth
            for denominator in {1 + now - first for now in (math.floor(state["time"]), math.floor(state["time"] + 0.25))
                                for first in (math.floor(state["first"]), math.floor(state["first"] + 0.25))})]
        if len(valid) != 1:
            raise ValueError(("original counter/recursive RTT/byte-rate replay differs", row, candidates[:1]))
        printed.append({"utc": row["utc"], "bandwidth_bytes_per_second": bandwidth, "num_tx_sequence_proxy": tx,
                        "num_rx": rx, "num_rt_proxy": rt, "receive_percent": rxpercent,
                        "roundtrip_percent": rtpercent, "recursive_rtt_us": rtt, "packet_bytes": size})
    if len(printed) < 10 or datetime.fromisoformat(printed[-1]["utc"]).timestamp() - \
            datetime.fromisoformat(start[0]["utc"]).timestamp() < seconds - 3 or \
            "UDP sender" in text[text.rfind("\tpid |"):] or "UDP receiver" in text[text.rfind("\tpid |"):] :
        raise ValueError("original output window/clean worker termination incomplete")
    diagnostics = ({"cross_direction_timestamp_backsteps_us": [p["timestamp_backstep_us"] for p in wire
                    if p["timestamp_backstep_us"] > 1]} if any(p["timestamp_backstep_us"] > 1 for p in wire) else {})
    return {"final_published_original_row": printed[-1], "audited_original_rows": len(printed),
            **diagnostics,
            "original_wire_data_packets": len(states), "first_utc": uart[0]["utc"], "last_utc": uart[-1]["utc"],
            "one_quantum_pcap_timestamp_backsteps": sum(packet["timestamp_backstep_us"] == 1 for packet in wire),
            "sha256": {name: digest(directory / name) for name in ("uart.raw", "uart.jsonl", "host.raw", "host.jsonl", "udp.pcap", "actions.json")}}


def audit(directory, dependencies):
    admission = readiness(directory, dependencies)
    check_manifest(directory, "performance.sha256")
    cohort = directory / "captures-v1"
    folders = ("captures-v1", "connection-probe-v1", "connection-probe-v2", "connection-probe-v3", "connection-probe-v4")
    if any(not (directory / folder).is_dir() for folder in folders):
        raise ValueError("historical connection diagnostic archive missing")
    expected_files = {path.resolve() for folder in folders for path in (directory / folder).rglob("*") if path.is_file()}
    manifest_files = [(directory / line.split(maxsplit=1)[1].lstrip("*")).resolve()
                      for line in (directory / "performance.sha256").read_text().splitlines()]
    if set(manifest_files) != expected_files or len(manifest_files) != len(expected_files):
        raise ValueError("performance/diagnostic archive manifest coverage differs")
    before, after = (json.loads((cohort / name).read_text()) for name in ("host-before.json", "host-after.json"))
    setup = json.loads((cohort / "firewall-setup.json").read_text())
    if before["scoped_firewall_rule"]["returncode"] != 1 or after["scoped_firewall_rule"]["returncode"] != 1 or \
            before["scoped_firewall_rule"]["arguments"] != ["ip6tables", "-C", "INPUT", *FIREWALL] or \
            after["scoped_firewall_rule"]["arguments"] != ["ip6tables", "-C", "INPUT", *FIREWALL] or \
            setup["arguments"] != ["ip6tables", "-I", "INPUT", "1", *FIREWALL] or \
            after["cleanup"][0]["arguments"] != ["ip6tables", "-D", "INPUT", *FIREWALL] or \
            [row["arguments"] for row in after["cleanup"][1:]] != [["nmcli", "connection", "delete", "esp32-benchmark-temporary"],
                ["nmcli", "radio", "wifi", "off"]] or \
            any(row["returncode"] for row in after["cleanup"]) or \
            setup["returncode"] != 0 or before["radio"]["output"].strip() not in ("disabled", "已禁用") or \
            after["radio"]["output"].splitlines()[1].split()[1] not in ("disabled", "已禁用"):
        raise ValueError("scoped firewall/link restoration differs")
    cases = {}
    for profile, (interval, payload, _) in PROFILES.items():
        resets = [capture(cohort / f"{profile}-reset{reset}", profile) for reset in range(1, 4)]
        values = [row["final_published_original_row"]["bandwidth_bytes_per_second"] for row in resets]
        cases[profile] = {"interval_us": interval, "payload_bytes": payload, "resets": resets,
                          "median_bytes_per_second": statistics.median(values), "range_bytes_per_second": [min(values), max(values)]}
    boot_times = [row["first_utc"] for case in cases.values() for row in case["resets"]]
    if len(set(boot_times)) != 6:
        raise ValueError("native independent reset repeated")
    return {"audit": "pass", "resets": 6, "source_files": admission["source_files"], "cases": cases,
            "network_performance_measured": True, "ranking_eligible": False,
            "image_sha256": admission["image_sha256"],
            "excluded": ["connection-probe-v1: address only, ping admission failed",
                         "connection-probe-v2: neighbor discovery succeeded, native ICMP Echo absent",
                         "connection-probe-v3: host IPv6 firewall rejected original UDP",
                         "connection-probe-v4: two 15-second connectivity diagnostics, not formal windows"],
            "boundary": "original b/s means bytes/s; RTT is recursive smoothing of the client's four-slot retained samples; TX/RT are sequence/reply proxies; no FIN, full-loss closure, maximum-throughput score or cross-OS ranking"}


def render_table(result):
    lines = ["| Original RIOT UDP condition | Published bandwidth median, B/s | Three-boot range, B/s | Original RX percent, three boots | Original recursive RTT, three boots, us |",
             "| --- | --- | --- | --- | --- |"]
    for profile, case in result["cases"].items():
        rows = [row["final_published_original_row"] for row in case["resets"]]
        percentages = " / ".join(str(row["receive_percent"]) for row in rows)
        rtts = " / ".join(str(row["recursive_rtt_us"]) for row in rows)
        low, high = case["range_bytes_per_second"]
        lines.append(f"| RIOT UDP {profile} | {case['median_bytes_per_second']:.0f} | {low}-{high} | {percentages} | {rtts} |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("dependencies", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.directory, args.dependencies)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")
