#!/usr/bin/env python3
"""Replay AliOS native iPerf with explicit corrected-clock and original-rate boundaries."""
import argparse
from datetime import datetime
import json
import hashlib
import math
from pathlib import Path
import re
import statistics
import struct

from audit_esp32_alios_iperf_readiness import audit as readiness
from audit_esp32_iperf_original import ANSI, HOST, CASES
from audit_esp32_riot_original import check_manifest, digest

COHORT = "captures-v1"
REPORT = re.compile(r"\[iperf_display_report:1067\], time = (\d+), h_ms_time = (\d+), "
                    r"GBytes = (\d+), MBytes = (\d+), KBytes= (\d+), Bytes= (\d+) "
                    r"(\[Total\])?(TCP|UDP) (Client|Server) Bandwidth: "
                    r"(?:(\d+) Gbits )?(?:(\d+) Mbits )?(?:(\d+) Kbits )?(\d+) bits/secReceive times: (\d+)")


def reports(text):
    result = []
    for match in REPORT.finditer(ANSI.sub("", text)):
        seconds, tenth, g, m, k, b = map(int, match.groups()[:6])
        divisor = seconds * 10 + tenth
        original = (((k * 80 & 0xffffffff) % divisor * 1024 + (b * 80 & 0xffffffff)) & 0xffffffff) // divisor if divisor else 0
        original += ((((m * 80 & 0xffffffff) % divisor * 1024 + (k * 80 & 0xffffffff)) & 0xffffffff) // divisor) * 1024 if divisor else 0
        original += ((((g * 80 & 0xffffffff) % divisor * 1024 + (m * 80 & 0xffffffff)) & 0xffffffff) // divisor) * 1024 ** 2 if divisor else 0
        original += ((g * 80 & 0xffffffff) // divisor) * 1024 ** 3 if divisor else 0
        printed = sum(int(value or 0) * 1024 ** exponent for value, exponent in zip(match.groups()[9:13], (3, 2, 1, 0)))
        total = g * 1024 ** 3 + m * 1024 ** 2 + k * 1024 + b
        exact_integer = total * 80 // divisor if divisor else 0
        if printed != original or tenth >= 10 or not total or not divisor:
            raise ValueError("original native rate/counter arithmetic differs")
        result.append({"duration_s": divisor / 10, "bytes": total, "calls": int(match[14]),
                       "total": bool(match[7]), "protocol": match[8], "role": match[9],
                       "original_bit_s": printed, "rate_arithmetic_eligible": printed == exact_integer,
                       "recomputed_original_counter_bit_s": exact_integer,
                       "original_unsigned_arithmetic_wrap": printed != exact_integer})
    if not result:
        raise ValueError("complete original native counter/report output missing")
    return result


def wire(path, case):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", data, 20)[0] != 1:
        raise ValueError("unsupported original packet capture")
    position, times, udp_ids, udp_fin, udp_sizes, tcp, peer_finals = 24, [], [], [], set(), [], []
    source = bytes((192, 168, 4, 1 if case.endswith("tx") else 2))
    destination = bytes((192, 168, 4, 2 if case.endswith("tx") else 1))
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated packet record")
        sec, us, size, actual = struct.unpack_from("<4I", data, position)
        position += 16
        if size > 96 or size > actual or position + size > len(data) or us >= 1000000:
            raise ValueError("invalid packet bounds/time")
        frame = data[position:position + size]
        position += size
        if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            raise ValueError("not the selected IPv4 native stream")
        header = (frame[14] & 15) * 4
        if header < 20 or struct.unpack_from("!H", frame, 20)[0] & 0x3fff:
            raise ValueError("unsupported fragment/header")
        offset = 14 + header
        if case == "udp_tx" and frame[23] == 17 and frame[26:30] == destination and frame[30:34] == source:
            if struct.unpack_from("!H", frame, offset)[0] == 5001 and offset + 60 <= len(frame):
                ident = struct.unpack_from("!i", frame, offset + 8)[0]
                fields = struct.unpack_from("!10I", frame, offset + 20)
                if ident >= 0 or fields[0] != 0x80000000 or fields[4] >= 1000000:
                    raise ValueError("invalid original peer final statistics")
                peer_finals.append({"bytes": fields[1] * 2 ** 32 + fields[2],
                                    "duration_us": fields[3] * 1000000 + fields[4]})
        if frame[26:30] != source or frame[30:34] != destination:
            continue
        sport, dport = struct.unpack_from("!HH", frame, offset)
        if dport != 5001:
            continue
        stamp = sec + us / 1000000
        if frame[23] == 17 and case.startswith("udp"):
            length = struct.unpack_from("!H", frame, offset + 4)[0] - 8
            ident = struct.unpack_from("!i", frame, offset + 8)[0]
            (udp_ids if ident >= 0 else udp_fin).append(ident)
            udp_sizes.add(length)
            times.append(stamp)
        elif frame[23] == 6 and case.startswith("tcp"):
            if offset + 20 > len(frame):
                raise ValueError("missing native TCP header")
            length = struct.unpack_from("!H", frame, 16)[0] - header - (frame[offset + 12] >> 4) * 4
            if length > 0:
                sequence = struct.unpack_from("!I", frame, offset + 4)[0]
                tcp.append((sequence, sequence + length))
                times.append(stamp)
    if not times or any(b < a - 0.0000011 for a, b in zip(times, times[1:])):
        raise ValueError("missing traffic or invalid packet clock chronology")
    unique = 0
    end = None
    if tcp:
        origin = tcp[0][0]
        tcp = [((start - origin) & 0xffffffff, ((start - origin) & 0xffffffff) + stop - start) for start, stop in tcp]
    for start, stop in sorted(tcp):
        if end is not None and start > end:
            raise ValueError("TCP packet capture has a sequence gap")
        unique += stop - max(start, end or start) if end is None or stop > end else 0
        end = max(stop, end or stop)
    return {"observed_duration_s": times[-1] - times[0], "first_packet_utc": datetime.fromtimestamp(times[0]).astimezone().isoformat(),
            "udp_packets": len(udp_ids), "udp_fin": udp_fin, "udp_sizes": sorted(udp_sizes),
            "udp_unique_sequence_numbers": len(set(udp_ids)), "tcp_unique_payload_bytes": unique,
            "udp_max_sequence_number": max(udp_ids) if udp_ids else None,
            "peer_final_statistics": peer_finals,
            "sha256": digest(path)}


def capture(directory, case, seconds=60, *, board_bssid="84:1f:e8:8f:55:dd"):
    from audit_esp32_zephyr_thread import read_raw_capture
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", board_bssid):
        raise ValueError("Invalid native AP identity")
    raw_bytes = (directory / "uart.raw").read_bytes()
    raw = raw_bytes.decode("utf-8", errors="replace")
    rows = read_raw_capture(directory, "", prefix="uart", allow_legacy=seconds != 60)
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])) or \
            raw.count("Native AliOS lwIP iPerf ready: AP 192.168.4.1 channel 1") != 1 or \
            raw.count("Welcome to AliOS Things") != 1 or raw.count("cpu_start: Starting scheduler on PRO CPU") != 1 or \
            "Set iperf debug to 4(0x4)" not in raw or re.search(r"Fatal Error|Guru Meditation|ASSERT|Exception", raw):
        raise ValueError("native reset/fault/clock chronology differs")
    resets = re.findall(r"rst:0x([0-9a-f]+) \(([A-Z_]+)\)", raw)
    if resets and resets != [("1", "POWERON_RESET")]:
        raise ValueError("readable native ROM reset reason differs")
    measurements = reports(raw)
    if measurements != reports("".join(row["line"] for row in rows)):
        raise ValueError("raw UART and decoded original reports differ")
    finals = [row for row in measurements if row["total"]]
    tx, udp = case.endswith("tx"), case.startswith("udp")
    if len(finals) != 1 or any(row["protocol"] != ("UDP" if udp else "TCP") or
                             row["role"] != ("Client" if tx else "Server") for row in measurements):
        raise ValueError("native protocol/direction/aggregate differs")
    final = finals[0]
    intervals = [row for row in measurements if not row["total"]]
    if len(intervals) not in (seconds // 10 - 1, seconds // 10) or any(row["duration_s"] != 10 for row in intervals) or \
            sum(row["bytes"] for row in intervals) > final["bytes"] or sum(row["calls"] for row in intervals) > final["calls"]:
        raise ValueError("native original interval/counter coverage differs")
    actions = json.loads((directory / "actions.json").read_text())
    if sum(row.get("capture_complete") is True for row in actions) != 1 or \
            sum("hardware_reset" in row for row in actions) != 1 or \
            [row["packet_returncode"] for row in actions if "packet_returncode" in row] != [0]:
        raise ValueError("native acquisition/packet completion missing")
    links = [row["output"] for row in actions if row.get("arguments", [])[:2] == ["iw", "dev"]]
    if len(links) != 2 or any("Connected to " + board_bssid not in link or "freq: 2412" not in link for link in links):
        raise ValueError("native endpoint/channel differs")
    commands = [row["host_command"] for row in actions if "host_command" in row]
    board = [row["board_command"] for row in actions if row.get("board_command", "").startswith("iperf -c") or
             row.get("board_command", "").startswith("iperf -s")]
    expected = f"iperf {'-c 192.168.4.2' if tx else '-s'} -i" + (f" -t {seconds}" if tx else "")
    if udp:
        expected += " -u" + (" -b 10m -l 1470" if tx else "")
    if len(commands) != 1 or board != [expected] or ("-u" in commands[0]) != udp or ("-s" in commands[0]) != tx or \
            (udp and not tx and commands[0][commands[0].index("-b") + 1] != "10000000"):
        raise ValueError("native original CLI/peer conditions differ")
    expected_peer = [commands[0][0], "-B", "192.168.4.2", "-i", "3", "-f", "m"]
    expected_peer += ["-s"] if tx else ["-c", "192.168.4.1", "-t", str(seconds)]
    if udp:
        expected_peer += ["-u"] + ([] if tx else ["-b", "10000000", "-l", "1470"])
    if commands[0] != expected_peer:
        raise ValueError("native original peer parameters differ")
    packet = wire(directory / "network.pcap", case)
    if abs(final["duration_s"] - seconds) > 1 or abs(packet["observed_duration_s"] - seconds) > 1.5:
        raise ValueError("native time disagrees with independent packet clock")
    host = [m for line in (directory / "host.log").read_text().splitlines() if (m := HOST.fullmatch(line.strip()))]
    aggregates = [m for m in host if float(m[1]) == 0 and abs(float(m[2]) - seconds) < 1.5]
    if not host or (not udp and len(aggregates) != 1):
        raise ValueError("native paired peer aggregate missing")
    if udp and packet["udp_sizes"] != [1470]:
        raise ValueError("native datagram size differs")
    if tx and not udp and packet["tcp_unique_payload_bytes"] != final["bytes"]:
        raise ValueError("native sender byte count disagrees with stream sequence coverage")
    if tx and not udp:
        peer = aggregates[0]
        scale = 1024 ** ("KMG".index(peer[4]) + 1) if peer[4] else 1
        transfer_error = 0.5 * 10 ** (-len(peer[3].split(".")[1])) if "." in peer[3] else 0.5
        if abs(float(peer[3]) * scale - final["bytes"]) > transfer_error * scale:
            raise ValueError("original TCP peer transfer differs from captured byte count")
        lower = final["bytes"] * 8 / (float(peer[2]) + 0.05) / 1000000
        upper = final["bytes"] * 8 / (float(peer[2]) - 0.05) / 1000000
        if float(peer[5]) + 0.0051 < lower or float(peer[5]) - 0.0051 > upper:
            raise ValueError("original TCP peer rate differs from byte/time rounding bounds")
    if not tx and not udp and packet["tcp_unique_payload_bytes"] != final["bytes"]:
        raise ValueError("native receiver byte count disagrees with stream sequence coverage")
    if udp and tx and (len(packet["udp_fin"]) != 1 or -packet["udp_fin"][0] < final["calls"] or
                      packet["udp_unique_sequence_numbers"] > final["calls"] or
                      packet["udp_max_sequence_number"] >= -packet["udp_fin"][0] or final["bytes"] != final["calls"] * 1470):
        raise ValueError("native UDP sender counter/FIN differs")
    if udp and not tx and (final["bytes"] != final["calls"] * 1470 or final["calls"] > packet["udp_packets"] + len(packet["udp_fin"])):
        raise ValueError("native UDP receive counter exceeds the captured stream")
    if udp and tx:
        finals_peer = packet["peer_final_statistics"]
        if len(finals_peer) != 1 or len(aggregates) != 1 or finals_peer[0]["bytes"] != packet["udp_packets"] * 1470 or \
                abs(finals_peer[0]["duration_us"] / 1000000 - packet["observed_duration_s"]) > 0.1:
            raise ValueError("original UDP peer byte/time final differs from packet trace")
        peer_rate = finals_peer[0]["bytes"] * 8 / finals_peer[0]["duration_us"]
        if abs(peer_rate - float(aggregates[0][5])) > 0.0051:
            raise ValueError("original UDP peer displayed rate differs from final wire statistics")
    receiver = float(aggregates[0][5]) if tx else final["recomputed_original_counter_bit_s"] / 1000000
    if "0 packets dropped by kernel" not in (directory / "pcap.log").read_text():
        raise ValueError("packet observer lost records")
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "original_reports": measurements,
            "board_total": final, "wire": packet, "receiver_decimal_mbit_s": receiver,
            "receiver_rate_source": "original host receiver" if tx else "wide-integer replay of original received-byte/time formula",
            "udp_loss": None, "udp_jitter_ms": None, "ranking_eligible": False,
            "udp_boundary": "native RX counts the FIN payload and has no loss/jitter accounting; native TX sequences include failed sends and timestamp microseconds are milliseconds" if udp else None}


def audit(directory):
    admission = readiness(directory)
    check_manifest(directory, "performance.sha256")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "performance.sha256").read_text().splitlines()}
    required = {"image.sha256", "capture.sha256", "official-source.json", "network-dependencies.json",
                "measurement-preprocess.json", "iperf_task-preprocessed.c", "iperf_cli-preprocessed.c",
                "iperf-host", "host-dependencies/provenance.json", "host-dependencies/iperf-2.0.5.tar.gz",
                COHORT + "/runner.py", COHORT + "/host-before.json", COHORT + "/host-after.json"}
    required.update(f"{COHORT}/{case}-reset{i}/{name}" for case in CASES for i in (1, 2, 3)
                    for name in ("uart.raw", "uart.jsonl", "host.log", "actions.json", "pcap.log", "network.pcap"))
    required.update(row["path"] for row in json.loads((directory / "network-dependencies.json").read_text())["files"])
    if not required <= covered:
        raise ValueError("native acquisition manifest coverage incomplete")
    if admission["unmodified_native_measurement_clock"] or admission["verified_native_link_archive_inputs"] != 25:
        raise ValueError("corrected reference clock/fixed native archives missing")
    host_proof = json.loads((directory / "host-dependencies/provenance.json").read_text())
    if digest(directory / "host-dependencies/iperf-2.0.5.tar.gz") != "636b4eff0431cea80667ea85a67ce4c68698760a9837e1e9d13096d20362265b" or \
            host_proof["iperf_binary_sha256"] != digest(directory / "iperf-host"):
        raise ValueError("original native peer source/binary differs")
    cases, captured = {}, []
    for case in CASES:
        cohort = [capture(directory / COHORT / f"{case}-reset{i}", case) for i in (1, 2, 3)]
        received = [row["receiver_decimal_mbit_s"] for row in cohort]
        cases[case] = {"captures": cohort,
                       "median_receiver_decimal_mbit_s": statistics.median(received) if all(v is not None for v in received) else None,
                       "ranking_eligible": False}
        captured.extend(cohort)
    captured.sort(key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captured, captured[1:])):
        raise ValueError("independent captures overlap")
    after = json.loads((directory / COHORT / "host-after.json").read_text())
    before = json.loads((directory / COHORT / "host-before.json").read_text())
    if any(row["returncode"] for row in after["cleanup"]) or not any(v in after["radio"]["output"] for v in ("disabled", "已禁用")):
        raise ValueError("temporary network session not restored")
    if "iperf version 2.0.5 " not in before["iperf"]["output"]:
        raise ValueError("original native peer version witness missing")
    return {"audit": "pass", "benchmark": "AliOS native iPerf, corrected hardware-reference clock adapter",
            "resets": 12, "cases": cases, "admission": admission, "ranking_eligible": False,
            "unmodified_official_measurement_method": False,
            "boundary": "original test bodies and counters; AP/stack/stdio/hardware-clock adaptation; wrapped original rates remain invalid, wide-integer analysis replay is explicitly separate"}


def render_table(result):
    lines = ["| AliOS native iPerf | Receiver Mbit/s, three boots | Median |",
             "| --- | --- | --- |"]
    for case in CASES:
        rows = result["cases"][case]
        values = [row["receiver_decimal_mbit_s"] for row in rows["captures"]]
        shown = " / ".join(f"{value:.3f}" if value is not None else "not eligible" for value in values)
        median = rows["median_receiver_decimal_mbit_s"]
        label = "AliOS iPerf / " + case.replace('_', ' ').upper()
        lines.append(f"| {label} | {shown} | {median:.3f} |" if median is not None else
                     f"| {label} | {shown} | not eligible |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    print(result, end="")
