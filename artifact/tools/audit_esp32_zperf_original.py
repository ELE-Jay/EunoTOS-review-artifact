#!/usr/bin/env python3
"""Replay native zperf results, final UDP wire statistics and exact image binding."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_resources import image_length
from audit_esp32_iperf_original import ANSI, HOST
from audit_esp32_zephyr_thread import read_raw_capture

UPSTREAM = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/"
CASES = ("udp_tx", "udp_rx", "tcp_tx", "tcp_rx")
TCP_RX_COHORT = "tcp-rx-clock-checked-v4"
IPERF_SHA = "636b4eff0431cea80667ea85a67ce4c68698760a9837e1e9d13096d20362265b"


def native_image(directory):
    data = (directory / "zephyr.bin").read_bytes()
    tail = image_length(data)
    if data[23] != 0:
        raise ValueError("not the native simple-boot RAM-only header")
    segments, position = [], 24
    for _ in range(data[1]):
        address, size = struct.unpack_from("<II", data, position)
        position += 8
        segments.append((address, data[position:position + size]))
        position += size
    position = tail
    while position < len(data):
        if position + 8 > len(data):
            raise ValueError("truncated native ROM segment header")
        address, size = struct.unpack_from("<II", data, position)
        position += 8
        if position + size > len(data) or not size:
            raise ValueError("invalid native ROM segment length")
        payload = data[position:position + size]
        if address == 0:
            if any(payload):
                raise ValueError("nonzero native flash alignment padding")
        else:
            if not (0x400D0000 <= address < 0x40400000 or 0x3F400000 <= address < 0x3F800000) or \
                    (position + 0x1000) % 65536 != address % 65536:
                raise ValueError("native ROM segment address/alignment mismatch")
            segments.append((address, payload))
        position += size
    ordered = sorted((address, address + len(payload)) for address, payload in segments)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("native allocated image segments overlap")
    with (directory / "zephyr.elf").open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf["e_machine"] != "EM_XTENSA" or \
                elf["e_entry"] != struct.unpack_from("<I", data, 4)[0]:
            raise ValueError("native ELF/BIN architecture or entry differs")
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_PROGBITS" or not section["sh_flags"] & 2 or not section["sh_size"]:
                continue
            start, size = section["sh_addr"], section["sh_size"]
            matches = [payload[start - address:start - address + size] for address, payload in segments
                       if address <= start and start + size <= address + len(payload)]
            if matches != [section.data()]:
                raise ValueError(("allocated native ELF section not bound to flashed image", section.name))


def printed_number(line, kind):
    units = {"m": 60000000, "s": 1000000, "ms": 1000, "us": 1} if kind == "time" else \
            {"Mbps": 1000000, "Kbps": 1000}
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s+(\w+)", line.strip())
    if not match or match[2] not in units:
        raise ValueError("unknown original output unit")
    scale = units[match[2]]
    decimals = len(match[1].split(".")[1]) if "." in match[1] else 0
    value, quantum = float(match[1]) * scale, scale / 10 ** decimals
    return {"original": line.strip(), "value": value, "resolution": quantum}


def printed(line, exact, kind):
    result = printed_number(line, kind)
    if not result["value"] <= exact < result["value"] + result["resolution"] + 1e-6:
        raise ValueError(("printed statistic differs from wire value/truncation", line, exact))
    return result


def udp_sender_rate(rate_line, duration_line, sent_packets):
    rate_match = re.fullmatch(r"Rate:\s*([^()]+)\s*\(([^()]+)\)", rate_line)
    duration_match = re.fullmatch(r"Duration:\s*([^()]+)\s*\(([^()]+)\)", duration_line)
    if not rate_match or not duration_match:
        raise ValueError("missing original UDP client report")
    rate = printed_number(rate_match[2], "rate")
    duration = printed_number(duration_match[2], "time")
    if duration["value"] <= 0 or rate["value"] <= 0:
        raise ValueError("nonpositive original UDP client duration/rate")
    # The shell truncates both duration and rate; test interval consistency, not fake precision.
    bits = sent_packets * 1024 * 8
    lower = bits * 1000000 / (duration["value"] + duration["resolution"])
    upper = bits * 1000000 / duration["value"]
    if max(lower, rate["value"]) >= min(upper, rate["value"] + rate["resolution"]):
        raise ValueError("original UDP client rate contradicts packet count/duration")
    return rate, duration


def wire(path, tx):
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1" or len(data) < 24 or struct.unpack_from("<I", data, 20)[0] != 1:
        raise ValueError("unsupported original pcap format/link layer")
    position, ids, final, stats, sizes, times = 24, [], [], [], set(), []
    sender = bytes([192, 168, 4, 1 if tx else 2])
    receiver = bytes([192, 168, 4, 2 if tx else 1])
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated pcap record")
        sec, usec, captured, actual = struct.unpack_from("<4I", data, position)
        position += 16
        if captured > actual or captured > 96 or position + captured > len(data) or usec >= 1000000:
            raise ValueError("invalid pcap bounds/timestamp")
        frame = data[position:position + captured]
        position += captured
        times.append(sec + usec / 1000000)
        if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            raise ValueError("not captured native IPv4/Ethernet traffic")
        header = (frame[14] & 15) * 4
        if header < 20 or frame[23] != 17 or struct.unpack_from("!H", frame, 20)[0] & 0x3FFF:
            raise ValueError("unsupported fragmented/non-UDP traffic")
        source, destination = frame[26:30], frame[30:34]
        udp = 14 + header
        if udp + 20 > len(frame):
            raise ValueError("missing native UDP datagram header")
        srcport, dstport, length, _ = struct.unpack_from("!4H", frame, udp)
        payload = frame[udp + 8:]
        ident, stamp_sec, stamp_usec = struct.unpack_from("!iII", payload)
        if source == sender and destination == receiver and dstport == 5001:
            if ident >= 0:
                if stamp_usec >= 1000000 or stamp_sec == stamp_usec == 0:
                    raise ValueError("native sender timestamp missing")
                ids.append(ident)
                sizes.add(length - 8)
            else:
                final.append(-ident)
        elif source == receiver and destination == sender and srcport == 5001:
            if ident >= 0 or len(payload) < 52:
                raise ValueError("missing original receiver final header")
            fields = struct.unpack_from("!10I", payload, 12)
            if fields[0] != 0x80000000 or fields[4] >= 1000000 or fields[9] >= 1000000:
                raise ValueError("invalid receiver original final fields")
            stats.append({"bytes": (fields[1] << 32) + fields[2],
                          "duration_us": fields[3] * 1000000 + fields[4],
                          "lost": fields[5], "outorder": fields[6], "datagrams": fields[7],
                          "jitter_us": fields[8] * 1000000 + fields[9]})
        else:
            raise ValueError("unrelated traffic in original benchmark capture")
    if not ids or sizes != {1024} or not final or len(set(final)) != 1 or not stats or \
            any(s != stats[0] for s in stats) or stats[0]["duration_us"] <= 0 or \
            any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("incomplete/contradictory native UDP handshake")
    return {"receiver": stats[0], "fin_sequence_magnitude": final[0], "observed_data_packets": len(ids),
            "observed_unique_ids": len(set(ids)), "observed_first_id": min(ids), "observed_last_id": max(ids),
            "pcap_sha256": digest(path)}


def capture(directory, case, require_consistent_clock=True, *, controlled=False):
    rows = read_raw_capture(directory, "", prefix="uart", allow_legacy=not controlled)
    pre_reset_lines = 0
    if controlled:
        actions = json.loads((directory / "actions.json").read_text())
        resets = [datetime.fromisoformat(r["utc"]) for r in actions if "hardware_reset" in r]
        witnesses = [i for i, r in enumerate(rows) if r["line"].startswith("rst:0x1 (")
                     and len(resets) == 1 and datetime.fromisoformat(r["utc"]) >= resets[0]]
        if len(witnesses) != 1:
            raise ValueError("Controlled EN reset witness missing or repeated")
        pre_reset_lines = witnesses[0]
        rows = rows[pre_reset_lines:]
    lines = [ANSI.sub("", row["line"]).replace("uart:~$ ", "").strip() for row in rows]
    text = "\n".join(lines)
    marker = b"*** Booting Zephyr OS build 3.7.0 ***"
    raw = (directory / "uart.raw").read_bytes()
    joined = "".join(row["line"] for row in rows)
    if marker not in raw or marker.decode() not in joined or re.sub(r"\s+", "", raw[raw.index(marker):].decode("utf-8")) != \
            re.sub(r"\s+", "", joined[joined.index(marker.decode()):]):
        raise ValueError("native UART text differs from preserved raw bytes")
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid capture chronology")
    if text.count("*** Booting Zephyr OS build 3.7.0 ***") != 1 or text.count("boot: chip revision: v1.1") != 1 or \
            next(row["elapsed_s"] for row in rows if "Booting Zephyr" in row["line"]) > 2 or \
            "Version: 1.1" not in lines or ("Link addr : " + ("34:98:7A:A2:85:28" if controlled else "84:1F:E8:8F:55:DC")) not in lines or \
            re.search(r"FATAL|PANIC|ASSERTION|Guru Meditation|Brownout|LAST PACKET NOT RECEIVED", text) or \
            any("<err>" in line and not line.endswith(("<err> esp32_wifi: Failed to send packet",
                "<err> net_zperf: Failed to receive packet (11)")) for line in lines):
        raise ValueError("native independent reset/version/interface/failure mismatch")
    actions = json.loads((directory / "actions.json").read_text())
    ats = [datetime.fromisoformat(row["utc"]) for row in actions]
    if any(t.utcoffset() is None for t in ats) or any(b < a for a, b in zip(ats, ats[1:])) or \
            sum(row.get("capture_complete") is True for row in actions) != 1 or \
            sum("hardware_reset" in row for row in actions) != 1:
        raise ValueError("uncompleted/invalid acquisition actions")
    protocol, direction = case.split("_")
    tx = direction == "tx"
    hosts = [row["host_command"] for row in actions if "host_command" in row]
    command = [row["board_command"] for row in actions if row.get("board_command", "").startswith("zperf " + protocol)]
    expected = f"zperf {protocol} " + ("upload 192.168.4.2 5001 60 1024" if tx else "download 5001")
    if tx and protocol == "udp":
        expected += " 10000000"
    suffix = (r"/esp32-network-udp-controlled-b1-v1/iperf-host$" if protocol == "udp" else
              r"/esp32-network-controlled-b1-v[12]/iperf-host$") if controlled else r"/zperf-original-v3/iperf-host$"
    if command != [expected] or len(hosts) != 1 or not re.search(suffix, hosts[0][0]):
        raise ValueError("original workload command/binary mismatch")
    expected_host = [hosts[0][0], "-B", "192.168.4.2", "-i", "3", "-f", "m"] + \
                    (["-s"] if tx else ["-c", "192.168.4.1", "-t", "60"])
    if protocol == "udp":
        expected_host += ["-u", "-l", "1024"]
        if not tx:
            expected_host += ["-b", "10000000"]
    if hosts[0] != expected_host:
        raise ValueError("native host binding/protocol/window/datagram/rate conditions differ")
    links = [row["output"] for row in actions if row.get("arguments", [])[:2] == ["iw", "dev"]]
    ap, ssid = ("34:98:7a:a2:85:29", "IoTOSBench-B1") if controlled else ("84:1f:e8:8f:55:dd", "ESP32-bench-55dc")
    if len(links) != 2 or any("Connected to " + ap not in line or "freq: 2412" not in line or
                              "SSID: " + ssid not in line for line in links):
        raise ValueError("native AP/channel/identity differs")
    host_text = (directory / "host.log").read_text()
    host_matches = [m for line in host_text.splitlines() if (m := HOST.fullmatch(line.strip()))]
    finals = [m for m in host_matches if float(m[1]) == 0 and 59 <= float(m[2]) <= 63]
    result = {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
              "uart_sha256": digest(directory / "uart.jsonl"), "raw_uart_sha256": digest(directory / "uart.raw"),
              "host_sha256": digest(directory / "host.log"), "actions_sha256": digest(directory / "actions.json"),
              "driver_send_failure_log_lines": sum(line.endswith("<err> esp32_wifi: Failed to send packet") for line in lines),
              "native_final_stat_receive_retry_log_lines": sum(line.endswith(
                  "<err> net_zperf: Failed to receive packet (11)") for line in lines),
              "link_signal_dbm": [int(re.search(r"signal: (-?\d+) dBm", link)[1]) for link in links]}
    if controlled:
        result["pre_reset_uart_lines_retained_outside_measured_boot"] = pre_reset_lines
    if protocol == "udp":
        packet_log = (directory / "pcap.log").read_text()
        if "0 packets dropped by kernel" not in packet_log or not any(
                row.get("packet_capture_returncode") == 0 for row in actions):
            raise ValueError("independent packet capture lost data/failed")
        record = wire(directory / "udp.pcap", tx)
        stats = record["receiver"]
        if not 59000000 <= stats["duration_us"] <= 63000000 or stats["bytes"] % 1024:
            raise ValueError("original receiver duration/byte total inconsistent")
        if tx:
            match = re.search(r"Num packets:\s*(\d+)\s*\((\d+)\)", text)
            if text.count("Upload completed!") != 1 or not match or int(match[1]) != stats["datagrams"] or \
                    int(match[2]) != record["fin_sequence_magnitude"]:
                raise ValueError("native sender/receiver packet counters differ from final handshake")
            fields = {"lost": "Num packets lost:", "outorder": "Num packets out order:"}
            rate_lines = [line for line in lines if line.startswith("Rate:") and "(" in line]
            jitter_lines = [line for line in lines if line.startswith("Jitter:")]
        else:
            if text.count("End of session!") != 1 or f"received packets:\t{stats['datagrams']}" not in text:
                raise ValueError("native receiver counter/complete session differs")
            fields = {"lost": "nb packets lost:", "outorder": "nb packets outorder:"}
            rate_lines = [line for line in lines if line.startswith("rate:")]
            jitter_lines = [line for line in lines if line.startswith("jitter:")]
        for key, label in fields.items():
            if len(values := re.findall(re.escape(label) + r"\s*(\d+)", text)) != 1 or int(values[0]) != stats[key]:
                raise ValueError("native original statistic not bound to wire header")
        if len(rate_lines) != 1 or len(jitter_lines) != 1:
            raise ValueError("missing original rate/jitter outputs")
        reports = []
        for match in finals:
            tail = re.fullmatch(r"\s*([\d.]+) ms\s+(\d+)/\s*(\d+)\s+\([\deE.+-]+%\)", match[6])
            if tail:
                reports.append((match, tail))
        if len(reports) != 1 or int(reports[0][1][2]) != stats["lost"] or \
                int(reports[0][1][3]) != stats["datagrams"] or \
                abs(float(reports[0][1][1]) - stats["jitter_us"] / 1000) > 0.002:
            raise ValueError("original host final loss/jitter not bound to wire statistics")
        exact_rate = stats["bytes"] * 8 * 1000000 // (stats["duration_us"] * 1000) * 1000
        result["receiver_rate_printed"] = printed(rate_lines[0].split(":", 1)[1].split("(")[0], exact_rate, "rate")
        result["jitter_printed"] = printed(jitter_lines[0].split(":", 1)[1], stats["jitter_us"], "time")
        if tx:
            durations = [line for line in lines if line.startswith("Duration:") and "(" in line]
            if len(durations) != 1:
                raise ValueError("missing/duplicate original UDP client duration")
            board_rate, board_duration = udp_sender_rate(rate_lines[0], durations[0], record["fin_sequence_magnitude"])
            result["original_board_duration_printed"] = board_duration
        else:
            board_rate = result["receiver_rate_printed"]
        result.update(original_board_decimal_mbit_s=board_rate["value"] / 1000000,
                      original_board_rate_resolution_mbit_s=board_rate["resolution"] / 1000000,
                      original_board_endpoint="sender" if tx else "receiver")
        result.update({"wire": record, "receiver_decimal_mbit_s": stats["bytes"] * 8 / stats["duration_us"],
                       "original_lost_packets": stats["lost"], "original_jitter_ms": stats["jitter_us"] / 1000,
                       "loss_measurement_eligible": tx,
                       "loss_boundary": "iPerf 2.0.5 original receiver loss convention" if tx else
                       "native zperf RX omits first data from bytes/count, reports sequence gaps and does not reconcile the tail against FIN"})
        if tx:
            if stats["datagrams"] != record["fin_sequence_magnitude"] or stats["outorder"] == 0 and \
                    stats["bytes"] // 1024 + stats["lost"] != stats["datagrams"]:
                raise ValueError("original host sequence-total/loss accounting differs")
            result["original_loss_percent"] = stats["lost"] * 100 / stats["datagrams"]
            result["receiver_counter_semantics"] = "iPerf server header datagrams is sequence total, not packets received"
        else:
            if stats["bytes"] != stats["datagrams"] * 1024:
                raise ValueError("original native RX byte/packet accounting differs")
            result["original_loss_percent"] = None
            result["receiver_counter_semantics"] = "zperf native RX counts data packets after first; different from host header"
    else:
        if len(finals) != 1 or ("Upload completed!" if tx else "TCP session ended") not in text:
            raise ValueError("native TCP final endpoint statistics absent")
        end_marker = "Upload completed!" if tx else "TCP session ended"
        complete_lines = lines[lines.index(end_marker):]
        rates = [line.split(":", 1)[1].strip() for line in complete_lines if line.startswith("Rate:" if tx else "rate:")]
        if len(rates) != 1:
            raise ValueError("duplicate/missing native TCP rate")
        token, unit = rates[0].split()
        rate = float(token) * {"Mbps": 1, "Kbps": 0.001}[unit]
        result.update({"host_decimal_mbit_s": float(finals[0][5]), "original_board_decimal_mbit_s": rate,
                       "receiver_decimal_mbit_s": float(finals[0][5]) if tx else rate})
        durations = [line.split(":", 1)[1].strip() for line in complete_lines if line.startswith("Duration:")]
        if len(durations) != 1:
            raise ValueError("native TCP duration missing/duplicated")
        result["original_board_duration_printed"] = printed_number(durations[0], "time")
    if not tx:
        begin = "New session started." if protocol == "udp" else "New TCP session started."
        end = "End of session!" if protocol == "udp" else "TCP session ended"
        starts = [row["elapsed_s"] for row, line in zip(rows, lines) if line == begin]
        ends = [row["elapsed_s"] for row, line in zip(rows, lines) if line == end]
        if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
            raise ValueError("native receive-session start/end witnesses differ")
        lower = stats["duration_us"] if protocol == "udp" else result["original_board_duration_printed"]["value"]
        quantum = 1 if protocol == "udp" else result["original_board_duration_printed"]["resolution"]
        span = ends[0] - starts[0]
        # This coarse one-second UART guard rejects clock failures; it is not clock calibration.
        consistent = lower / 1000000 - 1 <= span <= (lower + quantum) / 1000000 + 1
        result.update({"host_observed_receiver_callback_span_s": span,
                       "native_receiver_duration_interval_s": [lower / 1000000, (lower + quantum) / 1000000],
                       "receiver_clock_consistent": consistent, "measurement_eligible": consistent})
        if not consistent and require_consistent_clock:
            raise ValueError(("native receive clock differs from independent UART span", directory.name, span, lower, quantum))
    else:
        result["measurement_eligible"] = True
    if controlled:
        duration = stats["duration_us"] / 1000000 if protocol == "udp" else \
                   float(finals[0][2]) if tx else result["original_board_duration_printed"]["value"] / 1000000
        result.update(receiver_duration_s=duration, nominal_duration_guard_passed=59 <= duration <= 63)
    return result


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    originals = {"zperf.h": "include/zephyr/net/zperf.h", "esp_wifi_drv.c": "drivers/wifi/esp32/src/esp_wifi_drv.c"}
    for folder, prefix in (("source", "samples/net/zperf/"), ("zperf-library", "subsys/net/lib/zperf/")):
        for path in (directory / folder).rglob("*"):
            if path.is_file():
                originals[path.relative_to(directory).as_posix()] = prefix + path.relative_to(directory / folder).as_posix()
    proof_path = directory / "official-source.json"
    dependency = json.loads((directory / "dependencies/provenance.json").read_text())
    hal_prefix = dependency["hal_module_url"].rsplit("/zephyr/module.yml", 1)[0] + "/"
    urls = {relative: UPSTREAM + path for relative, path in originals.items()}
    urls.update({"esp_wifi_adapter.c": hal_prefix + "zephyr/esp32/src/wifi/esp_wifi_adapter.c",
                 "bin_image.py": hal_prefix + "tools/esptool_py/esptool/bin_image.py"})
    if verify_upstream:
        proof = []
        for relative, url in sorted(urls.items()):
            with urlopen(url, timeout=40) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / relative) != sha:
                raise ValueError(("original public source changed", relative))
            proof.append({"path": relative, "url": url, "sha256": sha})
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(urls) or {row["path"] for row in proof} != set(urls) or any(
            row["url"] != urls[row["path"]] or digest(directory / row["path"]) != row["sha256"] for row in proof):
        raise ValueError("original program/driver/image-generator provenance changed")
    check_manifest(directory, "capture.sha256")
    check_manifest(directory, TCP_RX_COHORT + ".sha256")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./")
               for name in ("capture.sha256", TCP_RX_COHORT + ".sha256")
               for line in (directory / name).read_text().splitlines()}
    required = {"flash.log", "runner.py", "captures-v3/host-before.json", "captures-v3/host-after.json"}
    for case in CASES:
        for reset in (1, 2, 3):
            required.update(f"captures-v3/{case}-reset{reset}/{name}" for name in
                            ("uart.raw", "uart.jsonl", "host.log", "actions.json"))
            if case.startswith("udp"):
                required.update(f"captures-v3/{case}-reset{reset}/{name}" for name in ("udp.pcap", "pcap.log"))
    required.update("rf-libraries/" + Path(row["path"]).name for row in dependency["rf_libraries"])
    required.update(TCP_RX_COHORT + "/" + name for name in ("host-before.json", "host-after.json"))
    required.update(f"{TCP_RX_COHORT}/tcp_rx-reset{reset}/{name}" for reset in (1, 2, 3)
                    for name in ("uart.raw", "uart.jsonl", "host.log", "actions.json"))
    if not required <= covered:
        raise ValueError("acquisition manifest omits required raw/host/Flash/binary/dependency evidence")
    if digest(directory / "dependencies/iperf-2.0.5.tar.gz") != IPERF_SHA or \
            dependency.get("iperf_binary_sha256") != digest(directory / "iperf-host"):
        raise ValueError("original host source/binary digest differs")
    for record in dependency["rf_libraries"]:
        if digest(directory / "rf-libraries" / Path(record["path"]).name) != record["sha256"]:
            raise ValueError("native linked RF library differs from official pinned digest")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000", "CONFIG_SYS_CLOCK_TICKS_PER_SEC=10000",
                    "CONFIG_MP_MAX_NUM_CPUS=1", "CONFIG_ESP_SIMPLE_BOOT=y", "CONFIG_HEAP_MEM_POOL_SIZE=98304",
                    "CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE=-1", "CONFIG_NET_PKT_RX_COUNT=10",
                    "CONFIG_NET_PKT_TX_COUNT=10", "CONFIG_NET_BUF_RX_COUNT=20", "CONFIG_NET_BUF_TX_COUNT=20",
                    "CONFIG_NET_ZPERF_MAX_PACKET_SIZE=1024"):
        if setting not in config:
            raise ValueError(("native network condition mismatch", setting))
    if "CONFIG_SMP=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("wrong native compiler/core profile")
    compiled = json.loads((directory / "compile_commands.json").read_text())
    for name in ("zperf_shell.c", "zperf_udp_receiver.c", "zperf_udp_uploader.c", "zperf_tcp_receiver.c", "zperf_tcp_uploader.c"):
        matches = [row for row in compiled if Path(row["file"]).name == name]
        if len(matches) != 1 or "/subsys/net/lib/zperf/" not in matches[0]["file"]:
            raise ValueError("original library missing from actual compiled sources")
    native_image(directory)
    flash = (directory / "flash.log").read_text()
    if "MAC: 84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 1 or \
            re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash) != [
                (str((directory / "zephyr.bin").stat().st_size), "0x00001000")]:
        raise ValueError("native installed image/MAC/length differs")
    base = directory / "captures-v3"
    for folder in (base, directory / TCP_RX_COHORT):
        before = json.loads((folder / "host-before.json").read_text())
        after = json.loads((folder / "host-after.json").read_text())
        if "iperf version 2.0.5 " not in before["iperf"]["output"] or any(row["returncode"] for row in after["cleanup"]) or \
                "已禁用" not in after["radio"]["output"] or before["routes"]["output"] != after["routes"]["output"]:
            raise ValueError("original host version or network restoration differs")
    cases, all_captures = {}, []
    for case in CASES:
        selected = directory / TCP_RX_COHORT if case == "tcp_rx" else base
        captures = [capture(selected / f"{case}-reset{i}", case) for i in (1, 2, 3)]
        values = [row["receiver_decimal_mbit_s"] for row in captures]
        cases[case] = {"captures": captures, "median_receiver_decimal_mbit_s": statistics.median(values),
                       "range_receiver_decimal_mbit_s": [min(values), max(values)], "ranking_eligible": False}
        if case.startswith("udp"):
            jitter = [row["original_jitter_ms"] for row in captures]
            cases[case].update({"median_original_jitter_ms": statistics.median(jitter),
                               "range_original_jitter_ms": [min(jitter), max(jitter)],
                               "original_lost_packets": [row["original_lost_packets"] for row in captures],
                               "loss_measurement_eligible": case.endswith("tx")})
            if case.endswith("tx"):
                loss = [row["original_loss_percent"] for row in captures]
                cases[case]["median_original_loss_percent"] = statistics.median(loss)
                cases[case]["range_original_loss_percent"] = [min(loss), max(loss)]
        all_captures.extend(captures)
    all_captures.sort(key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(all_captures, all_captures[1:])):
        raise ValueError("physical board capture intervals overlap")
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 original zperf + original iPerf 2.0.5",
            "os": "Zephyr 3.7.0", "resets": 12, "cores": 1, "clock_mhz": 240, "tick_hz": 10000,
            "cases": cases, "source_files": len(urls), "image_sha256": digest(directory / "zephyr.bin"),
            "ranking_eligible": False, "ranking_reason": "native profile/buffer differences; uncontrolled RF; no matched cross-OS cohort",
            "udp_rx_loss_boundary": "original first-data-packet omission and sequence-gap algorithm retained, not silently corrected",
            "excluded_tcp_rx_clock_cohort": [capture(base / f"tcp_rx-reset{i}", "tcp_rx", False) for i in (1, 2, 3)],
            "excluded": ["v1 zero-libc-arena boot", "v2 shell/AP-notification probes and exhausted-kernel-heap UDP run",
                         "v3 captures-v1 incomplete packet-capture closure/interrupted TCP pilot",
                         "v3 captures-v2 requested 1470 bytes exceeds native 1024-byte maximum",
                         "v3 captures-v3 original TCP RX trio: third native duration disagrees with host UART span"],
            "unsupported": ["controlled cross-OS network ranks", "network idle/transaction/sleep energy"]}


def render_tables(result):
    lines = ["| Original zperf condition, board direction | Receiver median, SI Mbit/s | Three-boot range, SI Mbit/s |",
             "| --- | ---: | ---: |"]
    for case in CASES:
        row = result["cases"][case]
        lo, hi = row["range_receiver_decimal_mbit_s"]
        lines.append(f"| zperf {case.upper().replace('_', ' ')} | {row['median_receiver_decimal_mbit_s']:.2f} | {lo:.2f}-{hi:.2f} |")
    lines.extend(["", "| Original UDP statistic | Three-reset observations | Interpretation |",
                  "| --- | --- | --- |"])
    for case in ("udp_tx", "udp_rx"):
        row = result["cases"][case]
        label = case.upper().replace("_", " ")
        jitter = " / ".join(f"{capture['original_jitter_ms']:.3f}" for capture in row["captures"])
        lost = " / ".join(str(value) for value in row["original_lost_packets"])
        lines.append(f"| {label} original receiver jitter, ms | {jitter} | Original final-header value; no cross-OS rank |")
        lines.append(f"| {label} original lost count | {lost} | Original receiver counter convention |")
        if row["loss_measurement_eligible"]:
            loss = " / ".join(f"{capture['original_loss_percent']:.3f}%" for capture in row["captures"])
            lines.append(f"| {label} original receiver loss percentage | {loss} | iPerf 2.0.5 sequence-total convention; no cross-OS rank |")
        else:
            lines.append(f"| {label} comparable loss percentage | Not qualified | First data omitted; FIN tail not reconciled |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    audited = audit(args.directory, args.verify_upstream)
    result = (render_tables(audited) if args.markdown else json.dumps(audited, indent=2)) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
