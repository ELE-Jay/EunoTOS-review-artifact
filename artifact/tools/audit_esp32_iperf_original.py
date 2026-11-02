#!/usr/bin/env python3
"""Audit original iPerf endpoint throughput, not unsupported UDP statistics."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
from urllib.request import urlopen

from audit_esp32_riot_original import check_manifest, digest

UPSTREAM = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/"
CASES = ("tcp_tx", "tcp_rx", "udp_tx", "udp_rx")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
BANDWIDTH = re.compile(r"\s*(\d+)-\s*(\d+) sec\s+(\d+\.\d+) Mbits/sec\s*")
HOST = re.compile(r"\[\s*\d+\]\s+(\d+\.\d+)-\s*(\d+\.\d+) sec\s+([\d.]+) ([KMG]?)Bytes\s+([\d.]+) Mbits/sec(.*)")


def capture(directory, case, *, controlled=False):
    # The shared reader imports the ANSI pattern above; resolve it after module initialization.
    from audit_esp32_zephyr_thread import read_raw_capture
    rows = read_raw_capture(directory, "", prefix="uart", allow_legacy=not controlled)
    pre_reset_rows = None
    if controlled and case.startswith("udp"):
        actions = json.loads((directory / "actions.json").read_text())
        resets = [datetime.fromisoformat(r["utc"]) for r in actions if "hardware_reset" in r]
        if len(resets) != 1:
            raise ValueError("Controlled UDP requires one explicit hardware reset")
        markers = [i for i, r in enumerate(rows) if "rst:0x" in r["line"] and
                   0 <= (datetime.fromisoformat(r["utc"]) - resets[0]).total_seconds() <= 2]
        if len(markers) != 1 or sum("rst:0x" in r["line"] for r in rows[markers[0]:]) != 1:
            raise ValueError("Controlled UDP measured reset boundary is missing or repeated")
        pre_reset_rows = markers[0]
        rows = rows[markers[0]:]
    lines = [ANSI.sub("", row["line"]) for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or any(
            not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("invalid timestamp chronology")
    if sum("2nd stage bootloader" in line for line in lines) != 1 or sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
            sum(("cpu_start: Unicore app" if controlled else "cpu_start: Multicore app") in line for line in lines) != 1 or \
            not any("cpu freq: 240000000 Hz" in line for line in lines) or any(
            re.search(r"Guru Meditation|panic|Assertion.*failed|Brownout", line) for line in lines):
        raise ValueError("board reset/clock/core/failure mismatch")
    tx = case.endswith("tx")
    udp = case.startswith("udp")
    mode = f"mode={'udp' if udp else 'tcp'}-{'client' if tx else 'server'}"
    if sum(mode in line and "interval=3, time=60" in line for line in lines) != 1:
        raise ValueError("wrong native protocol/direction/window")
    measurements = [BANDWIDTH.fullmatch(line) for line in lines]
    measurements = [(int(m[1]), int(m[2]), float(m[3])) for m in measurements if m]
    aggregate = [value for start, end, value in measurements if start == 0 and end == 60]
    intervals = [(start, end) for start, end, _ in measurements if end - start == 3]
    if len(aggregate) != 1 or aggregate[0] <= 0 or intervals != [(i, i + 3) for i in range(0, 60, 3)]:
        raise ValueError("incomplete original aggregate/report intervals")
    actions = json.loads((directory / "actions.json").read_text())
    ats = [datetime.fromisoformat(row["utc"]) for row in actions]
    if any(t.utcoffset() is None for t in ats) or any(b < a for a, b in zip(ats, ats[1:])) or \
            sum(row.get("capture_complete") is True for row in actions) != 1:
        raise ValueError("missing/invalid acquisition completion")
    commands = [row["host_command"] for row in actions if "host_command" in row]
    if len(commands) != 1:
        raise ValueError("missing original host endpoint")
    command = commands[0]
    required = {command[0] if controlled else "iperf", "-B", "192.168.4.2", "-i", "3", "-f", "m", "-s" if tx else "-c"}
    if not required <= set(command) or ("-u" in command) != udp or (not tx and "192.168.4.1" not in command):
        raise ValueError("host protocol/binding mismatch")
    if udp and not tx and command[command.index("-b") + 1] != "10000000":
        raise ValueError("UDP receive pilot used binary 10M, not the matched 10000000-bit/s offer")
    if controlled:
        expected = [command[0], "-B", "192.168.4.2", "-i", "3", "-f", "m"] + \
                   (["-s"] if tx else ["-c", "192.168.4.1", "-t", "60"])
        board = "iperf " + ("-c 192.168.4.2" if tx else "-s") + " -i 3 -t 60"
        if udp:
            expected += ["-u"] + ([] if tx else ["-b", "10000000"]) + ["-l", "1472"]
            board += " -u" + (" -b 10 -l 1472" if tx else "")
        else:
            expected += ["-l", "16384"]
            board += " -l 16384" if tx else ""
        suffix = r"/esp32-network-udp-controlled-b1-v1/iperf-host$" if udp else r"/esp32-network-controlled-b1-v[123456]/iperf-host$"
        if command != expected or not re.search(suffix, command[0]) or \
                [r["board_command"] for r in actions if r.get("board_command", "").startswith("iperf ")] != [board]:
            raise ValueError("Controlled original command/payload differs")
    links = [row["output"] for row in actions if row.get("arguments", [])[:2] == ["iw", "dev"]]
    ap, ssid = ("34:98:7a:a2:85:29", "IoTOSBench-B1") if controlled else ("84:1f:e8:8f:55:dd", "ESP32-bench-55dc")
    if len(links) != 2 or any("Connected to " + ap not in link or
                              "SSID: " + ssid not in link or "freq: 2412" not in link for link in links):
        raise ValueError("wrong measured AP/MAC/channel")
    host_text = (directory / "host.log").read_text()
    host = [m for line in host_text.splitlines() if (m := HOST.fullmatch(line.strip()))]
    host_aggregates = [m for m in host if float(m[1]) == 0 and 59.5 <= float(m[2]) <= 61.5]
    if not udp and len(host_aggregates) != 1:
        raise ValueError("TCP peer final aggregate missing")
    peer = float(host_aggregates[0][5]) if host_aggregates else None
    if controlled and udp and tx:
        # No FIN means iPerf2 may never emit its last data-triggered interval.
        # Validate the observed prefix, but do not report a receiver aggregate.
        peer_intervals = [(float(m[1]), float(m[2])) for m in host
                          if float(m[2]) - float(m[1]) == 3]
        if peer_intervals not in ([(i, i + 3) for i in range(0, 57, 3)],
                                  [(i, i + 3) for i in range(0, 60, 3)]):
            raise ValueError("UDP peer interval prefix missing or discontinuous")
    elif not host or max(float(m[2]) for m in host) < 59.5:
        raise ValueError("host endpoint observation incomplete")
    # IDF uses 2^20 in its original M-unit formatter; iPerf2 uses SI for -f m.
    receiver = peer if tx and not udp else aggregate[0] * 1.048576
    if tx and udp:
        receiver = None  # No complete receiver aggregate without the final UDP protocol handshake.
    result = {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "reset_evidence": "unique native second-stage boot and app initialization; ROM UART can be garbled",
            "original_board_m_unit": aggregate[0], "board_decimal_mbit_s": aggregate[0] * 1.048576,
            "host_decimal_mbit_s": peer, "receiver_decimal_mbit_s": receiver,
            "offered_udp_bit_s": 10000000 if udp else None,
            "udp_loss": None, "udp_jitter_ms": None,
            "udp_statistics_reason": "IDF lacks full final receiver statistics; TX timestamp fields are zero" if udp else None,
            "link_signal_dbm": [int(re.search(r"signal: (-?\d+) dBm", link)[1]) for link in links],
            "uart_sha256": digest(directory / "uart.jsonl"), "host_sha256": digest(directory / "host.log"),
            "actions_sha256": digest(directory / "actions.json")}
    if controlled:
        duration = (float(host_aggregates[0][2]) if host_aggregates else None) if tx else 60.0
        result.update(receiver_duration_s=duration,
                      nominal_duration_guard_passed=duration is not None and 59 <= duration <= 63)
        if pre_reset_rows is not None:
            result["pre_reset_uart_lines_retained_outside_measured_boot"] = pre_reset_rows
            result["measured_boot_boundary"] = "unique early ROM reset after the recorded explicit EN action; all raw bytes retained"
        if udp and tx:
            result["peer_interval_reported_through_s"] = max(end for _, end in peer_intervals)
            result["complete_receiver_aggregate_available"] = False
            result["receiver_observation_scope"] = "data-triggered interval prefix only; original IDF sender has no final UDP handshake"
    return result


def audit(directory, verify_upstream=False):
    check_manifest(directory, "image.sha256")
    originals = {}
    for folder, prefix in (("source", "examples/wifi/iperf/"), ("iperf-component", "examples/common_components/iperf/")):
        for path in (directory / folder).rglob("*"):
            if path.is_file() and path.name != "dependencies.lock" and not any(part.startswith("._") for part in path.parts):
                originals[path.relative_to(directory).as_posix()] = prefix + path.relative_to(directory / folder).as_posix()
    provenance_path = directory / "official-source.json"
    if verify_upstream:
        provenance = []
        for relative, official in sorted(originals.items()):
            with urlopen(UPSTREAM + official, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / relative) != sha:
                raise ValueError(("original iPerf source differs", relative))
            provenance.append({"path": relative, "url": UPSTREAM + official, "sha256": sha})
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    provenance = json.loads(provenance_path.read_text())
    if len(provenance) != len(originals) or {r["path"] for r in provenance} != set(originals) or any(
            r["url"] != UPSTREAM + originals[r["path"]] or digest(directory / r["path"]) != r["sha256"] for r in provenance):
        raise ValueError("original source provenance incomplete/changed")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1000", "CONFIG_ESP_WIFI_ENABLED=y"):
        if setting not in config:
            raise ValueError("native performance configuration mismatch")
    if "CONFIG_FREERTOS_UNICORE=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("wrong original dual-core/compiler profile")
    commands = json.loads((directory / "compile_commands.json").read_text())
    for source in ("cmd_wifi.c", "iperf_example_main.c", "iperf.c"):
        compiled = [row for row in commands if Path(row["file"]).name == source]
        if len(compiled) != 1 or not compiled[0]["file"].endswith(source) or " -O2 " not in compiled[0]["command"]:
            raise ValueError("original performance sources/compiler conditions absent")
    flash = (directory / "flash.log").read_text()
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or [
            (int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)
    ] != [((directory / name).stat().st_size, address) for name, address in
          (("bootloader.bin", 0x1000), ("partition-table.bin", 0x8000), ("iperf.bin", 0x10000))]:
        raise ValueError("network original Flash/MAC binding missing")
    cases = {}
    all_captures = []
    for case in CASES:
        base = directory / "udp-rx-decimal-v2" if case == "udp_rx" else directory
        captures = [capture(base / f"{case}-reset{i}", case) for i in (1, 2, 3)]
        for i in (1, 2, 3):
            uart = (base / f"{case}-reset{i}" / "uart.jsonl").read_text()
            if "ELF file SHA256:  " + digest(directory / "iperf.elf")[:9] + "..." not in uart:
                raise ValueError("native startup ELF fingerprint mismatch")
        if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
            raise ValueError("reset intervals overlap")
        receiver = [c["receiver_decimal_mbit_s"] for c in captures]
        board = [c["board_decimal_mbit_s"] for c in captures]
        cases[case] = {"captures": captures,
            "median_receiver_decimal_mbit_s": statistics.median(receiver) if all(v is not None for v in receiver) else None,
            "range_receiver_decimal_mbit_s": [min(receiver), max(receiver)] if all(v is not None for v in receiver) else None,
            "median_board_decimal_mbit_s": statistics.median(board), "range_board_decimal_mbit_s": [min(board), max(board)],
            "ranking_eligible": False, "reason": "single OS/AP topology; no matching other-OS ports or RF isolation"}
        all_captures.extend(captures)
    all_captures.sort(key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(all_captures, all_captures[1:])):
        raise ValueError("physical board captures overlap")
    for base in (directory, directory / "udp-rx-decimal-v2"):
        before = json.loads((base / "host-before.json").read_text())
        after = json.loads((base / "host-after.json").read_text())
        if "2.0.10" not in before["iperf"]["output"] or any(row["returncode"] for row in after["cleanup"]) or \
                "已禁用" not in after["radio"]["output"]:
            raise ValueError("peer version/temporary network restoration missing")
    return {"audit": "pass", "benchmark": "ESP-IDF 5.2.5 original iPerf example", "os": "FreeRTOS/ESP-IDF 5.2.5",
            "cores": 2, "clock_mhz": 240, "tick_hz": 1000, "resets": 12,
            "scope": "SoftAP channel 1, WPA/WPA2, original performance defaults; RF environment uncontrolled",
            "cases": cases, "source_files": len(originals), "binary_sha256": digest(directory / "iperf.bin"),
            "excluded_pilot": "original UDP RX 10M offer is 10485760 bit/s; retained, not pooled",
            "unsupported": ["complete UDP loss", "UDP jitter", "network idle/transaction/sleep energy", "cross-OS ranks"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
