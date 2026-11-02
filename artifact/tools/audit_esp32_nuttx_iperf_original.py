#!/usr/bin/env python3
"""Replay the unchanged NuttX iPerf throughput; unsupported UDP statistics stay absent."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import zipfile

from audit_esp32_iperf_original import ANSI, HOST, CASES
from audit_esp32_report import audit_flash
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_zperf_original import IPERF_SHA
from verify_esp32_nuttx_iperf_sources import urls, verify
from audit_esp32_zephyr_thread import read_raw_capture

COHORT = "captures-v3"
BANDWIDTH = re.compile(r"\s*(\d+\.\d+)-\s*(\d+\.\d+) sec\s+(\d+) Bytes\s+([\d.]+) Mbits/sec\s*")


def capture(directory, case, *, controlled=False):
    rows = read_raw_capture(directory, "", prefix="uart", allow_legacy=not controlled)
    joined = "".join(row["line"] for row in rows)
    marker = "NuttShell (NSH) NuttX-12.2.1"
    raw = (directory / "uart.raw").read_bytes()
    if marker.encode() not in raw or marker not in joined or re.sub(r"\s+", "", raw[raw.index(marker.encode()):].decode()) != \
            re.sub(r"\s+", "", joined[joined.index(marker):]):
        raise ValueError("native UART differs from raw bytes")
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])) or \
            abs((times[-1] - times[0]).total_seconds() - (elapsed[-1] - elapsed[0])) > 0.1:
        raise ValueError("invalid independent capture chronology")
    lines = [ANSI.sub("", row["line"]).replace("nsh> ", "").strip() for row in rows]
    text = "\n".join(lines)
    if lines.count(marker) != 1 or not any("NuttX  12.2.1 snapshot-nuttx-12.2.1" in line for line in lines) or \
            ("wlan0\tLink encap:Ethernet HWaddr " + ("34:98:7a:a2:85:29" if controlled else "84:1f:e8:8f:55:dd") + " at UP mtu 1500") not in lines or \
            "inet addr:192.168.4.1 DRaddr:0.0.0.0 Mask:255.255.255.0" not in lines or \
            re.search(r"PANIC|ASSERTION|Guru Meditation|Brownout|Exception|pthread_create failed|clock_gettime failed", text):
        raise ValueError("native boot/version/interface/failure mismatch")
    protocol, direction = case.split("_")
    tx, udp = direction == "tx", protocol == "udp"
    mode = "mode=" + protocol + ("-client" if tx else "-server")
    if sum(mode in line and "interval=3, time=60" in line for line in lines) != 1:
        raise ValueError("original protocol/direction/window mismatch")
    measurements = [(i, match) for i, line in enumerate(lines) if (match := BANDWIDTH.fullmatch(line))]
    finals = [(i, match) for i, match in measurements if float(match[1]) == 0 and 59.5 <= float(match[2]) <= 64]
    if len(finals) != 1 or finals[0] != measurements[-1] or float(finals[0][1][4]) <= 0:
        raise ValueError("original aggregate incomplete")
    intervals = measurements[:-1]
    if not intervals or float(intervals[0][1][1]) != 0 or len(intervals) < 19 or \
            any(not 2.9 <= float(m[2]) - float(m[1]) <= 4 for _, m in intervals) or \
            any(a[1][2] != b[1][1] for a, b in zip(intervals, intervals[1:])) or \
            intervals[-1][1][2] != finals[0][1][2]:
        raise ValueError("original report sequence incomplete")
    for _, match in measurements:
        duration = float(match[2]) - float(match[1])
        expected = int(match[3]) * 8 / 1e6 / duration
        # NuttX 12.2.1 dtoa keeps significant digits below 0.1 before fixed
        # formatting, so a sub-0.1 interval can truncate a decimal position.
        precision = .0101 if controlled and expected < .1 else .0051
        uncertainty = expected * 0.011 / max(duration - 0.011, 0.01) + precision
        if abs(float(match[4]) - expected) > uncertainty:
            raise ValueError("original byte/time/SI rate arithmetic differs")
    index, final = finals[0]
    header = [i for i, line in enumerate(lines) if "Interval" in line and "Transfer" in line and "Bandwidth" in line]
    if len(header) != 1 or header[0] >= intervals[0][0]:
        raise ValueError("original report-start witness missing")
    wall = elapsed[index] - elapsed[header[0]]
    if abs(wall - float(final[2])) > 1.01:
        raise ValueError("native CLOCK_MONOTONIC duration disagrees with independent capture")
    total = int(final[3])
    if sum(int(m[3]) for _, m in intervals) > total or (udp and total % 1472):
        raise ValueError("native aggregate/interval/datagram byte accounting differs")
    actions = json.loads((directory / "actions.json").read_text())
    ats = [datetime.fromisoformat(row["utc"]) for row in actions]
    if any(t.utcoffset() is None for t in ats) or any(b < a for a, b in zip(ats, ats[1:])) or \
            sum(row.get("capture_complete") is True for row in actions) != 1 or \
            sum("hardware_reset" in row for row in actions) != 1:
        raise ValueError("independent reset/completion missing")
    board = "iperf " + ("-c 192.168.4.2" if tx else "-s") + " -i 3 -t 60" + (" -u" if udp else "")
    for command in (("wapi psk wlan0 benchmark-only-b1 3", "wapi essid wlan0 IoTOSBench-B1 1") if controlled else
                    ("wapi psk wlan0 benchmark-only-55dc 3", "wapi essid wlan0 ESP32-bench-55dc 1")):
        if sum(row.get("board_command") == command for row in actions) != 1:
            raise ValueError("native runtime AP configuration missing")
    if [row["board_command"] for row in actions if row.get("board_command", "").startswith("iperf ")] != [board]:
        raise ValueError("not the native original iPerf command")
    commands = [row["host_command"] for row in actions if "host_command" in row]
    suffix = (r"/esp32-network-udp-controlled-b1-v1/iperf-host$" if udp else
              r"/esp32-network-controlled-b1-v[123456]/iperf-host$") if controlled else r"/nuttx-iperf-original-v5/iperf-host$"
    if len(commands) != 1 or not re.search(suffix, commands[0][0]):
        raise ValueError("wrong original peer binary")
    expected = [commands[0][0], "-B", "192.168.4.2", "-i", "3", "-f", "m"] + \
               (["-s"] if tx else ["-c", "192.168.4.1", "-t", "63"])
    if udp:
        expected += ["-u", "-l", "1472"]
        if not tx:
            expected += ["-b", "10000000"]
    if controlled and not udp:
        expected += ["-l", "16384"]
    if commands[0] != expected:
        raise ValueError("peer binding/window/offer/datagram conditions differ")
    links = [row["output"] for row in actions if row.get("arguments", [])[:2] == ["iw", "dev"]]
    ap, ssid = ("34:98:7a:a2:85:29", "IoTOSBench-B1") if controlled else ("84:1f:e8:8f:55:dd", "ESP32-bench-55dc")
    if len(links) != 2 or any("Connected to " + ap not in link or
                              "SSID: " + ssid not in link or "freq: 2412" not in link for link in links):
        raise ValueError("wrong measured AP/channel")
    host_text = (directory / "host.log").read_text()
    if udp and tx and "Receiving 1472 byte datagrams" not in host_text:
        raise ValueError("native UDP peer receive buffer truncates datagrams")
    host = [m for line in host_text.splitlines() if (m := HOST.fullmatch(line.strip()))]
    host_limit = 75 if controlled and tx else 65
    host_final = [m for m in host if float(m[1]) == 0 and 59 <= float(m[2]) <= host_limit]
    if not host or max(float(m[2]) for m in host) < 57 or (not udp and len(host_final) != 1):
        raise ValueError("peer observations/aggregate incomplete")
    peer = float(host_final[0][5]) if len(host_final) == 1 else None
    result = {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(),
            "board_bytes": total, "board_duration_s": float(final[2]), "observed_report_span_s": wall,
            "board_decimal_mbit_s": float(final[4]), "host_decimal_mbit_s": peer,
            "receiver_decimal_mbit_s": peer if tx and not udp else (None if tx else float(final[4])),
            "udp_offered_bit_s": 10000000 if udp and not tx else None,
            "host_requested_duration_s": None if tx else 63,
            "host_window_boundary": "RX peer remains active for 63 s; only the native approximately 60 s receive aggregate is selected" if not tx else None,
            "udp_loss": None, "udp_jitter_ms": None,
            "udp_boundary": "native sender is unpaced with zero timestamp and no FIN; native receiver does not account loss/jitter/FIN" if udp else None,
            "link_signal_dbm": [int(re.search(r"signal: (-?\d+) dBm", link)[1]) for link in links],
            "raw_uart_sha256": digest(directory / "uart.raw"), "uart_sha256": digest(directory / "uart.jsonl"),
            "host_sha256": digest(directory / "host.log"), "actions_sha256": digest(directory / "actions.json")}
    if controlled:
        duration = (float(host_final[0][2]) if host_final else None) if tx else float(final[2])
        result.update(receiver_duration_s=duration,
                      nominal_duration_guard_passed=duration is not None and 59 <= duration <= 63,
                      receiver_window_scope="original UDP receiver aggregate; no inferred missing final handshake" if udp else
                          "original receiver aggregate; extended TCP drain/teardown is not rescaled to a 60-second result")
    return result


def audit(directory):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    required = {"official-source.json", "rf-provenance.json", "rf-commit.json", "wireless-upstream.zip", "flash.log",
                "host-interface-capabilities.txt",
                "iperf-host", "host-dependencies/provenance.json", "host-dependencies/iperf-2.0.5.tar.gz",
                COHORT + "/runner.py", COHORT + "/host-before.json", COHORT + "/host-after.json"}
    required.update(f"{COHORT}/{case}-reset{i}/{name}" for case in CASES for i in (1, 2, 3)
                    for name in ("uart.raw", "uart.jsonl", "host.log", "actions.json"))
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not required <= covered:
        raise ValueError("acquisition manifest omits required evidence")
    proof = json.loads((directory / "official-source.json").read_text())
    originals = urls()
    if len(proof) != len(originals) or {row["path"] for row in proof} != set(originals) or any(
            row["url"] != originals[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("native original source identity differs")
    rf = json.loads((directory / "rf-provenance.json").read_text())
    commit = rf["commit"]
    if len(commit) != 40 or not commit.startswith("45701c0") or \
            json.loads((directory / "rf-commit.json").read_text())["sha"] != commit or \
            rf["commit_response_sha256"] != digest(directory / "rf-commit.json") or \
            rf["archive_url"] != "https://codeload.github.com/espressif/esp-wireless-drivers-3rdparty/zip/" + commit or \
            rf["archive_sha256"] != digest(directory / "wireless-upstream.zip"):
        raise ValueError("native fixed RF archive binding differs")
    with zipfile.ZipFile(directory / "wireless-upstream.zip") as package:
        actual = {p.relative_to(directory / "wireless-dependency").as_posix() for p in (directory / "wireless-dependency").rglob("*") if p.is_file()}
        if actual != {row["path"] for row in rf["files"]}:
            raise ValueError("RF file coverage incomplete")
        for row in rf["files"]:
            upstream = package.read("esp-wireless-drivers-3rdparty-" + commit + "/" + row["path"])
            if row["sha256"] != digest(directory / "wireless-dependency" / row["path"]) or \
                    row["sha256"] != hashlib.sha256(upstream).hexdigest():
                raise ValueError("native RF file differs from fixed original archive")
    host = json.loads((directory / "host-dependencies/provenance.json").read_text())
    if digest(directory / "host-dependencies/iperf-2.0.5.tar.gz") != IPERF_SHA or \
            host["iperf_binary_sha256"] != digest(directory / "iperf-host"):
        raise ValueError("native original peer source/binary changed")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_ARCH_CHIP_ESP32WROOM32=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240",
                    "CONFIG_USEC_PER_TICK=10000", "CONFIG_RR_INTERVAL=200", "CONFIG_ESP32_WIFI_SOFTAP=y",
                    "CONFIG_NETUTILS_IPERF=y", "CONFIG_NET_TCP=y", "CONFIG_NET_UDP=y",
                    "CONFIG_NETINIT_WAPI_STAMODE=3", 'CONFIG_NETINIT_WAPI_SSID=""',
                    'CONFIG_NETINIT_WAPI_PASSPHRASE="benchmark-only-55dc"'):
        if setting not in config:
            raise ValueError(("native profile differs", setting))
    if "CONFIG_SMP=y" in config or "CONFIG_DEBUG_FEATURES=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text() or \
            '#define CONFIG_VERSION_STRING "12.2.1"' not in (directory / "version-header.h").read_text():
        raise ValueError("core/compiler/debug/version differs")
    build = (directory / "build.log").read_text()
    for name in ("iperf.c", "iperf_main.c", "netinit_associate.c", "driver_wext.c"):
        if len([line for line in build.splitlines() if "xtensa-esp32-elf-gcc -c " in line and name + " -o " in line and " -Os " in line]) != 1:
            raise ValueError(("actual original compiled source missing", name))
    for lib in ("phy", "rtc", "core", "net80211", "pp", "smartconfig", "espnow", "wpa_supplicant"):
        if " -l" + lib + " " not in build or not (directory / "wireless-dependency/libs/esp32" / ("lib" + lib + ".a")).exists():
            raise ValueError("actual native RF link missing")
    audit_elf_image(directory / "nuttx", directory / "nuttx.bin")
    audit_flash(directory, "flash.log", 3)
    written = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())]
    if written != [((directory / name).stat().st_size, address) for name, address in
                   (("bootloader-esp32.bin", 0x1000), ("partition-table-esp32.bin", 0x8000), ("nuttx.bin", 0x10000))]:
        raise ValueError("native installed lengths/addresses differ")
    cases, captures = {}, []
    for case in CASES:
        cohort = [capture(directory / COHORT / f"{case}-reset{i}", case) for i in (1, 2, 3)]
        receiver = [row["receiver_decimal_mbit_s"] for row in cohort]
        board = [row["board_decimal_mbit_s"] for row in cohort]
        cases[case] = {"captures": cohort, "median_receiver_decimal_mbit_s": statistics.median(receiver) if all(v is not None for v in receiver) else None,
                       "range_receiver_decimal_mbit_s": [min(receiver), max(receiver)] if all(v is not None for v in receiver) else None,
                       "median_board_decimal_mbit_s": statistics.median(board), "range_board_decimal_mbit_s": [min(board), max(board)],
                       "ranking_eligible": False}
        captures.extend(cohort)
    captures.sort(key=lambda row: row["start_utc"])
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent board captures overlap")
    before = json.loads((directory / COHORT / "host-before.json").read_text())
    after = json.loads((directory / COHORT / "host-after.json").read_text())
    if "iperf version 2.0.5 " not in before["iperf"]["output"] or any(row["returncode"] for row in after["cleanup"]) or \
            not any(value in after["radio"]["output"] for value in ("disabled", "已禁用")):
        raise ValueError("peer version/temporary Wi-Fi restoration missing")
    capabilities = (directory / "host-interface-capabilities.txt").read_text()
    modes = capabilities.split("Supported interface modes:", 1)[1].split("Band 1:", 1)[0]
    if re.findall(r"\* (\S+)", modes) != ["managed", "monitor"]:
        raise ValueError("archived host interface modes differ")
    return {"audit": "pass", "benchmark": "NuttX 12.2.1 original native iPerf", "os": "NuttX 12.2.1",
            "source_files": len(proof), "rf_files": len(rf["files"]), "rf_revision": commit, "resets": 12,
            "cores": 1, "clock_mhz": 240, "tick_hz": 100, "rr_interval_ms": 200,
            "image_sha256": digest(directory / "nuttx.bin"), "ranking_eligible": False, "cases": cases,
            "selected_capture_cohort": COHORT, "host_ap_capable": False,
            "scope": "native SoftAP, original 16-KiB TCP buffers / 1472-byte UDP sender; uncontrolled RF",
            "excluded": ["v1 unflashed quoted-SSID build", "v2 boot/interface admission, no performance",
                         "v3 automatic association probes could not establish the native AP",
                         "v4 debug initialization diagnostic, not a performance profile",
                         "v5 captures-v1 stopped for the host's default 1470-byte UDP receive truncation",
                         "v5 captures-v2 had concurrent host dependency fetching; TCP RX reset2 closed before the original final report"],
            "unsupported": ["complete UDP session loss/jitter", "network idle/transaction/sleep energy", "cross-OS ranking"]}


def render_table(result):
    lines = ["| Original NuttX iPerf condition | Native board median, SI Mbit/s | Three-boot range | Receiver median, SI Mbit/s |",
             "| --- | ---: | ---: | ---: |"]
    for case in CASES:
        row = result["cases"][case]
        receiver = row["median_receiver_decimal_mbit_s"]
        low, high = row["range_board_decimal_mbit_s"]
        lines.append(f"| NuttX iPerf {case.replace('_', ' ').upper()} | {row['median_board_decimal_mbit_s']:.2f} | {low:.2f}-{high:.2f} | " +
                     (f"{receiver:.2f}" if receiver is not None else "Not qualified") + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    if args.verify_upstream:
        verify(args.directory)
    result = audit(args.directory)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(render_table(result) if args.markdown else json.dumps(result, indent=2))
