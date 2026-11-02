#!/usr/bin/env python3
"""Audit native UDP build/boot admission without treating it as network performance."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex

from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from verify_esp32_riot_udp_sources import urls
from prepare_esp32_riot_network_dependencies import prepare


def audit(directory, dependencies):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    prepare(dependencies, offline=True)
    if json.loads((directory / "dependency-provenance.json").read_text()) != json.loads((dependencies / "provenance.json").read_text()):
        raise ValueError("native RF/TLSF provenance differs")
    originals = urls()
    proof = json.loads((directory / "official-source.json").read_text())
    if {row["path"] for row in proof} != set(originals) or len(proof) != len(originals) or any(
            row["url"] != originals[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("original workload/peer/AP source binding differs")
    config = (directory / "config.h").read_text().splitlines()
    for setting in ("#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240 1", "#define CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE 1",
                    "#define MODULE_ESP_WIFI_AP 1", "#define MODULE_GNRC_SOCK_UDP 1", "#define MODULE_BENCHMARK_UDP 1",
                    '#define WIFI_SSID "ESP32-bench-55dc"', '#define WIFI_PASS "benchmark-only-55dc"'):
        if setting not in config:
            raise ValueError(("native profile differs", setting))
    if "12.2.0" not in (directory / "compiler.txt").read_text() or not (directory / "host-source/bin/benchmark_server").is_file():
        raise ValueError("native compiler/peer absent")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc " in line and " -c " in line]
    for name in ("examples/benchmark_udp/main.c", "sys/test_utils/benchmark_udp/benchmark_udp.c", "cpu/esp_common/esp-wifi/esp_wifi_netdev.c"):
        compiled = [command for command in commands if any(value.endswith("/" + name) for value in command)]
        if len(compiled) != 1 or "-Os" not in compiled[0]:
            raise ValueError(("native original compile witness differs", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("installed native board/image binding differs")
    rows = [json.loads(line) for line in (directory / "boot-probe.jsonl").read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            sum("rst:0x" in line for line in lines) != 1 or lines.count("Single core mode") != 1 or \
            lines.count("main(): This is RIOT! (Version: 2024.10-devel)") != 1 or \
            lines.count("RIOT UDP stress-test application") != 1 or \
            any(re.search(r"panic|Guru Meditation|ASSERT|Exception", line) for line in lines) or \
            not any(re.fullmatch(r"Iface\s+8\s+HWaddr: 84:1F:E8:8F:55:DD\s+Channel: 0\s+Link: up\s*", line) for line in lines):
        raise ValueError("native boot/interface admission failed")
    return {"audit": "pass", "scope": "build/installed-image/boot/interface admission only", "source_files": len(proof),
            "cores": 1, "configured_clock_mhz": 240, "interface_id": 8,
            "ipv6_address_observed": any("inet6 addr:" in line for line in lines),
            "network_performance_measured": False, "ranking_eligible": False,
            "image_sha256": digest(directory / "application.bin"),
            "remaining": ["native IPv6 address setup and real peer connection", "original UDP traffic and independent reset repeats",
                          "paired raw/packet records and original byte/counter/recursive-RTT arithmetic audit"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("dependencies", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.dependencies), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    print(result, end="")
