#!/usr/bin/env python3
"""Replay NuttX original iPerf boot admission; this does not create a benchmark score."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from audit_esp32_report import audit_flash
from audit_esp32_iperf_original import ANSI


def original_urls():
    originals = {"source/" + name: "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/netutils/iperf/" + name
                 for name in ("Kconfig", "Make.defs", "Makefile", "README.md", "iperf.c", "iperf.h", "iperf_main.c")}
    originals.update({"native-source/" + name: "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/" + name
                      for name in ("arch/xtensa/src/esp32/Make.defs", "arch/xtensa/src/esp32/esp32_wifi_adapter.c",
                                   "arch/xtensa/src/esp32/esp32_wlan.c",
                                   "boards/xtensa/esp32/esp32-devkitc/configs/softap/defconfig")})
    originals.update({"netinit-source/" + name: "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/netutils/netinit/" + name
                      for name in ("Kconfig", "Make.defs", "Makefile", "netinit.c")})
    return originals


def audit(directory):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "probe.sha256")
    originals = original_urls()
    proof = json.loads((directory / "official-source.json").read_text())
    if len(proof) != len(originals) or {row["path"] for row in proof} != set(originals) or any(
            row["url"] != originals[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("original native application/network/board source identity differs")
    config = (directory / "config").read_text().splitlines()
    for setting in ("CONFIG_ARCH_CHIP_ESP32WROOM32=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240",
                    "CONFIG_USEC_PER_TICK=10000", "CONFIG_ESP32_WIFI_SOFTAP=y", "CONFIG_NETUTILS_IPERF=y",
                    "CONFIG_NETINIT_WAPI_STAMODE=3", 'CONFIG_NETINIT_WAPI_SSID="ESP32-bench-55dc"',
                    'CONFIG_NETINIT_WAPI_PASSPHRASE="benchmark-only-55dc"', "CONFIG_NETINIT_IPADDR=0xc0a80401"):
        if setting not in config:
            raise ValueError(("native profile mismatch", setting))
    if "CONFIG_SMP=y" in config or "13.2.0" not in (directory / "compiler.txt").read_text():
        raise ValueError("unexpected core/compiler profile")
    audit_elf_image(directory / "nuttx", directory / "nuttx.bin")
    audit_flash(directory, "flash.log", 3)
    written = [(int(size), int(address, 16)) for size, address in re.findall(
        r"Wrote (\d+) bytes .* at (0x\w+)", (directory / "flash.log").read_text())]
    if written != [((directory / name).stat().st_size, address) for name, address in
                   (("bootloader-esp32.bin", 0x1000), ("partition-table-esp32.bin", 0x8000), ("nuttx.bin", 0x10000))]:
        raise ValueError("native installed segment length/address differs")
    rows = [json.loads(line) for line in (directory / "boot-probe.jsonl").read_text().splitlines()]
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if any(time.utcoffset() is None for time in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(b["elapsed_s"] < a["elapsed_s"] for a, b in zip(rows, rows[1:])) or \
            lines.count("NuttShell (NSH)") != 1 or lines.count("ifconfig") != 1 or \
            "wlan0\tLink encap:Ethernet HWaddr 84:1f:e8:8f:55:dd at UP mtu 1500" not in lines or \
            "inet addr:192.168.4.1 DRaddr:0.0.0.0 Mask:255.255.255.0" not in lines or \
            re.search(r"PANIC|ASSERTION|Guru Meditation|Brownout|Exception", "\n".join(lines)):
        raise ValueError("native boot/interface admission failed")
    if '#define CONFIG_VERSION_STRING "0.0.0"' not in (directory / "version-header.h").read_text():
        raise ValueError("snapshot automatic version metadata changed")
    return {"audit": "pass", "scope": "original NuttX iPerf build/Flash/boot/interface admission only",
            "source_release": "nuttx-12.2.1", "original_verified_files": len(proof),
            "snapshot_generated_version_string": "0.0.0", "image_sha256": digest(directory / "nuttx.bin"),
            "configured_clock_mhz": 240, "cores": 1, "tick_hz": 100,
            "throughput_measured": False, "ranking_eligible": False,
            "remaining": ["native command/connectivity gate and four-direction independently reset throughput captures",
                          "native RF dependency provenance and full original result replay",
                          "source-release version stamping before the performance cohort"],
            "udp_boundary": "original native sender has no -b/-l options, timestamps or FIN; no full-session loss/jitter score"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
