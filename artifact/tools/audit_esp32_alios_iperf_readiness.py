#!/usr/bin/env python3
"""Audit installed AliOS original iPerf startup/CLI admission, never a traffic score."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shlex

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest
from verify_esp32_alios_iperf_sources import urls, REVISION


def audit(directory):
    check_manifest(directory, "image.sha256")
    check_manifest(directory, "capture.sha256")
    originals = urls()
    proof = json.loads((directory / "official-source.json").read_text())
    if len(proof) != len(originals) or {row["path"] for row in proof} != set(originals) or any(
            row["url"] != originals[row["path"]] or row["sha256"] != digest(directory / row["path"]) for row in proof):
        raise ValueError("original workload/network/CLI source binding differs")
    config = (directory / "config").read_text().splitlines()
    for setting in ('AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="native_iperf"', "AOS_COMP_CLI=y",
                    "IPERF_ENABLED=y", "OSAL_RHINO=y"):
        if setting not in config:
            raise ValueError(("native configuration differs", setting))
    if "5.2.0" not in (directory / "compiler.txt").read_text() or \
            "#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ 240" not in (directory / "sdkconfig.h").read_text() or \
            not re.search(r"#define RHINO_CONFIG_CPU_NUM\s+1\b", (directory / "k_config.h").read_text()) or \
            not re.search(r"#define RHINO_CONFIG_TICKS_PER_SECOND\s+100\b", (directory / "k_config.h").read_text()):
        raise ValueError("native compiler/core/clock/tick profile differs")
    expected_header = '#ifndef ALIOS_NATIVE_IPERF_LWIPOPTS_H\n#define ALIOS_NATIVE_IPERF_LWIPOPTS_H\n\n#include "../../../../board/esp32bench/lwipopts.h"\n\n/* Enable only the original iPerf report switch; retain every native stack setting. */\n#undef IPERF_DEBUG\n#define IPERF_DEBUG LWIP_DBG_ON\n\n#endif\n'
    if (directory / "include/lwipopts.h").read_text() != expected_header:
        raise ValueError("native report switch modifies other stack configuration")
    stack_header = directory / "include/lwip/apps/iperf_task.h"
    stack_bytes = 1536
    measurement_clock = "native aos_now_ms"
    if stack_header.exists():
        expected_stack = '#ifndef ALIOS_NATIVE_IPERF_TASK_CONFIGURATION_H\n#define ALIOS_NATIVE_IPERF_TASK_CONFIGURATION_H\n\n#include "../../../../../../network/lwip/include/lwip/apps/iperf_task.h"\n\n/* Original 1536-byte stack overflows on this ESP32 network/report path. */\n#undef IPERF_STACKSIZE\n#define IPERF_STACKSIZE 6144\n\n#endif\n'
        expected_hardware = expected_stack.replace('iperf_task.h"\n', 'iperf_task.h"\n#include "aos/kernel.h"\n#include "esp_timer.h"\n').replace('\n#endif\n', '\n/* Native tick time drifts under Wi-Fi load; use an independent hardware clock. */\nstatic inline long long native_iperf_hardware_now_ms(void)\n{\n    return esp_timer_get_time() / 1000;\n}\n#define aos_now_ms native_iperf_hardware_now_ms\n\n#endif\n')
        if stack_header.read_text() not in (expected_stack, expected_hardware):
            raise ValueError("native workload stack wrapper modifies other settings")
        stack_bytes = 6144
        if stack_header.read_text() == expected_hardware:
            measurement_clock = "esp_timer_get_time / 1000, corrected hardware-reference adapter"
            preprocess = json.loads((directory / "measurement-preprocess.json").read_text())
            if len(preprocess) != 2 or "--wrap=aos_task_new_ext" not in (directory / "link.opts").read_text() or \
                    "setvbuf(stdout, NULL, _IONBF, 0);" not in (directory / "native_iperf.c").read_text():
                raise ValueError("hardware clock/unbuffered entry adapter witness missing")
            for row, name in zip(preprocess, ("iperf_task", "iperf_cli")):
                output = directory / (name + "-preprocessed.c")
                compiled = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                            if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line and
                            "network/lwip/apps/iperf/" + name + ".c" in shlex.split(line)]
                if row["output_sha256"] != digest(output) or compiled != [row["original_compile"]]:
                    raise ValueError("actual native measurement preprocessor binding differs")
                text = output.read_text()
                if (name == "iperf_task" and "uint64_t now = native_iperf_hardware_now_ms();" not in text) or \
                        (name == "iperf_cli" and "g_iperf_param, 6144, 6" not in text):
                    raise ValueError("actual native clock/stack expansion differs")
    dependency_count = 0
    dependencies = directory / "network-dependencies.json"
    if dependencies.exists():
        linked = {part[2:] if part.startswith("./") else part for part in shlex.split((directory / "link.opts").read_text())
                  if part.startswith(("./platform/mcu/esp32/lib/", "platform/mcu/esp32/lib/")) and part.endswith(".a")}
        provenance = json.loads(dependencies.read_text())
        files = provenance["files"]
        if provenance["revision"] != REVISION or provenance["link_opts_sha256"] != digest(directory / "link.opts") or \
                len(files) != len(linked) or {row["path"] for row in files} != {"native-dependencies/" + path for path in linked}:
            raise ValueError("fixed native archive coverage/link binding differs")
        for row in files:
            path = row["path"].removeprefix("native-dependencies/")
            if row["url"] != f"https://raw.githubusercontent.com/alibaba/AliOS-Things/{REVISION}/{path}" or \
                    row["sha256"] != digest(directory / row["path"]):
                raise ValueError("fixed native archive identity differs")
        dependency_count = len(files)
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                if line.startswith("xtensa-esp32-elf-gcc ") and " -c " in line]
    for name in ("network/lwip/apps/iperf/iperf_task.c", "network/lwip/apps/iperf/iperf_cli.c", "kernel/cli/cli.c",
                 "platform/mcu/esp32/hal/wifi_port.c", "app/example/native_iperf/native_iperf.c"):
        compiled = [command for command in commands if name in command]
        if len(compiled) != 1 or "-Os" not in compiled[0] or "-DOSAL_RHINO" not in compiled[0] or \
                "-Iapp/example/native_iperf/include" not in compiled[0] or \
                (name.endswith("wifi_port.c") and "-DENABLE_WIFI" not in compiled[0]):
            raise ValueError(("native original compile witness differs", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = {symbol.name: symbol for symbol in elf.get_section_by_name(".symtab").iter_symbols()}
        for name in ("iperf_command", "iperf_udp_run_server", "iperf_udp_run_client", "iperf_tcp_run_server", "iperf_tcp_run_client"):
            if name not in symbols or symbols[name]["st_shndx"] == "SHN_UNDEF" or not symbols[name]["st_size"]:
                raise ValueError("original test executable not linked")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("installed image/board binding differs")
    rows = [json.loads(line) for line in (directory / "boot-probe.jsonl").read_text().splitlines()]
    lines = [ANSI.sub("", row["line"]) for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    if not rows or any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            sum("rst:0x1 (POWERON_RESET)" in line for line in lines) != 1 or \
            sum("Welcome to AliOS Things" in line for line in lines) != 1 or \
            lines.count("Native AliOS lwIP iPerf ready: AP 192.168.4.1 channel 1") != 1 or \
            not any("mode : softAP (84:1f:e8:8f:55:dd)" in line for line in lines) or \
            "iperf -h" not in lines or not any("Usage: iperf [-s|-c] [options]" in line for line in lines) or \
            any(re.search(r"panic|Guru Meditation|ASSERT|Exception|ESP_ERROR_CHECK failed", line) for line in lines):
        raise ValueError("native boot/AP/original CLI admission failed")
    return {"audit": "pass", "scope": "build/installed-image/boot/native iPerf CLI admission only", "source_files": len(proof),
            "cores": 1, "configured_clock_mhz": 240, "tick_hz": 100, "native_cli_observed": True,
            "native_ap_address_observed": "192.168.4.1", "peer_connectivity_measured": False,
            "iperf_stack_bytes": stack_bytes,
            "measurement_clock": measurement_clock,
            "unmodified_native_measurement_clock": measurement_clock == "native aos_now_ms",
            "verified_native_link_archive_inputs": dependency_count,
            "network_performance_measured": False, "ranking_eligible": False,
            "image_sha256": digest(directory / "application.bin"),
            "remaining": ["real peer/RF condition witness", "original four-direction traffic and independent resets",
                          "paired raw/packet records, native counter/rate/time arithmetic", "selected-network report"] +
                         ([] if dependency_count else ["RF library provenance"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    print(result, end="")
