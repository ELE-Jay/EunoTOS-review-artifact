#!/usr/bin/env python3
"""Repeat original TCP programs on B1 with controlled CPU/peer/link settings."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil

from run_esp32_followup import Board, sha

SOURCES = {"FreeRTOS": ("/dev/shm/iotos-network-idf-v2", "idf", {
    "iperf.elf": "application.elf", "iperf.bin": "application.bin",
    "bootloader.bin": "bootloader.bin", "partition-table.bin": "partitions.bin"}),
    "Zephyr": ("/dev/shm/iotos-network-zephyr-v1", "zephyr", {
        "zephyr.elf": "application.elf", "zephyr.bin": "application.bin"}),
    "NuttX": ("/dev/shm/iotos-network-nuttx-v2", "nuttx", {
        "nuttx": "application.elf", "nuttx.bin": "application.bin",
        "bootloader-esp32.bin": "bootloader.bin", "partition-table-esp32.bin": "partitions.bin"})}
SCHEDULE = (("FreeRTOS", "Zephyr", "NuttX"), ("NuttX", "FreeRTOS", "Zephyr"), ("Zephyr", "NuttX", "FreeRTOS"))
RESUME_TASKS = [[2, "NuttX"], [2, "FreeRTOS"], [3, "NuttX"], [3, "FreeRTOS"]]
RETAINED = [[1, s] for s in SCHEDULE[0]] + [[2, "Zephyr"], [3, "Zephyr"]]


def configuration(system, folder):
    config = set((folder / "config").read_text().splitlines())
    expected = {"FreeRTOS": {"CONFIG_FREERTOS_UNICORE=y", "CONFIG_FREERTOS_HZ=100", "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240"},
        "Zephyr": {"CONFIG_SYS_CLOCK_TICKS_PER_SEC=100", "CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC=240000000"},
        "NuttX": {"CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_USEC_PER_TICK=10000", "CONFIG_RR_INTERVAL=0",
                  "CONFIG_DEBUG_CUSTOMOPT=y", 'CONFIG_DEBUG_OPTLEVEL="-O2"'}}[system]
    if not expected <= config or "CONFIG_SMP=y" in config or "13.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("Controlled CPU/core/tick/compiler settings differ: " + system)
    expected_buffers = {
        "FreeRTOS": {"CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=10", "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=32", "CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=32"},
        "Zephyr": {"CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM=10", "CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM=32", "CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM=32"},
        "NuttX": {"CONFIG_ESP32_WIFI_STATIC_RXBUF_NUM=10", "CONFIG_ESP32_WIFI_DYNAMIC_RXBUF_NUM=32", "CONFIG_ESP32_WIFI_DYNAMIC_TXBUF_NUM=32"}}[system]
    if not expected_buffers <= config:
        raise ValueError("Wi-Fi buffer allocation counts differ")


def collect(root, output, resume_parent=None, protocol="tcp"):
    import run_esp32_iperf_original as native
    import run_esp32_zperf_original as zperf
    os.environ["LC_ALL"] = "C"
    mac = "34:98:7a:a2:85:28"
    tasks = [(i, system) for i, order in enumerate(SCHEDULE, 1) for system in order]
    parent = None
    if protocol not in ("tcp", "udp") or protocol != "tcp" and resume_parent is not None:
        raise ValueError("Only the sealed TCP cohort can be resumed")
    cases = [protocol + "_tx", protocol + "_rx"]
    if resume_parent is not None:
        record = json.loads((resume_parent / "campaign.json").read_text())
        if resume_parent.name != "esp32-network-controlled-b1-v2" or record["status"] != "incomplete" or \
                not record["original_flash_restored"] or record["board_mac"] != mac or \
                record.get("error") != "Error: Timeout expired (35 seconds)\n":
            raise ValueError("Unexpected interrupted parent campaign")
        for name, digest in record["files"].items():
            if sha(resume_parent / name) != digest:
                raise ValueError("Parent evidence changed: " + name)
        tasks = RESUME_TASKS
        parent = {"directory": resume_parent.name, "campaign_sha256": sha(resume_parent / "campaign.json"),
            "retained_closed_os_rounds": RETAINED,
            "replaced_os_rounds": tasks,
            "reason": "round2 native TX peer final aggregates incomplete; NuttX round3 WPA timeout and missing post-verify; repeat affected complete OS-rounds, retain all attempts"}
    if shutil.disk_usage(root).free < 40 * 1024 ** 2:
        raise ValueError("Insufficient backup/evidence space")
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = native.run(["nmcli", "-t", "-f", "WIFI", "radio"])
        if initial["output"].strip() != "disabled":
            raise ValueError("Refusing to replace an enabled Wi-Fi session")
        connection = "iotosbench-controlled-b1"
        if connection in native.run(["nmcli", "-t", "-f", "NAME", "connection"])["output"].splitlines():
            raise ValueError("Controlled connection already exists")
        output.mkdir(parents=True, exist_ok=False)
        (output / "host-before.json").write_text(json.dumps({"radio": initial,
            "routes": native.run(["ip", "-j", "route"]),
            "addresses": native.run(["ip", "-j", "address"])}, indent=2) + "\n")
        for module in (native, zperf):
            module.CONNECTION, module.SSID, module.PASSWORD = connection, "IoTOSBench-B1", "benchmark-only-b1"
        for system, (name, _, images) in SOURCES.items():
            source = Path(name)
            configuration(system, source)
            folder = output / system
            (folder / "build").mkdir(parents=True)
            for name, saved in images.items():
                shutil.copyfile(source / name, folder / "build" / saved)
                if resume_parent is not None and sha(source / name) != sha(resume_parent / system / "build" / saved):
                    raise ValueError("Resume firmware differs from parent: " + system)
            for name in ("config", "compiler.txt", "compile_commands.json", "build.log", "image.sha256"):
                if (source / name).exists():
                    shutil.copyfile(source / name, folder / name)
        peer = root / "downloads/zperf-original-v3/iperf-host"
        shutil.copyfile(peer, output / "iperf-host")
        (output / "iperf-host").chmod(0o755)
        zperf.OUTPUT = output
        for p in (__file__, native.__file__, zperf.__file__):
            shutil.copyfile(p, output / Path(p).name)
        original_auto = native.run(["nmcli", "-g", "GENERAL.AUTOCONNECT", "device", "show", native.DEVICE])["output"].strip()
        actions = []
        report = {"status": "incomplete", "mode": "network-controlled" if protocol == "tcp" else "network-controlled-udp", "board_mac": mac,
            "started_utc": datetime.now(timezone.utc).isoformat(), "schedule": SCHEDULE,
            "original_flash_restored": False, "old_cohort_modified": False,
            "energy_measured": False, "ranking_eligible": False, "external_independent_replication": False,
            "protocol": {"cores": 1, "clock_mhz": 240, "tick_hz": 100, "seconds": 60,
                "peer": "retained original iPerf 2.0.5", "host": native.DEVICE, "channel": 1,
                "directions": cases, "radio_buffers_rx_static_dynamic_tx_dynamic": [10, 32, 32],
                "peer_bind_barrier": "pre-workload local protocol-specific bind readiness; TX also verifies the native server socket without a probe connection",
                "boundary": "original programs; FreeRTOS/NuttX TCP buffer 16384 B; original zperf uses 1024 B and explicit yield; do not silently combine"}}
        if protocol == "udp":
            report["protocol"].update(payload_bytes={"FreeRTOS": 1472, "NuttX": 1472, "Zephyr": 1024},
                boundary="original UDP programs; zperf has final handshake/loss/jitter, IDF/NuttX do not; NuttX TX is unpaced; no common loss or maximum-throughput ranking")
        if parent is not None:
            report.update(mode="network-controlled-resume", parent=parent, selected_os_rounds=tasks)
            report["protocol"]["resume"] = "sealed v2 parent plus four affected OS-rounds; fixed selection by failed endpoint/Flash evidence, never by throughput"
            report["protocol"]["connection_recovery"] = "explicit BSSID; at most two WPA activation attempts before workload, all retained"
            report["protocol"]["ap_discovery_barrier"] = "targeted SSID scans; exact B1 BSSID, channel1 and WPA2 required before activation; bounded 40-second discovery wait"
        board = Board(root, output, mac, native.SERIAL_PORT)
        try:
            board.backup()
            try:
                actions.append(native.run(["nmcli", "device", "set", native.DEVICE, "autoconnect", "no"], True))
                actions.append(native.run(["nmcli", "radio", "wifi", "on"], True))
                actions.append(native.run(["nmcli", "connection", "add", "type", "wifi", "ifname", native.DEVICE,
                    "con-name", connection, "ssid", native.SSID, "connection.autoconnect", "no",
                    "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", native.PASSWORD,
                    "802-11-wireless.powersave", "2", "802-11-wireless.band", "bg", "802-11-wireless.channel", "1",
                    "ipv4.method", "manual", "ipv4.addresses", "192.168.4.2/24", "ipv4.never-default", "yes", "ipv6.method", "ignore"], True))
                actions.append(native.run(["iw", "dev", native.DEVICE, "set", "power_save", "off"], True))
                for index, system in tasks:
                    folder = output / system / ("run%d" % index)
                    folder.mkdir()
                    pairs = board.flash(folder, output / system / "build")
                    for case in cases:
                        if system == "Zephyr":
                            zperf.trial(folder / case, case, 60, controlled_peer=True)
                        else:
                            native.trial(folder / case, case, 60, SOURCES[system][1], str(output / "iperf-host"),
                                         1472 if protocol == "udp" else 16384, controlled_peer=True)
                    board.verify(pairs, folder / "verify-after.log")
                    print("NETWORK", system, index, "both original " + protocol.upper() + " directions captured", flush=True)
                report["status"] = "collection_complete_audit_pending"
            finally:
                try:
                    actions.append(native.run(["nmcli", "connection", "delete", connection], True, False))
                    actions.append(native.run(["nmcli", "radio", "wifi", "off"], True, False))
                    actions.append(native.run(["nmcli", "device", "set", native.DEVICE, "autoconnect", "yes" if original_auto.startswith("yes") else "no"], True, False))
                    (output / "host-after.json").write_text(json.dumps({"radio": native.run(["nmcli", "-t", "-f", "WIFI", "radio"]),
                        "routes": native.run(["ip", "-j", "route"]),
                        "addresses": native.run(["ip", "-j", "address"])}, indent=2) + "\n")
                finally:
                    board.restore()
                    report["original_flash_restored"] = True
        except Exception as error:
            report["error"] = str(error)
            raise
        finally:
            (output / "network-actions.json").write_text(json.dumps(actions, indent=2) + "\n")
            report["completed_utc"] = datetime.now(timezone.utc).isoformat()
            report["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*")
                               if p.is_file() and p.name != "campaign.json"}
            (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-parent", type=Path)
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    args = parser.parse_args()
    collect(args.root, args.output, args.resume_parent, args.protocol)
