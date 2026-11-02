#!/usr/bin/env python3
"""Collect existing tests on an explicit replacement board; never rewrite old cohorts."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

CANDIDATES = [(kind, system, "riot-" + kind + "-" + system + "-" + version)
    for kind, system, version in (
        ("yield", "freertos", "v1"), ("yield", "zephyr", "v3"),
        ("yield", "nuttx", "v1"), ("yield", "alios", "v2"),
        ("flags", "freertos", "v1"), ("flags", "zephyr", "v1"),
        ("flags", "nuttx", "v1"), ("flags", "alios", "v1"),
        ("msg", "freertos", "v1"), ("msg", "zephyr", "v1"))]
RAMS = (("nuttx", "ram-hartstone-nuttx-v4/nuttx/ph4"),
        ("alios", "ram-hartstone-alios-v1/alios/ph4"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified(folder, build, mac, *, logs=("identity.log", "flash.log", "verify-before.log", "verify-after.log")):
    names = [(0x1000, "application.bin")] if not (build / "bootloader.bin").exists() else [
        (0x1000, "bootloader.bin"), (0x8000, "partitions.bin"), (0x10000, "application.bin")]
    for log in logs:
        text = (folder / log).read_text()
        if set(re.findall(r"^MAC: ([0-9a-f:]+)$", text, re.M)) != {mac} or \
                re.search(r"fatal error|digest mismatch|Traceback", text, re.I):
            raise ValueError("Flash/verification identity or status differs")
        if log.startswith("verify-"):
            matches = re.findall(r"^Verifying 0x[0-9a-f]+ \((\d+)\) bytes @ 0x([0-9a-f]+).*\n"
                                 r"-- verify OK \(digest matched\)$", text, re.M)
            expected = [(((build / name).stat().st_size + 3) & ~3, address) for address, name in names]
            if [(int(size), int(address, 16)) for size, address in matches] != expected:
                raise ValueError("Verified Flash segment coverage differs")


def check_uart_chronology(rows):
    if not rows:
        raise ValueError("empty UART chronology")
    times = [datetime.fromisoformat(row["utc"]).timestamp() for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if any(datetime.fromisoformat(row["utc"]).utcoffset() is None for row in rows) or \
            any(not math.isfinite(x) or x < 0 for x in elapsed) or \
            any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("original UART physical chronology differs")
    absolute = ("host_boot_id", "capture_started_monotonic_ns", "clock_read_before_ns", "clock_read_after_ns")
    if any(key in row for row in rows for key in absolute):
        if not all(all(key in row for key in absolute + ("clock_read_before_s", "clock_read_after_s")) for row in rows):
            raise ValueError("Absolute monotonic chronology incomplete")
        boot = rows[0]["host_boot_id"]
        start = rows[0]["capture_started_monotonic_ns"]
        if not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot) or type(start) is not int or start <= 0:
            raise ValueError("Invalid monotonic clock epoch")
        previous = start
        for row in rows:
            low, high = row["clock_read_before_ns"], row["clock_read_after_ns"]
            if row["host_boot_id"] != boot or row["capture_started_monotonic_ns"] != start or \
                    type(low) is not int or type(high) is not int or not previous <= low <= high or \
                    not abs(row["elapsed_s"] - (low - start) / 1e9) <= 1e-6 or \
                    not abs(row["clock_read_before_s"] - (low - start) / 1e9) <= 1e-6 or \
                    not abs(row["clock_read_after_s"] - (high - start) / 1e9) <= 1e-6:
                raise ValueError("Absolute monotonic chronology differs")
            previous = high
        return
    if any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("original UART physical chronology differs")
    brackets = ("clock_read_before_s", "clock_read_after_s")
    if any(key in row for row in rows for key in brackets):
        if not all(all(key in row for key in brackets) for row in rows):
            raise ValueError("UART clock read brackets incomplete")
        before, after = ([row[key] for row in rows] for key in brackets)
        if any(not math.isfinite(x) or x < 0 for x in before + after) or \
                any(not low <= value <= high for low, value, high in zip(before, elapsed, after)) or \
                any(a > b for a, b in zip(after, before[1:])) or \
                max(t - high for t, high in zip(times, after)) > min(t - low for t, low in zip(times, before)) + 0.1:
            raise ValueError("UART clock chronology lies outside measured read brackets")
    elif any(abs((time - times[0]) - (duration - elapsed[0])) > 0.1
             for time, duration in zip(times, elapsed)):
        raise ValueError("original UART physical chronology differs")


def monotonic_interval(rows):
    """Get a boot-scoped interval after read_raw_capture validates every row."""
    if "host_boot_id" not in rows[0]:
        return None
    return {"host_boot_id": rows[0]["host_boot_id"], "start_ns": rows[0]["clock_read_before_ns"],
            "end_ns": rows[-1]["clock_read_after_ns"]}


def read_raw_capture(directory, index, *, prefix="reset", allow_legacy=False):
    rows = [json.loads(line) for line in (directory / f"{prefix}{index}.jsonl").read_text().splitlines()]
    if allow_legacy and rows and not any("raw_bytes" in row or "raw_sha256" in row for row in rows):
        # Legacy network callers retain their own decoded-text checks; no byte proof is inferred.
        check_uart_chronology(rows)
        return rows
    raw, position = (directory / f"{prefix}{index}.raw").read_bytes(), 0
    for row in rows:
        if not {"raw_bytes", "raw_sha256"} <= row.keys():
            raise ValueError("original raw UART chunk metadata incomplete")
        chunk = raw[position:position + row["raw_bytes"]]
        if row["raw_bytes"] <= 0 or hashlib.sha256(chunk).hexdigest() != row["raw_sha256"] or \
                chunk.decode("utf-8", errors="replace").rstrip("\r\n") != row["line"]:
            raise ValueError("original raw UART chunk binding differs")
        position += row["raw_bytes"]
    if not rows or position != len(raw):
        raise ValueError("original UART byte coverage incomplete")
    check_uart_chronology(rows)
    return rows


class Board:
    def __init__(self, root, output, mac, port):
        self.root, self.output, self.mac, self.port = root, output, mac, port
        self.env = dict(os.environ, PYTHONPATH=str(root / "python-nuttx/lib/python3.8/site-packages")
                        + ":" + str(root / "esptool-4.8.1"))
        self.python = str(root / "idf-python-env/bin/python")
        self.transfer_baud = os.environ.get("ESP32_FLASH_BAUD", "460800")
        if self.transfer_baud not in ("115200", "230400", "460800"):
            raise ValueError("Unsupported Flash transfer baud")
        self.base = [self.python, "-m", "esptool", "--chip", "esp32", "--port", port, "--baud", self.transfer_baud]
        self.backup_chunk = int(os.environ.get("ESP32_BACKUP_CHUNK_BYTES", "0"))
        if self.backup_chunk not in (0, 262144):
            raise ValueError("Unsupported backup chunk size")
        self.restore_attempted = False

    def command(self, args, log, timeout=180):
        with log.open("x") as stream:
            result = subprocess.run(args, env=self.env, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Failed command; retained " + str(log))
        return log.read_text(errors="replace")

    def identify(self, log):
        value = self.command(self.base + ["read_mac"], log, 35)
        if set(re.findall(r"^MAC: ([0-9a-f:]+)$", value, re.M)) != {self.mac} or \
                "Chip is ESP32-D0WDQ6 (revision v1.1)" not in value:
            raise ValueError("Unexpected board identity; refusing write")

    def backup(self):
        self.identify(self.output / "identity-before.log")
        backup_root = Path(os.environ.get("ESP32_PRIVATE_BACKUP_ROOT", str(self.root / "private-backups")))
        backup_root.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(backup_root).free < 16 * 1024 ** 2:
            raise ValueError("Insufficient private full-Flash backup space")
        destination = backup_root / self.output.name
        destination.mkdir(parents=True, exist_ok=False)
        self.backup_path = destination / "original-flash.bin"
        reuse = os.environ.get("ESP32_VERIFIED_BACKUP")
        if reuse:
            source = Path(reuse).resolve()
            if not source.is_relative_to(backup_root.resolve()) or not source.is_file() or source.stat().st_size != 0x400000:
                raise ValueError("Reuse requires a complete private full-Flash backup")
            shutil.copyfile(source, self.backup_path)
            self.backup_sha = sha(self.backup_path)
            value = self.command(self.base + ["verify_flash", "0", str(self.backup_path)],
                                 self.output / "backup-verify.log")
            if set(re.findall(r"^MAC: ([0-9a-f:]+)$", value, re.M)) != {self.mac} or \
                    "Verifying 0x400000 (4194304) bytes @ 0x00000000" not in value or \
                    "verify OK (digest matched)" not in value:
                raise ValueError("Current board does not witness the reused full-Flash backup")
            (self.output / "backup.log").write_text(json.dumps({"mode": "verified-full-flash-reuse",
                "board_mac": self.mac, "bytes": 0x400000, "sha256": self.backup_sha,
                "source_private_campaign": source.parent.name, "verification": "backup-verify.log"}, indent=2) + "\n")
            return
        if self.backup_chunk:
            chunks = []
            for address in range(0, 0x400000, self.backup_chunk):
                for attempt in (1, 2):
                    part = destination / ("chunk-%06x-attempt%d.bin" % (address, attempt))
                    log = self.output / ("backup-%06x-attempt%d.log" % (address, attempt))
                    try:
                        text = self.command(self.base + ["read_flash", hex(address), hex(self.backup_chunk), str(part)], log, 90)
                        if set(re.findall(r"^MAC: ([0-9a-f:]+)$", text, re.M)) != {self.mac} or part.stat().st_size != self.backup_chunk:
                            raise ValueError("Wrong board or incomplete backup segment")
                    except RuntimeError:
                        if attempt == 2:
                            raise
                        self.base[-1] = self.transfer_baud = "115200"
                        continue
                    chunks.append({"address": address, "bytes": self.backup_chunk, "sha256": sha(part),
                                   "log": log.name, "private_file": part.name})
                    break
            with self.backup_path.open("xb") as output:
                for chunk in chunks:
                    with (destination / chunk["private_file"]).open("rb") as part:
                        shutil.copyfileobj(part, output)
            self.command(self.base + ["verify_flash", "0", str(self.backup_path)], self.output / "backup-verify.log")
            (self.output / "backup.log").write_text(json.dumps({"mode": "chunked-full-flash",
                "board_mac": self.mac, "bytes": 0x400000, "chunks": chunks, "sha256": sha(self.backup_path)}, indent=2) + "\n")
        else:
            self.command(self.base + ["read_flash", "0", "0x400000", str(self.backup_path)], self.output / "backup.log", 600)
        if self.backup_path.stat().st_size != 0x400000:
            raise ValueError("Incomplete private Flash backup")
        self.backup_sha = sha(self.backup_path)

    def restore(self):
        self.restore_attempted = True
        self.identify(self.output / "identity-restore.log")
        if sha(self.backup_path) != self.backup_sha:
            raise ValueError("Original backup changed")
        self.command(self.base + ["write_flash", "0", str(self.backup_path)], self.output / "restore.log")
        self.command(self.base + ["verify_flash", "0", str(self.backup_path)], self.output / "restore-verify.log")

    def flash(self, folder, build):
        self.identify(folder / "identity.log")
        names = [("0x1000", "application.bin")] if not (build / "bootloader.bin").exists() else [
            ("0x1000", "bootloader.bin"), ("0x8000", "partitions.bin"), ("0x10000", "application.bin")]
        pairs = [v for offset, name in names for v in (offset, str(build / name))]
        self.command(self.base + ["write_flash", "--flash_mode", "dio", "--flash_freq", "40m", "--flash_size", "4MB"] + pairs,
                     folder / "flash.log")
        self.verify(pairs, folder / "verify-before.log")
        return pairs

    def verify(self, pairs, log):
        self.command(self.base + ["verify_flash", "--flash_mode", "dio", "--flash_freq", "40m",
                                  "--flash_size", "4MB"] + pairs, log)

    def capture(self, folder, index, seconds, stop=None, send=None, capture_script=None, monotonic_clock=False):
        command = [self.python, str(capture_script or self.root / "capture_esp32_uart.py"), "--port", self.port,
            "--seconds", str(seconds), "--output", str(folder / ("reset%d.jsonl" % index)),
            "--raw-output", str(folder / ("reset%d.raw" % index))]
        if stop:
            command += ["--stop-on", stop]
        if send:
            command += ["--send-line", send, "--send-after", "2"]
        if monotonic_clock:
            command += ["--monotonic-chronology"]
        self.command(command, folder / ("capture%d.log" % index), seconds + 15)


def native_suite(board, output, proof_path, cases):
    proof = json.loads(proof_path.read_text())
    if proof["audit"] != "pass" or proof["built_os_case_cells"] != 14 or proof["new_measured_results"]:
        raise ValueError("Native suite requires the complete build-only qualification")
    shutil.copyfile(proof_path, output / "build-proof.json")
    origins = {"RIOT": Path("/dev/shm/iotos-riot-tm-gcc13-build-v1"),
               "AliOS-Rhino": Path("/dev/shm/iotos-rhino-gcc13-suite-build-v1")}
    for case in cases:
        for system, origin in origins.items():
            cell = next(r for r in proof["cells"] if r["os"] == system and r["case"] == case)
            folder = output / system / case
            build, captures = folder / "build", folder / "captures"
            build.mkdir(parents=True)
            captures.mkdir()
            for name, digest in cell["proof"]["images"].items():
                source = origin / case / name
                if sha(source) != digest:
                    raise ValueError("Native suite image differs from qualified build")
                shutil.copyfile(source, build / name)
            pairs = board.flash(captures, build)
            try:
                for index in (1, 2, 3):
                    board.capture(captures, index, 95)
                    result = subprocess.check_output([board.python,
                        str(board.root / "audit-workspace/tools/audit_esp32_tm_basic.py"),
                        str(captures / ("reset%d.jsonl" % index)), system, case], env=board.env)
                    (captures / ("result%d.json" % index)).write_bytes(result)
                    board.verify(pairs, captures / ("verify-run%d.log" % index))
                    print("NATIVE", system, case, index, "complete original reports captured", flush=True)
            finally:
                board.verify(pairs, captures / "verify-after.log")


def candidates(board, output, selected):
    for kind, system, source_name in CANDIDATES:
        if source_name not in selected:
            continue
        folder = output / source_name
        folder.mkdir()
        source = board.root / "downloads" / source_name
        module = importlib.import_module("audit_esp32_riot_" + kind + "_" + system)
        result = {"status": "failed", "original": source_name, "measured": False, "captures": []}
        try:
            proof = module.audit(source)
            build = folder / "build"
            shutil.copytree(source, build)
            (folder / "build-proof.json").write_text(json.dumps(proof, indent=2))
            captures = folder / "captures"
            captures.mkdir()
            shutil.copyfile(build / "application.elf", captures / "application.elf")
            pairs = board.flash(captures, build)
            for index in range(1, 4):
                board.capture(captures, index, 180 if system == "alios" else 30, "RIOT " + kind.upper() + " PORT END",
                              "riot_" + kind if system == "nuttx" else None)
                aligned = proof["machine_control"].get("aligned_peer_storage_bytes")
                args = (captures, index, aligned) if aligned is not None else (captures, index)
                result["captures"].append(module.capture(*args))
            board.verify(pairs, captures / "verify-after.log")
            result.update(status="pass", measured=True, board_mac=board.mac, energy_measured=False,
                          ranking_eligible=False, source_build=str(source_name))
        except Exception as error:
            result["error"] = str(error)
        (folder / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(result["status"], source_name, result.get("error", ""), flush=True)


def interrupts(board, output, prepared):
    data = json.loads((prepared / "build.json").read_text())
    if data["status"] != "build_pass_not_measured":
        raise ValueError("IRQ control build incomplete")
    shutil.copyfile(prepared / "build.json", output / "build.json")
    shutil.copyfile(prepared / "adapter.patch", output / "adapter.patch")
    cases = ("interrupt_processing", "interrupt_preemption_processing")
    from audit_esp32_tm_basic import audit
    from audit_esp32_tm_reboots import require_cpu2_interrupt
    schedule = [(case, variant, index) for case in cases for index in range(1, 4)
                for variant in (("legacy", "corrected") if index % 2 else ("corrected", "legacy"))]
    schedule += [(case, "replica", index) for case in cases for index in range(1, 4)]
    (output / "schedule.json").write_text(json.dumps(schedule, indent=2))
    for case, variant, index in schedule:
        item = next(r for r in data["builds"] if r["case"] == case and r["variant"] == variant)
        build = prepared / item["directory"]
        if any(sha(build / name) != digest for name, digest in item["images"].items()):
            raise ValueError("IRQ build changed after preparation")
        folder = output / variant / case / ("run%d" % index)
        folder.mkdir(parents=True)
        pairs = board.flash(folder, build)
        board.capture(folder, 1, 95)
        board.verify(pairs, folder / "verify-after.log")
        result = audit(folder / "reset1.jsonl", "AliOS-Rhino", case)
        rows = [json.loads(line) for line in (folder / "reset1.jsonl").read_text().splitlines()]
        require_cpu2_interrupt(rows)
        from audit_esp32_alios_tm import check_conditions
        check_conditions(rows)
        result.update(board_mac=board.mac, variant=variant, images=item["images"],
            ranking_eligible=False, external_replication=False, energy_measured=False)
        (folder / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print("CAPTURE", variant, case, index, result["original_window_totals"][0], flush=True)


def ram(board, output):
    from audit_esp32_hartstone_series import audit as series
    for system, source_name in RAMS:
        module = importlib.import_module("audit_esp32_hartstone_ram_" +
                                        ("nuttx_freelist" if system == "nuttx" else "alios"))
        source = board.root / "downloads" / source_name
        proof = module.audit(source) if system == "nuttx" else module.build(source)
        if system == "alios":
            proof["machine_control"] = module.machine(source)
        folder = output / system
        folder.mkdir()
        build, captures = folder / "build", folder / "captures"
        shutil.copytree(source, build)
        captures.mkdir()
        shutil.copyfile(build / "application.elf", captures / "application.elf")
        (folder / "build-proof.json").write_text(json.dumps(proof, indent=2))
        pairs = board.flash(captures, build)
        for index in (1, 2, 3):
            board.capture(captures, index, 1800, "BENCH_RAM lifecycle complete",
                          "hartstone" if system == "nuttx" else None)
            result = series(captures / ("reset%d.jsonl" % index),
                            "NuttX" if system == "nuttx" else "AliOS-Rhino", 4, high_resolution=True)
            (captures / ("series%d.json" % index)).write_text(json.dumps(result, indent=2))
            print("RAM", system, index, result["completion"], result["first_loss_step"], flush=True)
        board.verify(pairs, captures / "verify-after.log")


if __name__ == "__main__":
    import fcntl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("candidates", "interrupts", "ram", "native-suite"))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--port", default="/dev/ttyUSB0")
    parser.add_argument("--only", nargs="+", choices=[n for _, _, n in CANDIDATES])
    parser.add_argument("--cases", nargs="+", choices=("basic_processing", "cooperative_scheduling",
        "preemptive_scheduling", "synchronization_processing", "memory_allocation",
        "interrupt_processing", "interrupt_preemption_processing"),
        default=["interrupt_processing", "interrupt_preemption_processing"])
    args = parser.parse_args()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", args.mac):
        parser.error("explicit canonical board MAC required")
    if args.mode in ("interrupts", "native-suite") and args.prepared is None:
        parser.error("selected mode requires --prepared")
    root, output = args.root.resolve(), args.output.resolve()
    device = subprocess.check_output(["udevadm", "info", "-q", "property", "-n", args.port]).decode()
    if any(s not in device.splitlines() for s in ("ID_VENDOR_ID=1a86", "ID_MODEL_ID=7523", "ID_USB_DRIVER=ch341")) or \
            "ID_TYPE=audio" in device or "ID_MODEL=USB_MIDI" in device:
        raise ValueError("Device is not the usable retained USB bridge")
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        (output / "device.log").write_text(device)
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(root / "capture_esp32_uart.py", output / "capture_esp32_uart.py")
        board = Board(root, output, args.mac, args.port)
        report = {"status": "incomplete", "board_mac": args.mac, "mode": args.mode,
            "started_utc": datetime.now(timezone.utc).isoformat(), "original_flash_restored": False,
            "old_cohort_modified": False, "energy_measured": False, "external_independent_replication": False}
        report["requested_candidates"] = args.only or [n for _, _, n in CANDIDATES]
        if args.mode == "native-suite":
            report.update(requested_candidates=[], requested_cases=args.cases)
        try:
            board.backup()
            try:
                if args.mode == "candidates":
                    candidates(board, output, report["requested_candidates"])
                elif args.mode == "interrupts":
                    interrupts(board, output, args.prepared)
                elif args.mode == "native-suite":
                    native_suite(board, output, args.prepared, args.cases)
                else:
                    ram(board, output)
                report["status"] = "collection_complete_audit_pending"
            finally:
                board.restore()
                report["original_flash_restored"] = True
        except Exception as error:
            report["error"] = str(error)
            raise
        finally:
            report["completed_utc"] = datetime.now(timezone.utc).isoformat()
            report["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*")
                               if p.is_file() and p.name != "campaign.json"}
            (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")
