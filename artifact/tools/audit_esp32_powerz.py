#!/usr/bin/env python3
"""Replay POWER-Z packets, audit timing, and gate branch-energy integration."""

import argparse
import csv
import json
import math
import re
import statistics
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host.energy import integrate_series, measurement_sha256
from capture_esp32_powerz import decode_packet
from audit_esp32_tm_basic import CASES, audit as audit_tm
from audit_esp32_tm_reboots import require_self_check

SUPPORTED_OSES = ("FreeRTOS", "Zephyr", "NuttX", "RIOT", "AliOS-Rhino")


def audit_installed_power_image(directory, os, case, image_source=None):
    from audit_esp32_resources import EVIDENCE, audit_cell, primary_directory
    from audit_esp32_report import audit_flash
    if os in ("RIOT", "AliOS-Rhino"):
        cohort = "riot-native-gcc12-v3" if os == "RIOT" else "alios-native-gcc5-v3"
        source = EVIDENCE / cohort / case
    elif os == "NuttX" and case == "message_processing":
        source = EVIDENCE / "nuttx-message-resource-v2"
    else:
        source = primary_directory(os, case)
    if image_source is not None:
        source = Path(image_source)
    image = audit_cell(source, os, case)
    installed = directory.parent
    if (installed / "image.sha256").read_bytes() != (source / "image.sha256").read_bytes():
        raise ValueError("power installation does not bind the current original-test image")
    audit_flash(installed, "flash.log", len(image["segments"]))
    log = (installed / "flash.log").read_text()
    written = [(int(size), int(offset, 16)) for size, offset in
               re.findall(r"Wrote (\d+) bytes .*? at (0x[0-9a-f]+)", log)]
    expected = [(segment["bytes"], int(segment["offset"], 16)) for segment in image["segments"]]
    if sorted(written) != sorted(expected):
        raise ValueError("power installation differs from archived image sizes/offsets")
    return {"elf_sha256": image["elf_sha256"], "segments": image["segments"],
            "source_evidence": image["evidence"],
            "flash_log_sha256": measurement_sha256(installed / "flash.log")}


def audit_supply_record(directory, metadata, record_path):
    """Check capture-bound operator evidence; this cannot inspect wiring remotely."""
    record_path = Path(record_path)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if type(record.get("version")) is not int or record["version"] not in (1, 2) or \
            record.get("meter_usb_id") != "5fc9:0063" or \
            metadata.get("usb_id") != record["meter_usb_id"] or \
            record.get("board_mac") != "84:1f:e8:8f:55:dc":
        raise ValueError("supply record does not identify the measured board/meter")
    for field in ("sole_board_supply_through_meter", "wiring_unchanged_during_capture"):
        if record.get(field) is not True:
            raise ValueError(f"whole-board supply verification missing: {field}")
    allowed_paths = ("isolated", "through_same_meter")
    if record["version"] == 2:
        allowed_paths += ("operator_confirmed_no_unmetered_supply",)
    if record.get("data_usb_vbus_path") not in allowed_paths:
        raise ValueError("data USB VBUS must be isolated or pass through the same meter")
    if type(record.get("polarity")) is not int or record["polarity"] not in (-1, 1) or \
            not isinstance(record.get("operator_confirmation"), str) or \
            not record["operator_confirmation"].strip():
        raise ValueError("supply record lacks explicit operator direction/path confirmation")
    verified = datetime.fromisoformat(record["verified_utc"])
    started = datetime.fromisoformat(metadata["started_utc"])
    if verified.utcoffset() is None or started.utcoffset() is None or verified > started:
        raise ValueError("wiring must be verified before this fresh capture")
    for name in ("metadata.json", "power.csv", "meter.jsonl", "uart.jsonl"):
        if record.get("capture_sha256", {}).get(name) != measurement_sha256(directory / name):
            raise ValueError("supply record is not bound to these exact raw capture files")
    if record["version"] == 2:
        if record.get("evidence_type") != "operator_text_confirmation" or \
                record.get("confirmation_source") != "direct_user_message" or \
                record.get("wiring_continuity_basis") != "confirmed_setup_no_change_reported_during_capture":
            raise ValueError("text evidence must identify a direct operator reply and its continuity basis")
        if not isinstance(record.get("operator_confirmation_context"), str) or \
                not record["operator_confirmation_context"].strip():
            raise ValueError("text confirmation lacks the supply-path question it answers")
        if "wiring_photo" in record or "wiring_photo_sha256" in record:
            raise ValueError("text-only operator evidence must not claim a wiring photograph")
        name = record.get("operator_setup_file")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise ValueError("text confirmation requires its original local setup statement")
        source = (record_path.parent / name).resolve()
        if source.parent != record_path.parent.resolve() or not source.is_file() or \
                measurement_sha256(source) != record.get("operator_setup_sha256"):
            raise ValueError("operator setup statement is missing or changed")
        setup = json.loads(source.read_text(encoding="utf-8"))
        fields = ("version", "meter_usb_id", "board_mac", "polarity", "sole_board_supply_through_meter",
                  "data_usb_vbus_path", "wiring_unchanged_during_capture", "operator_confirmation", "verified_utc",
                  "evidence_type", "confirmation_source", "operator_confirmation_context", "wiring_continuity_basis")
        if any(record.get(field) != setup.get(field) for field in fields):
            raise ValueError("capture supply record differs from the original operator statement")
        return record
    name = record.get("wiring_photo")
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("supply record requires a local wiring photo filename")
    photo = (record_path.parent / name).resolve()
    if photo.parent != record_path.parent.resolve() or not photo.is_file() or \
            measurement_sha256(photo) != record.get("wiring_photo_sha256"):
        raise ValueError("wiring photo is missing or differs from the supplied evidence")
    return record


def audit(directory, polarity=None, boundary_note=None, tm_os=None, tm_case=None,
          whole_board_evidence=None, assumed_polarity=None, assumption_note=None, image_source=None):
    directory = Path(directory)
    metadata = json.loads((directory / "metadata.json").read_text())
    packets = [json.loads(line) for line in (directory / "meter.jsonl").read_text().splitlines()]
    with (directory / "power.csv").open(newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["timestamp_s", "voltage_v", "current_a"]:
            raise ValueError("unexpected POWER-Z CSV schema")
        samples = [tuple(float(row[field]) for field in reader.fieldnames) for row in reader]
    if metadata["status"] != "complete" or not 2 <= len(samples) == len(packets) == metadata["sample_count"]:
        raise ValueError("incomplete capture or mismatched sample counts")
    for index, ((timestamp, voltage, current), packet) in enumerate(zip(samples, packets)):
        before, after = packet["query_start_s"], packet["query_end_s"]
        if not all(math.isfinite(v) for v in (timestamp, voltage, current, before, after)):
            raise ValueError("non-finite sensor/timing record")
        if not 0 <= before <= after <= metadata["duration_actual_s"] or after - before > 0.05:
            raise ValueError("USB query timing outside capture or over 50 ms")
        if abs(timestamp - (before + after) / 2) > 1e-8 or timestamp != packet["elapsed_s"]:
            raise ValueError("CSV timestamp not associated with raw packet")
        if (voltage, current) != decode_packet(bytes.fromhex(packet["packet_hex"])):
            raise ValueError("CSV voltage/current differs from original USB packet")
        if index and (timestamp <= samples[index - 1][0] or before < packets[index - 1]["query_end_s"]):
            raise ValueError("unordered or overlapping samples")
    gaps = [right[0] - left[0] for left, right in zip(samples, samples[1:])]
    if max(gaps) > 0.5:
        raise ValueError("power trace has a sample gap over 500 ms")
    result = {
        "audit": "pass", "sample_count": len(samples),
        "observed_samples_per_s": (len(samples) - 1) / (samples[-1][0] - samples[0][0]),
        "max_sample_gap_s": max(gaps),
        "max_query_span_s": max(p["query_end_s"] - p["query_start_s"] for p in packets),
        "voltage_v": {"min": min(s[1] for s in samples), "max": max(s[1] for s in samples)},
        "signed_current_a": {"min": min(s[2] for s in samples),
                             "mean": statistics.mean(s[2] for s in samples),
                             "max": max(s[2] for s in samples)},
        "negative_current_samples": sum(s[2] < 0 for s in samples),
        "measurement_boundary": metadata["measurement_boundary"],
        "timestamp_semantics": metadata["timestamp_semantics"],
        "calibration": metadata["calibration"],
        "sha256": {name: measurement_sha256(directory / name)
                   for name in ("metadata.json", "power.csv", "meter.jsonl", "uart.jsonl")},
        "ranking_eligible": False, "whole_board_eligible": False,
        "energy_status": "not_computed_unverified_direction_and_boundary",
    }
    if (assumed_polarity is None) != (assumption_note is None):
        raise ValueError("assumed direction requires both polarity and an assumption note")
    if assumed_polarity is not None:
        if (type(assumed_polarity) is not int or assumed_polarity not in (-1, 1) or
                not isinstance(assumption_note, str) or not assumption_note.strip() or
                polarity is not None or boundary_note is not None or whole_board_evidence is not None):
            raise ValueError("assumed polarity cannot qualify or override verified whole-board evidence")
        polarity = assumed_polarity
        boundary_note = assumption_note
    if whole_board_evidence is not None:
        if polarity is not None or boundary_note is not None or tm_os is None or tm_case is None:
            raise ValueError("whole-board evidence requires a matched workload, not branch overrides")
        supply = audit_supply_record(directory, metadata, whole_board_evidence)
        polarity = supply["polarity"]
        boundary_note = supply["operator_confirmation"]
    if polarity is not None:
        if polarity not in (-1, 1) or not boundary_note or not boundary_note.strip():
            raise ValueError("integration requires explicit polarity and a verified supply-path note")
        powers = [(t, v * i * polarity) for t, v, i in samples]
        if any(p < 0 for _, p in powers):
            raise ValueError("current changes sign; do not clamp or silently take absolute values")
        result.update(energy_status="branch_trace_integrated_not_ranked", polarity=polarity,
                      verified_boundary_note=boundary_note,
                      whole_trace=integrate_series(powers, max_gap_s=0.5))
        if assumed_polarity is not None:
            del result["verified_boundary_note"]
            result.update(energy_status="assumed_direction_branch_integrated_not_ranked",
                          direction_status="assumed, not physically verified",
                          assumption_note=assumption_note)
    if (tm_os is None) != (tm_case is None):
        raise ValueError("matched workload requires both OS and original case")
    if tm_os is not None:
        if tm_os not in SUPPORTED_OSES or tm_case not in CASES:
            raise ValueError("unknown original Thread-Metric workload")
        witness = audit_tm(directory / "uart.jsonl", tm_os, tm_case)
        rows = [json.loads(line) for line in (directory / "uart.jsonl").read_text().splitlines()]
        if tm_case == "synchronization_processing":
            require_self_check(rows, "semaphore")
        if sum(row["line"].startswith("rst:0x") for row in rows) != 1:
            raise ValueError("matched power capture lacks one independent board reset")
        report_times = [row["elapsed_s"] for row in rows
                        if row["line"].startswith("**** Thread-Metric")]
        windows = []
        for start, end in zip(report_times, report_times[1:]):
            if start < samples[0][0] or end > samples[-1][0]:
                raise ValueError("meter trace does not cover original report interval")
            window = {"start_s": start, "end_s": end, "duration_s": end - start}
            if polarity is not None:
                window.update(integrate_series(powers, max_gap_s=0.5, start_s=start, end_s=end))
            windows.append(window)
        result.update(original_workload=witness, steady_report_intervals=windows,
                      phase_definition="original 30->60 and 60->90 report intervals, including reporting overhead",
                      timing_limit="host UART receipt and USB query midpoint; device conversion delay not calibrated",
                      whole_board_eligible=False)
    if whole_board_evidence is not None:
        if len(windows) != 2:
            raise ValueError("whole-board result requires both original steady report intervals")
        result.update(energy_status="whole_board_observation_operator_verified",
                      whole_board_eligible=True,
                      supply_evidence_sha256=measurement_sha256(Path(whole_board_evidence)),
                      supply_evidence_type=("operator_text_confirmation" if supply["version"] == 2
                                            else "operator_confirmation_with_photo"),
                      wiring_photo_sha256=supply.get("wiring_photo_sha256"),
                      operator_setup_sha256=supply.get("operator_setup_sha256"),
                      installed_image=audit_installed_power_image(directory, tm_os, tm_case, image_source),
                      measurement_boundary="entire development-board supply input, operator verified",
                      acceptance_scope="operator-confirmed physical path and original-workload phases; no independent electrical isolation test; instrument calibration remains as recorded; no cross-OS rank")
    return result


def audit_sync_suite(directory, assumed_polarity=None, assumption_note=None, require_whole_board=False):
    """Replay all profiles with either assumed direction or per-reset supply proof."""
    if type(require_whole_board) is not bool:
        raise ValueError("whole-board suite selection must be boolean")
    if require_whole_board:
        if assumed_polarity is not None or assumption_note is not None:
            raise ValueError("whole-board suite cannot override operator evidence with assumptions")
    elif (type(assumed_polarity) is not int or assumed_polarity not in (-1, 1) or
          not isinstance(assumption_note, str) or not assumption_note.strip()):
        raise ValueError("sync suite requires an explicit fixed direction assumption")
    capture_source = Path(directory) / "capture_esp32_powerz.py"
    if capture_source.read_bytes() != (Path(__file__).parent / "capture_esp32_powerz.py").read_bytes():
        raise ValueError("unreviewed power acquisition source")
    profiles = []
    previous_end = None
    for os, folder in zip(SUPPORTED_OSES, ("freertos", "zephyr", "nuttx", "riot", "alios")):
        runs = []
        source = Path(directory) / folder
        installed = audit_installed_power_image(source / "reset1", os, "synchronization_processing")
        for index in (1, 2, 3):
            capture = source / f"reset{index}"
            supply_record = capture / "supply-evidence.json" if require_whole_board else None
            if supply_record is not None and not supply_record.is_file():
                raise ValueError(f"missing capture-specific whole-board supply record: {supply_record}")
            result = audit(capture, tm_os=os, tm_case="synchronization_processing",
                           assumed_polarity=assumed_polarity, assumption_note=assumption_note,
                           whole_board_evidence=supply_record)
            if result.get("supply_evidence_type") == "operator_text_confirmation":
                setup = Path(directory) / "operator-setup.json"
                if not setup.is_file() or measurement_sha256(setup) != result["operator_setup_sha256"]:
                    raise ValueError("capture operator statement differs from the cohort's original confirmation")
            metadata = json.loads((capture / "metadata.json").read_text())
            if metadata.get("usb_id") != "5fc9:0063" or metadata.get("port") != "/dev/ttyUSB0":
                raise ValueError("power capture identifies a different meter or board UART")
            start = datetime.fromisoformat(metadata["started_utc"])
            if start.utcoffset() is None or previous_end is not None and start <= previous_end:
                raise ValueError("power captures overlap or lack timezone-aware start times")
            previous_end = start + timedelta(seconds=metadata["duration_actual_s"])
            rows = [json.loads(line) for line in (capture / "uart.jsonl").read_text().splitlines()]
            resets = [row for row in rows if row["line"].startswith("rst:0x")]
            if resets[0]["elapsed_s"] > 2 or not 25 < result["original_workload"]["host_window_seconds"][0] < 40:
                raise ValueError("expected an early independent reset and the original first report")
            if os in ("RIOT", "AliOS-Rhino"):
                timer = "timer=tickless" if os == "RIOT" else "tick_hz=100"
                marker = f"Thread-Metric conditions cpu_hz=240000000 cores=1 {timer} scheduler=priority-fifo"
                if sum(row["line"] == marker for row in rows) != 1:
                    raise ValueError("power workload lacks its native runtime-condition witness")
            windows = result["steady_report_intervals"]
            if len(windows) != 2 or any(not 29.5 < window["duration_s"] < 30.5 for window in windows):
                raise ValueError("power capture lacks both original steady report intervals")
            energy = sum(window["energy_j"] for window in windows)
            duration = sum(window["duration_s"] for window in windows)
            result.update(reset=index, started_utc=metadata["started_utc"],
                          steady_average_power_w=energy / duration,
                          steady_energy_j=energy, steady_duration_s=duration)
            runs.append(result)
        powers = [run["steady_average_power_w"] for run in runs]
        profiles.append({"os": os, "independent_resets": 3, "installed_image": installed,
                         "steady_average_power_w_median": statistics.median(powers),
                         "steady_average_power_w_min": min(powers),
                         "steady_average_power_w_max": max(powers),
                         "interval_energy_j_medians": [statistics.median(
                             run["steady_report_intervals"][index]["energy_j"] for run in runs)
                             for index in (0, 1)], "runs": runs})
    return {"audit": "pass", "case": "synchronization_processing",
            "os_profiles": len(profiles), "independent_resets": 15, "profiles": profiles,
            "raw_sample_count": sum(run["sample_count"] for profile in profiles for run in profile["runs"]),
            "acquisition_source_sha256": measurement_sha256(capture_source),
            "assumed_polarity": assumed_polarity, "assumption_note": assumption_note,
            "started_utc": profiles[0]["runs"][0]["started_utc"],
            "completed_utc": previous_end.isoformat(),
            "direction_status": ("capture-specific operator verified, raw signed packets preserved"
                                 if require_whole_board else "assumed fixed polarity, raw signed packets preserved"),
            "measurement_boundary": ("entire development-board supply input, operator verified"
                                     if require_whole_board else "meter branch; sole whole-board supply path unverified"),
            "whole_board_eligible": all(run["whole_board_eligible"]
                                        for profile in profiles for run in profile["runs"]),
            "ranking_eligible": False,
            "phase_definition": "original 30->60 and 60->90 report intervals, including reporting overhead",
            "timing_limit": "approximately 10 host queries/s; no interrupt transient or sleep-power claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--polarity", type=int, choices=(-1, 1))
    parser.add_argument("--boundary-note")
    parser.add_argument("--assumed-polarity", type=int, choices=(-1, 1),
                        help="Integrate a fixed direction assumption without whole-board eligibility")
    parser.add_argument("--assumption-note")
    parser.add_argument("--tm-os", choices=SUPPORTED_OSES)
    parser.add_argument("--tm-case", choices=CASES)
    parser.add_argument("--whole-board-evidence", type=Path,
                        help="Capture-bound operator supply-path/direction record with hashed wiring photo")
    parser.add_argument("--sync-suite", action="store_true", help="Audit all five native sync profiles, three resets each")
    parser.add_argument("--require-whole-board-evidence", action="store_true",
                        help="With --sync-suite, require supply-evidence.json and its hashed wiring photo in every reset")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.sync_suite:
        if any(value is not None for value in (args.polarity, args.boundary_note,
                                              args.tm_os, args.tm_case, args.whole_board_evidence)):
            parser.error("--sync-suite does not accept single-capture boundary/workload overrides")
        if args.require_whole_board_evidence:
            if args.assumed_polarity is not None or args.assumption_note is not None:
                parser.error("whole-board suite requires per-reset operator evidence, not direction assumptions")
        elif args.assumed_polarity is None or not args.assumption_note:
            parser.error("--sync-suite requires direction assumptions or --require-whole-board-evidence")
        result = audit_sync_suite(args.directory, args.assumed_polarity, args.assumption_note,
                                  require_whole_board=args.require_whole_board_evidence)
    else:
        if args.require_whole_board_evidence:
            parser.error("--require-whole-board-evidence requires --sync-suite")
        result = audit(args.directory, args.polarity, args.boundary_note,
                       args.tm_os, args.tm_case, args.whole_board_evidence,
                       args.assumed_polarity, args.assumption_note)
    content = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(content)
    else:
        print(content, end="")


if __name__ == "__main__":
    main()
