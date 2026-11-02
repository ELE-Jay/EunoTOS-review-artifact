#!/usr/bin/env python3
"""Audit ESP32 Hartstone PH series UART against the published PH step rules."""

import argparse
import json
import math
import re
from pathlib import Path

from hartstone_ph_protocol import audit as audit_protocol, baseline_tasks, trial_tasks


CAL = re.compile(r"HARTSTONE PH CAL status=PASS workload_kwi=10000 elapsed_us=(\d+) kwips=(\d+) clock_hz=240000000$")
TRIAL = re.compile(r"HARTSTONE PH TRIAL source=SEI_DERIVED_C clock_hz=240000000 tick_hz=(\d+) duration_s=10 raw_speed_kwips=(\d+) experiment=([1-4]) step=(\d+) task_count=(\d+)$")
TASK = re.compile(r"HARTSTONE PH task=(\d+) (hz|hz_tenths)=(\d+) workload_kwi=(\d+) met=(\d+) missed=(\d+) skipped=(\d+) late_sum_(ticks|us)=(\d+) failures=(\d+) done=(\d+)$")
STATUS = re.compile(r"HARTSTONE PH status=(PASS|FAIL) met=(\d+) missed=(\d+) skipped=(\d+)$")
END = re.compile(r"HARTSTONE PH SERIES status=FIRST_LOSS step=(\d+) raw_speed_kwips=(\d+)$")
MAX = re.compile(r"HARTSTONE PH SERIES status=MAX_STEPS_NO_LOSS step=(\d+)$")
BASELINE = [{"hz": hz, "kilo_whets": work} for hz, work in
            ((2, 2000), (4, 1000), (8, 500), (40, 100), (200, 20))]
NATIVE_TIMERS = {
    "FreeRTOS": ("ESP_TIMER", "TASK", 1000),
    "Zephyr": ("ZEPHYR_TICKLESS", "KERNEL", 100000),
    "NuttX": ("NUTTX_RT_TIMER", "TASK", 1000),
    "RIOT": ("RIOT_ZTIMER64", "KERNEL", 0),
    "AliOS-Rhino": ("ALIOS_ESP_TIMER", "TASK", 100),
}


def audit(path, os_name="FreeRTOS", experiment=2, allow_incomplete=False,
          high_resolution=False):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [row["elapsed_s"] for row in rows]
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0
           for value in times) or any(
        later < earlier for earlier, later in zip(times, times[1:])
    ):
        raise ValueError("invalid or nonmonotonic UART capture time")
    if sum(line.startswith("rst:0x") for line in lines) != 1:
        raise ValueError("expected exactly one ROM reset")
    boot = f"HARTSTONE PH SERIES boot target=ESP32 os={os_name} experiment={experiment}"
    if lines.count(boot) != 1:
        raise ValueError("expected exactly one matching OS boot")
    if any(term in line for line in lines for term in
           ("Guru Meditation", "PANIC", "ERROR", "watchdog", "status=FAIL",
            "Exception", "reboot!", "ASSERT", "FATAL", "abort")):
        raise ValueError("error or failed status in UART")
    calibrations = [CAL.fullmatch(line) for line in lines if line.startswith("HARTSTONE PH CAL ")]
    if len(calibrations) != 1 or calibrations[0] is None:
        raise ValueError("invalid calibration")
    reset_at = next(i for i, line in enumerate(lines) if line.startswith("rst:0x"))
    if times[reset_at] > 2:
        raise ValueError("ESP32 ROM reset was not captured at run start")
    boot_at = lines.index(boot)
    cal_at = next(i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH CAL "))
    trial_at = [i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH TRIAL ")]
    end_at = [i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH SERIES status=")]
    if not trial_at or len(end_at) > 1 or (not end_at and not allow_incomplete) or not (
        reset_at < boot_at < cal_at < trial_at[0]
    ) or (end_at and trial_at[-1] >= end_at[0]):
        raise ValueError("invalid Hartstone boot, trial, or terminal order")
    timer_at = [i for i, line in enumerate(lines) if line.startswith("HARTSTONE PH TIMER ")]
    if high_resolution:
        backend, callback, expected_tick_hz = NATIVE_TIMERS[os_name]
        marker = f"HARTSTONE PH TIMER backend={backend} quantum_us=10 callback={callback}"
        if len(timer_at) != 1 or lines[timer_at[0]] != marker or not (
            boot_at < timer_at[0] < cal_at
        ):
            raise ValueError("invalid high-resolution timer identity or order")
    elif timer_at:
        raise ValueError("native-us capture requires explicit high-resolution audit")
    if any(not 9.0 <= times[b] - times[a] <= 12.0 for a, b in zip(trial_at, trial_at[1:])):
        raise ValueError("Hartstone trials did not advance in 10-second intervals")
    elapsed_us, speed = map(int, calibrations[0].groups())
    if elapsed_us <= 0 or speed != 10000 * 1000000 // elapsed_us:
        raise ValueError("calibration speed mismatch")
    trials = []
    tick_hz = None
    timing_limited_steps = []
    sub_two_tick_steps = []
    index = 0
    while index < len(lines):
        header = TRIAL.fullmatch(lines[index])
        if header is None:
            index += 1
            continue
        trial_tick_hz, raw_speed, exp, step, count = map(int, header.groups())
        tickless_riot = os_name == "RIOT" and high_resolution and trial_tick_hz == 0
        if (trial_tick_hz <= 0 and not tickless_riot) or (tick_hz is not None and trial_tick_hz != tick_hz):
            raise ValueError("invalid or changing tick frequency")
        tick_hz = trial_tick_hz
        if high_resolution and tick_hz != expected_tick_hz:
            raise ValueError("native timer kernel tick configuration mismatch")
        if raw_speed != speed or exp != experiment or step != len(trials):
            raise ValueError("trial header mismatch or noncontiguous step")
        if count != 5 + (step if experiment == 4 else 0):
            raise ValueError("wrong task count")
        tasks = []
        for task_id in range(1, count + 1):
            index += 1
            if index >= len(lines) or (match := TASK.fullmatch(lines[index])) is None:
                raise ValueError("missing or malformed task")
            (actual_id, units, frequency, work, met, missed, skipped,
             late_units, late, failures, done) = match.groups()
            actual_id, frequency, work, met, missed, skipped, late, failures, done = map(
                int, (actual_id, frequency, work, met, missed, skipped, late, failures, done))
            if actual_id != task_id or units != ("hz_tenths" if experiment == 2 else "hz"):
                raise ValueError("task identity or frequency units mismatch")
            if late_units != ("us" if high_resolution else "ticks"):
                raise ValueError("lateness units do not match timer profile")
            if high_resolution and (late % 10 or late < missed * 10):
                raise ValueError("lateness was not quantized to 10 microseconds")
            if failures or done != 1 or (missed == 0 and late != 0) or (missed and late < missed):
                raise ValueError("workload, completion, or lateness mismatch")
            tasks.append({"frequency": frequency, "work": work, "met": met,
                          "missed": missed, "skipped": skipped, "late": late})
        index += 1
        if index >= len(lines) or (summary := STATUS.fullmatch(lines[index])) is None:
            raise ValueError("missing trial summary")
        state, met, missed, skipped = summary.groups()
        totals = tuple(sum(task[key] for task in tasks) for key in ("met", "missed", "skipped"))
        if state != "PASS" or totals != tuple(map(int, (met, missed, skipped))):
            raise ValueError("trial summary mismatch")
        expected_tasks = trial_tasks(baseline_tasks(BASELINE), experiment, step)
        release_clock_hz = 100000 if high_resolution else tick_hz
        if any(hz > release_clock_hz for hz, _ in expected_tasks):
            timing_limited_steps.append(step)
        if any(hz * 2 > release_clock_hz for hz, _ in expected_tasks):
            sub_two_tick_steps.append(step)
        for task, (hz, work) in zip(tasks, expected_tasks):
            expected_frequency = int(hz * (10 if experiment == 2 else 1))
            if task["frequency"] != expected_frequency or task["work"] != work:
                raise ValueError("PH frequency or workload differs from protocol")
            if sum(task[key] for key in ("met", "missed", "skipped")) != hz * 10:
                raise ValueError("release count differs from protocol")
        trials.append({"step": step, "tasks": [
            {"met": task["met"], "missed": task["missed"], "skipped": task["skipped"],
             "average_late_ms": (task["late"] / task["missed"] *
                                 (0.001 if high_resolution else 1000 / tick_hz))
                                if task["missed"] else 0}
            for task in tasks]})
        index += 1
    ends = [line for line in lines if line.startswith("HARTSTONE PH SERIES status=")]
    if len(ends) > 1 or (not ends and not allow_incomplete) or not trials:
        raise ValueError("missing or duplicated terminal marker")
    first_loss = END.fullmatch(ends[0]) if ends else None
    max_steps = MAX.fullmatch(ends[0]) if ends else None
    if ends and first_loss is None and max_steps is None:
        raise ValueError("unrecognized terminal marker")
    end_step = int((first_loss or max_steps).group(1)) if ends else len(trials) - 1
    if end_step != len(trials) - 1 or (first_loss and int(first_loss.group(2)) != speed):
        raise ValueError("terminal step or calibration mismatch")
    result = audit_protocol({"baseline": BASELINE, "experiment": experiment,
                             "raw_speed_kwips": speed, "duration_s": 10, "trials": trials})
    if first_loss and (result["status"] != "FIRST_LOSS_REACHED" or
                       result["first_loss"]["step"] != end_step):
        raise ValueError("terminal marker is not the first loss")
    if max_steps and result["status"] != "INCOMPLETE":
        raise ValueError("max-step marker contradicts observed loss")
    if max_steps and experiment == 3 and 20000 + end_step * 254 <= speed:
        raise ValueError("PH3 max step did not exceed calibrated raw speed")
    if not ends and result["status"] != "INCOMPLETE":
        raise ValueError("unterminated first-loss capture")
    baseline_utilization = result["baseline"]["requested_utilization_pct"]
    step_size = result["trials"][1]["step_size_pct"] if len(trials) > 1 else None
    return {"audit": "pass", "os": os_name, "experiment": experiment,
            "raw_speed_kwips": speed, "trials": len(trials),
            "best_step": result["best"]["step"] if result["best"] else None,
            "first_loss_step": end_step if first_loss else None,
            "completion": result["status"], "tick_hz": tick_hz,
            "timer_profile": "native-us" if high_resolution else "kernel-tick",
            "release_quantum_us": 10 if high_resolution else 1000000 / tick_hz,
            "bounded_capture": not ends,
            "timing_limited_steps": timing_limited_steps,
            "sub_two_tick_steps": sub_two_tick_steps,
            "sei_baseline_utilization_pct": baseline_utilization,
            "sei_baseline_in_guided_range": 10 <= baseline_utilization <= 30,
            "sei_step_size_pct": step_size,
            "ranking_eligible": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--os", default="FreeRTOS")
    parser.add_argument("--experiment", type=int, default=2)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--high-resolution", action="store_true")
    parser.add_argument("--require-first-loss", action="store_true")
    args = parser.parse_args()
    result = audit(args.capture, args.os, args.experiment,
                   args.allow_incomplete, args.high_resolution)
    if args.require_first_loss and result["completion"] != "FIRST_LOSS_REACHED":
        raise ValueError("complete threshold capture did not reach the first loss")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
