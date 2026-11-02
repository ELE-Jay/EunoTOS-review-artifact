#!/usr/bin/env python3
"""Audit the ESP32 Hartstone PH five-task baseline UART capture."""

import json
import math
import re
import sys
from pathlib import Path


EXPECTED = ((2, 2000, 20), (4, 1000, 40), (8, 500, 80),
            (40, 100, 400), (200, 20, 2000))
TASK = re.compile(
    r"HARTSTONE PH task=(\d+) hz=(\d+) workload_kwi=(\d+) met=(\d+) "
    r"missed=(\d+) skipped=(\d+) late_sum_ticks=(\d+) failures=(\d+) done=(\d+)$"
)
CAL = re.compile(r"HARTSTONE PH CAL status=PASS workload_kwi=10000 elapsed_us=(\d+) "
                 r"kwips=(\d+) clock_hz=240000000$")
TIMER = "HARTSTONE PH TIMER backend=NUTTX_RT_TIMER resolution_us=1 callback=TASK"


def audit(path, os_name="FreeRTOS", high_resolution=False):
    if os_name not in ("FreeRTOS", "Zephyr", "NuttX"):
        raise ValueError("unsupported OS")
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    lines = [row["line"] for row in rows]
    times = [row["elapsed_s"] for row in rows]
    if any(not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0
           for value in times) or any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("invalid or nonmonotonic UART capture time")
    if sum(line.startswith("rst:0x") for line in lines) != 1:
        raise ValueError("expected one ESP32 ROM reset")
    if sum(f"HARTSTONE PH boot target=ESP32 os={os_name}" in line
           for line in lines) != 1:
        raise ValueError(f"expected one {os_name} Hartstone boot")
    reset_at = next(index for index, line in enumerate(lines) if line.startswith("rst:0x"))
    if times[reset_at] > 2:
        raise ValueError("ROM reset was not captured at run start")
    if any(term in line for line in lines for term in
           ("ERROR", "Guru Meditation", "PANIC", "watchdog", "status=FAIL")):
        raise ValueError("UART contains error or panic")
    calibrations = [CAL.fullmatch(line) for line in lines if line.startswith("HARTSTONE PH CAL ")]
    if len(calibrations) != 1 or calibrations[0] is None:
        raise ValueError("calibration not proven exactly once")
    elapsed_us, speed = map(int, calibrations[0].groups())
    if elapsed_us <= 0 or speed != 10000 * 1000000 // elapsed_us:
        raise ValueError("calibration speed mismatch")
    if not any("tick_hz=1000 duration_s=10" in line and
               "source=SEI_DERIVED_C" in line and "task_count=5" in line
               for line in lines):
        raise ValueError("baseline configuration not proven")

    cal_at = next(index for index, line in enumerate(lines) if line.startswith("HARTSTONE PH CAL "))
    trial_at = [index for index, line in enumerate(lines) if line.startswith("HARTSTONE PH TRIAL ")]
    boot_at = next(index for index, line in enumerate(lines)
                   if f"HARTSTONE PH boot target=ESP32 os={os_name}" in line)
    if len(trial_at) != 1 or not reset_at < boot_at < cal_at < trial_at[0] or \
            f"raw_speed_kwips={speed} " not in lines[trial_at[0]] or \
            not 9.5 <= times[trial_at[0]] - times[cal_at] <= 12:
        raise ValueError("baseline calibration, trial order or duration mismatch")
    if high_resolution:
        if os_name != "NuttX" or lines.count(TIMER) != 1 or \
                not boot_at < lines.index(TIMER) < cal_at:
            raise ValueError("native microsecond timer configuration not proven")
        task_pattern = re.compile(TASK.pattern.replace("late_sum_ticks", "late_sum_us"))
    else:
        if any(line.startswith("HARTSTONE PH TIMER ") for line in lines):
            raise ValueError("high-resolution capture requires explicit timer audit")
        task_pattern = TASK
    tasks = [tuple(map(int, match.groups())) for line in lines
             if (match := task_pattern.fullmatch(line))]
    if len(tasks) != 5:
        raise ValueError(("expected five task records", tasks))
    for index, (task, expected) in enumerate(zip(tasks, EXPECTED), 1):
        task_id, hz, work, met, missed, skipped, late, failures, done = task
        if (task_id, hz, work, met) != (index, *expected) or any(
                (missed, skipped, late, failures)) or done != 1:
            raise ValueError(("invalid task", index, task))
    if sum("HARTSTONE PH status=PASS met=2540 missed=0 skipped=0 failures=0"
           in line for line in lines) != 1:
        raise ValueError("invalid final summary")
    return {"audit": "pass", "tasks": 5, "releases": 2540,
            "missed": 0, "skipped": 0, "failures": 0,
            "calibration_elapsed_us": elapsed_us, "raw_speed_kwips": speed,
            "sei_baseline_utilization_pct": 20000 * 100 / speed,
            "release_clock": "NUTTX_RT_TIMER_1US" if high_resolution else "KERNEL_TICK_1MS",
            "ranking_eligible": False}


if __name__ == "__main__":
    print(json.dumps(audit(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "FreeRTOS",
                           "--high-resolution" in sys.argv[3:]),
                     sort_keys=True))
