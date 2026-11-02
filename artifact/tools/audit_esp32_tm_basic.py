#!/usr/bin/env python3
"""Check raw ESP32 Thread-Metric windows without scoring or ranking."""

import json
import math
import re
import sys
from pathlib import Path


CASES = {
    "basic_processing": "Basic Single Thread Processing",
    "cooperative_scheduling": "Cooperative Scheduling",
    "preemptive_scheduling": "Preemptive Scheduling",
    "message_processing": "Message Processing",
    "synchronization_processing": "Synchronization Processing",
    "memory_allocation": "Memory Allocation",
    "interrupt_processing": "Interrupt Processing",
    "interrupt_preemption_processing": "Interrupt Preemption Processing",
}


def cooperative_balanced(values):
    # Match the original uint32 total and floor-average +/- 1 predicate.
    average = (sum(values) & 0xffffffff) // 5
    lower, upper = (average - 1) & 0xffffffff, (average + 1) & 0xffffffff
    return len(values) == 5 and all(lower <= value <= upper for value in values)


def audit(path, os_name, case="basic_processing"):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    marker = f"Thread-Metric {os_name} ESP32 boot"
    lines = [row["line"] for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if any(not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0
           for t in elapsed) or any(right < left for left, right in zip(elapsed, elapsed[1:])):
        raise ValueError("UART capture timestamps are invalid or out of order")
    if sum(marker in line for line in lines) != 1:
        raise ValueError(f"expected exactly one {marker!r}")
    bad = ("ERROR:", "panic", "abort", "task_wdt", "Guru Meditation",
           "Exception", "reboot!", "ASSERT", "FATAL")
    if any(any(token.lower() in line.lower() for token in bad) for line in lines):
        raise ValueError("UART contains error, panic, abort, or watchdog output")
    heading = re.compile(r"Thread-Metric " + re.escape(CASES[case]) +
                         r" Test .* Relative Time: (\d+)$")
    any_heading = re.compile(r"Thread-Metric .* Test .* Relative Time: \d+$")
    total = re.compile(r"Time Period Total:\s*(\d+)$")
    headings = [(index, int(match.group(1)), row["elapsed_s"])
                for index, row in enumerate(rows)
                if (match := heading.search(row["line"]))]
    if sum(bool(any_heading.search(line)) for line in lines) != len(headings):
        raise ValueError("UART contains a heading from another test case")
    windows = [(period, t) for _, period, t in headings]
    total_rows = [(index, int(match.group(1)))
                  for index, row in enumerate(rows)
                  if (match := total.search(row["line"]))]
    totals = [value for _, value in total_rows]
    if [period for period, _ in windows] != [30, 60, 90]:
        raise ValueError(("wrong windows", windows))
    if len(totals) != 3 or not all(value > 0 for value in totals):
        raise ValueError(("invalid totals", totals))
    if any(not (headings[index][0] < total_rows[index][0] <
                (headings[index + 1][0] if index < 2 else len(rows)))
           for index in range(3)):
        raise ValueError("Time Period Total is not paired with its test heading")
    if not all(29.5 < right[1] - left[1] < 30.5
               for left, right in zip(windows, windows[1:])):
        raise ValueError(("host intervals", windows))
    if case == "cooperative_scheduling":
        worker = re.compile(r"tm_cooperative_thread_([0-4])_counter:\s*(\d+)$")
        counters = [(index, int(match.group(1)), int(match.group(2)))
                    for index, row in enumerate(rows) if (match := worker.search(row["line"]))]
        if len(counters) != 15:
            raise ValueError(("missing cooperative worker counters", counters))
        previous = 0
        for heading_row, total_row in zip(headings, total_rows):
            group = [(thread, value) for index, thread, value in counters
                     if heading_row[0] < index < total_row[0]]
            values = [value for _, value in group]
            if [thread for thread, _ in group] != list(range(5)) or not cooperative_balanced(values):
                raise ValueError(("unbalanced cooperative workers", group))
            current = sum(values) & 0xffffffff
            if ((current - previous) & 0xffffffff) != total_row[1]:
                raise ValueError(("cooperative worker/period total mismatch", group, total_row[1]))
            previous = current
    return {"audit": "pass", "os": os_name, "case": case,
            "original_window_totals": totals,
            "host_window_seconds": [round(t, 3) for _, t in windows]}


if __name__ == "__main__":
    case_name = sys.argv[3] if len(sys.argv) > 3 else "basic_processing"
    print(json.dumps(audit(sys.argv[1], sys.argv[2], case_name), sort_keys=True))
