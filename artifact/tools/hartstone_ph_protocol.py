#!/usr/bin/env python3
"""Generate and audit the four PH experiments from the SEI Hartstone guide.

This is a host-side protocol checker, not the original Ada benchmark or its
Small_Whetstone workload. It never labels a capture as measured by itself.
"""

import argparse
import json
from fractions import Fraction
from pathlib import Path


def number(value):
    result = Fraction(str(value))
    if result <= 0:
        raise ValueError("frequency, speed and duration must be positive")
    return result


def nonnegative_number(value):
    result = Fraction(str(value))
    if result < 0:
        raise ValueError("average lateness must not be negative")
    return result


def baseline_tasks(rows):
    if len(rows) != 5:
        raise ValueError("PH baseline requires five tasks")
    if any(type(row.get("kilo_whets")) is not int for row in rows):
        raise ValueError("workloads must be integer Kilo-Whets")
    tasks = [(number(row["hz"]), row["kilo_whets"]) for row in rows]
    if any(work < 1 for _, work in tasks):
        raise ValueError("workloads must be positive integer Kilo-Whets")
    for previous, current in zip(tasks, tasks[1:]):
        ratio = current[0] / previous[0]
        if ratio <= 1 or ratio.denominator != 1:
            raise ValueError("baseline frequencies must be increasing and harmonic")
    if len({hz * work for hz, work in tasks}) != 1:
        raise ValueError("baseline tasks must have equal workload rates")
    return tasks


def trial_tasks(baseline, experiment, step):
    if type(experiment) is not int or experiment not in (1, 2, 3, 4) or type(step) is not int or step < 0:
        raise ValueError("invalid PH experiment or step")
    tasks = list(baseline)
    if experiment == 1:
        hz, work = tasks[4]
        tasks[4] = (hz + step * tasks[3][0], work)
    elif experiment == 2:
        tasks = [(hz * (Fraction(10 + step, 10)), work) for hz, work in tasks]
    elif experiment == 3:
        tasks = [(hz, work + step) for hz, work in tasks]
    else:
        tasks.extend([tasks[2]] * step)
    return tasks


def audit(run):
    baseline = baseline_tasks(run["baseline"])
    experiment = run["experiment"]
    if type(experiment) is not int or experiment not in (1, 2, 3, 4):
        raise ValueError("invalid PH experiment")
    speed = number(run["raw_speed_kwips"])
    duration = number(run.get("duration_s", 10))
    observations = run["trials"]
    if not observations or type(observations[0]["step"]) is not int or observations[0]["step"] != 0:
        raise ValueError("the first trial must be baseline step 0")
    result = []
    for step, observation in enumerate(observations):
        if type(observation["step"]) is not int or observation["step"] != step:
            raise ValueError("PH steps must be contiguous")
        tasks = trial_tasks(baseline, experiment, step)
        counts = observation["tasks"]
        if len(counts) != len(tasks):
            raise ValueError("task count does not match the PH experiment")
        if result and not result[-1]["all_deadlines_met"]:
            raise ValueError("first-loss completion criterion exceeded")
        totals = {key: 0 for key in ("met", "missed", "skipped")}
        per_task = []
        for (hz, work), counter in zip(tasks, counts):
            if any(type(counter.get(key)) is not int or counter[key] < 0 for key in totals):
                raise ValueError("invalid deadline counters")
            lateness = nonnegative_number(counter["average_late_ms"])
            if (counter["missed"] == 0 and lateness != 0) or (counter["missed"] > 0 and lateness == 0):
                raise ValueError("average lateness disagrees with missed deadlines")
            activations = sum(counter[key] for key in totals)
            expected = hz * duration
            if activations < expected.numerator // expected.denominator:
                raise ValueError("task activation count below scheduled releases")
            for key in totals:
                totals[key] += counter[key]
            per_task.append({"hz": float(hz), "kilo_whets": work,
                             "expected_activations": float(expected),
                             "observed_activations": activations,
                             "average_late_ms": float(lateness),
                             **{key: counter[key] for key in totals}})
        if any(sum(item[key] for key in totals) == 0 for item in per_task):
            raise ValueError("every task must record at least one activation")
        requested_kwips = sum(hz * work for hz, work in tasks)
        previous_kwips = sum(hz * work for hz, work in
                             trial_tasks(baseline, experiment, step - 1)) if step else None
        result.append({"step": step, "requested_kwips": float(requested_kwips),
                       "requested_utilization_pct": float(100 * requested_kwips / speed),
                       "step_size_pct": float(100 * (requested_kwips - previous_kwips) / speed)
                       if previous_kwips is not None else None,
                       "tasks": per_task, "totals": totals,
                       "total_activations": sum(totals.values()),
                       "all_deadlines_met": totals["missed"] == totals["skipped"] == 0})
    best = next((row for row in reversed(result) if row["all_deadlines_met"]), None)
    first_loss = next((row for row in result if not row["all_deadlines_met"]), None)
    return {"protocol": "Hartstone PH (SEI CMU/SEI-90-UG-001)",
            "status": "FIRST_LOSS_REACHED" if first_loss else "INCOMPLETE",
            "experiment": experiment, "raw_speed_kwips": float(speed),
            "duration_s": float(duration), "baseline": result[0],
            "best": best, "first_loss": first_loss, "final_test": result[-1],
            "trials": result,
            "physical_measurement_verified": False,
            "cross_os_ranking_eligible": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(json.loads(args.capture.read_text())), indent=2))


if __name__ == "__main__":
    main()
