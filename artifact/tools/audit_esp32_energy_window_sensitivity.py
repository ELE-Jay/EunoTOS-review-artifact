#!/usr/bin/env python3
"""Replay existing traces with one observed sample-gap boundary perturbation."""
import argparse
import csv
import json
import math
from pathlib import Path
from statistics import median

from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
CASES = ("message_processing", "preemptive_scheduling", "synchronization_processing",
         "interrupt_processing", "interrupt_preemption_processing")


def perturb(powers, start, end):
    from replay_esp32_b1_energy import interval_energy

    gap = max(b[0]-a[0] for a,b in zip(powers, powers[1:]) if a[0] <= end and b[0] >= start)
    nominal = interval_energy(powers, start, end)
    shifted = [interval_energy(powers, start+d, end+d) for d in (-gap, gap)]
    separate = [interval_energy(powers, start+a, end+b) for a in (-gap, gap) for b in (-gap, gap)]
    return {"sample_gap_s":gap, "nominal_energy_j":nominal,
        "translated_window_max_relative_change":max(abs(e/nominal-1) for e in shifted),
        "independent_endpoint_max_relative_change":max(abs(e/nominal-1) for e in separate)}


def sample_gaps(capture, windows):
    metadata = json.loads((capture / "metadata.json").read_text())
    with (capture / "power.csv").open(newline="") as stream:
        times = [float(row["timestamp_s"]) for row in csv.DictReader(stream)]
    if metadata.get("status") != "complete" or metadata.get("interval_requested_s") != 0.1 or \
            len(times) != metadata.get("sample_count") or len(times) < 2 or \
            any(not math.isfinite(t) or t < 0 for t in times) or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError("Incomplete or inconsistent host sampling metadata/timestamps")
    if not windows or any(not all(math.isfinite(w[k]) for k in ("start_s", "end_s")) or
            not times[0] <= w["start_s"] < w["end_s"] <= times[-1] for w in windows) or \
            any(a["end_s"] > b["start_s"] for a, b in zip(windows, windows[1:])):
        raise ValueError("Paired integration windows are unordered or outside the trace")
    gaps = [b-a for a, b in zip(times, times[1:]) if any(
        a <= w["end_s"] and b >= w["start_s"] for w in windows)]
    return len(times), gaps


def cadence_audit():
    from audit_esp32_b1_controlled_energy import audit as controlled
    from audit_esp32_b1_native_energy import audit as native

    rows, all_gaps = [], []
    for is_native in (False, True):
        for case in CASES:
            name = "esp32-native-"+case+"-energy-b1-v1" if is_native else "esp32-"+(
                "message" if case == "message_processing" else case)+"-energy-b1-v1"
            folder = ROOT / "artifacts/reports" / name
            result = (native if is_native else controlled)(folder)
            for cell in result["cells"]:
                for index, run in enumerate(cell["runs"], 1):
                    capture = folder / cell["os"] / ("run%d" % index) / "capture"
                    samples, gaps = sample_gaps(capture, run["paired"]["paired_intervals"])
                    all_gaps.extend(gaps)
                    rows.append({"campaign": name, "campaign_sha256": sha(folder / "campaign.json"),
                        "os": cell["os"], "reset": index, "capture_samples": samples,
                        "paired_window_gap_count": len(gaps), "median_gap_s": median(gaps), "max_gap_s": max(gaps)})
    return {"audit": "pass", "independent_resets_reused": len(rows), "new_physical_measurements": 0,
        "nominal_host_poll_interval_s": 0.1, "total_capture_samples": sum(r["capture_samples"] for r in rows),
        "paired_window_gap_count": len(all_gaps), "median_gap_s": median(all_gaps), "maximum_gap_s": max(all_gaps),
        "rows": rows, "scope": "host query/response-midpoint cadence within original paired integration windows; not sensor conversion rate, calibration or microsecond transient resolution",
        "ranking_eligible": False}


def audit():
    from audit_esp32_b1_controlled_energy import audit as controlled
    from audit_esp32_b1_native_energy import audit as native
    from replay_esp32_b1_energy import trace

    rows = []
    for is_native in (False, True):
        for case in CASES:
            name = "esp32-native-"+case+"-energy-b1-v1" if is_native else "esp32-"+(
                "message" if case == "message_processing" else case)+"-energy-b1-v1"
            folder = ROOT / "artifacts/reports" / name
            result = (native if is_native else controlled)(folder)
            setup = json.loads((folder / "operator-setup.json").read_text())
            for cell in result["cells"]:
                for index, run in enumerate(cell["runs"], 1):
                    capture = folder / cell["os"] / ("run%d" % index) / "capture"
                    _, powers = trace(capture, setup["polarity"])
                    windows = [perturb(powers, w["start_s"], w["end_s"]) for w in run["paired"]["paired_intervals"]]
                    rows.append({"campaign":name, "campaign_sha256":sha(folder / "campaign.json"),
                        "os":cell["os"], "case":case, "reset":index, "windows":windows})
    return {"audit":"pass", "independent_resets_reused":len(rows), "new_physical_measurements":0,
        "windows":sum(len(r["windows"]) for r in rows), "rows":rows,
        "maximum_translated_relative_change":max(w["translated_window_max_relative_change"] for r in rows for w in r["windows"]),
        "maximum_independent_endpoint_relative_change":max(w["independent_endpoint_max_relative_change"] for r in rows for w in r["windows"]),
        "maximum_observed_gap_s":max(w["sample_gap_s"] for r in rows for w in r["windows"]),
        "scope":"numerical sensitivity of retained whole-board energy windows, not sensor calibration or a total uncertainty bound",
        "counter_policy":"original work counts retained; no replacement benchmark score",
        "unmeasured":["sensor conversion delay", "voltage/current calibration error", "microsecond transients"],
        "ranking_eligible":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cadence", action="store_true", help="Audit retained host sampling cadence instead of window shifts")
    args = parser.parse_args()
    result = cadence_audit() if args.cadence else audit()
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k != "rows"}, indent=2))
