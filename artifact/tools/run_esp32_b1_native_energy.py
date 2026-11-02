#!/usr/bin/env python3
"""Acquire missing B1 RIOT/Rhino energy using their already measured images."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import shutil
import statistics

import run_esp32_b1_energy as engine
from replay_esp32_b1_energy import paired_trace
from replay_esp32_followup import raw_rows

CASES = ("message_processing", "synchronization_processing", "preemptive_scheduling",
         "interrupt_processing", "interrupt_preemption_processing")
SYSTEMS = ("RIOT", "AliOS-Rhino")
SCHEDULE = (SYSTEMS, tuple(reversed(SYSTEMS)), SYSTEMS)
IMAGES = {name: name for name in ("application.elf", "application.bin", "bootloader.bin", "partitions.bin")}


def reference(system, case):
    if case == "message_processing":
        return "esp32-" + ("riot" if system == "RIOT" else "rhino") + "-gcc13-legacy-v1"
    return "esp32-" + ("riot" if system == "RIOT" else "rhino") + "-gcc13-suite-build-v1/" + case


def sources(case):
    if case not in CASES:
        raise ValueError("Only the five previously measured active workloads are admitted")
    return {s: (str(engine.ROOT / "artifacts/reports" / reference(s, case)), IMAGES) for s in SYSTEMS}


def source_proof(system, case):
    from audit_esp32_rhino_gcc13 import build as rhino_build
    from audit_esp32_riot_startup import build as riot_build
    source = engine.ROOT / "artifacts/reports" / reference(system, case)
    checked = riot_build(source, False) if system == "RIOT" else rhino_build(source, case)
    return {"source": reference(system, case), "case": case,
            "images": checked["images"], "ranking_eligible": False,
            "conditions": "GCC13 sources; native tickless/GCC12 newlib" if system == "RIOT" else
                          "GCC13 sources; 100-Hz native Rhino, legacy SDK/libc"}


def plan(case):
    from audit_esp32_native_suite_builds import audit_campaign as native_suite
    from audit_esp32_rhino_gcc13 import audit as rhino_message
    from audit_esp32_riot_startup import audit as riot_message
    evidence = engine.ROOT / "artifacts/reports"
    baselines = []
    if case == "message_processing":
        for system, folder, check in (("RIOT", "esp32-riot-gcc13-legacy-b1-v1", riot_message),
                                       ("AliOS-Rhino", "esp32-rhino-gcc13-b1-v1", rhino_message)):
            source = evidence / reference(system, case)
            observed = check(evidence / folder, source, False) if system == "RIOT" else check(evidence / folder, source)
            if observed["audit"] != "pass" or observed["independent_resets"] != 3 or observed["case"] != case:
                raise ValueError("Missing admitted native message measurements")
            baselines.append({"directory": folder, "campaign_sha256": engine.sha(evidence / folder / "campaign.json")})
    else:
        folder = "esp32-native-irq-suite-b1-v1" if case.startswith("interrupt_") else "esp32-native-task-suite-b1-v1"
        observed = native_suite(evidence / folder)
        if observed["audit"] != "pass" or {r["os"] for r in observed["cells"] if r["case"] == case} != set(SYSTEMS):
            raise ValueError("Missing admitted native original workload")
        baselines.append({"directory": folder, "campaign_sha256": engine.sha(evidence / folder / "campaign.json")})
    return {"board_mac": engine.MAC, "case": case, "systems": list(SYSTEMS),
            "schedule": [list(s) for s in SCHEDULE], "reused_performance_evidence": baselines,
            "source_proofs": {s: source_proof(s, case) for s in SYSTEMS},
            "extension": {"driver_sha256": engine.sha(Path(__file__)),
                          "base_driver_sha256": engine.sha(Path(engine.__file__))},
            "replace_prior_performance": False, "reuse_old_board_energy_for_b1": False,
            "new_metric_created": False, "cross_os_ranking_eligible": False,
            "acquire": "same-clock whole-board input energy and unchanged original completed work"}


@contextmanager
def configured(case, sealed=None, root=None):
    previous = engine.CASE, engine.SOURCES, engine.SCHEDULE, engine.sources, engine.plan, engine.Board
    base_board = engine.Board

    class NativeBoard(base_board):
        def __init__(self, root, output, *args):
            super().__init__(root, output, *args)
            shutil.copyfile(__file__, output / "native-energy-driver.py")

    engine.CASE, engine.SOURCES, engine.SCHEDULE = case, dict.fromkeys(SYSTEMS), SCHEDULE
    def installed_sources(selected):
        if selected != case:
            raise ValueError("Wrong selected workload")
        if case == "message_processing":
            return {s: (str(root / "downloads" / ("esp32-riot-gcc13-legacy-b1-v1" if s == "RIOT" else
                       "esp32-rhino-gcc13-b1-v1") / "build"), IMAGES) for s in SYSTEMS}
        return {s: (str(Path("/dev/shm") / ("iotos-riot-tm-gcc13-build-v1" if s == "RIOT" else
                    "iotos-rhino-gcc13-suite-build-v1") / case), IMAGES) for s in SYSTEMS}
    engine.sources, engine.plan, engine.Board = (installed_sources if sealed else sources), (lambda: sealed if sealed else plan(case)), NativeBoard
    try:
        yield
    finally:
        engine.CASE, engine.SOURCES, engine.SCHEDULE, engine.sources, engine.plan, engine.Board = previous


def collect(root, output, setup, port, case, sealed_file):
    sealed = json.loads(sealed_file.read_text())[case]
    if sealed["case"] != case or sealed["board_mac"] != engine.MAC or sealed["systems"] != list(SYSTEMS) or \
            sealed["schedule"] != [list(s) for s in SCHEDULE] or \
            sealed["extension"] != {"driver_sha256": engine.sha(Path(__file__)), "base_driver_sha256": engine.sha(Path(engine.__file__))}:
        raise ValueError("Locally source-qualified acquisition plan differs")
    with configured(case, sealed, root):
        engine.collect(root, output, setup, port)


def audit(output):
    campaign = engine.envelope(output, allow_energy=True)
    case = campaign["case"]
    if campaign["mode"] != "b1-energy" or campaign["board_mac"] != engine.MAC or campaign["completed_resets"] != 6:
        raise ValueError("Incomplete native B1 energy cohort")
    expected = plan(case)
    if expected != json.loads((output / "plan.json").read_text()):
        raise ValueError("Native baseline or source proof changed")
    for name in ("run_esp32_b1_energy.py", "capture_esp32_b1_powerz.py", "capture_esp32_powerz.py"):
        if (output / name).read_bytes() != Path(__file__).with_name(name).read_bytes():
            raise ValueError("Acquisition source changed: " + name)
    if (output / "native-energy-driver.py").read_bytes() != Path(__file__).read_bytes():
        raise ValueError("Executed native profile changed")
    setup = engine.setup_statement(output / "operator-setup.json")
    setup["statement_sha256"] = engine.sha(output / "operator-setup.json")
    engine.meter_preflight(output / "meter-preflight", setup)
    cells, chronology = [], []
    with configured(case):
        for system in SYSTEMS:
            build = output / system / "build"
            proof = expected["source_proofs"][system]
            if set(p.name for p in build.iterdir()) != set(IMAGES) or any(engine.sha(build / n) != v for n, v in proof["images"].items()):
                raise ValueError("Measured image differs from its admitted native source")
            runs = []
            for index in (1, 2, 3):
                folder = output / system / ("run%d" % index)
                engine.verified(folder, build, engine.MAC)
                result = engine.capture_result(folder / "capture", build, system, proof, setup)
                if result != json.loads((folder / "energy-result.json").read_text()):
                    raise ValueError("Native captured result differs from source-bound replay")
                separate = paired_trace(folder / "capture", raw_rows(folder / "capture/reset1.jsonl"), setup["polarity"], system, case)
                if any(not math.isclose(separate[k], result["paired"][k], rel_tol=1e-10, abs_tol=1e-12)
                       for k in separate if k != "paired_intervals"):
                    raise ValueError("Independent signed-packet/window/count integration differs")
                metadata = json.loads((folder / "capture/metadata.json").read_text())
                start = datetime.fromisoformat(metadata["started_utc"])
                chronology.append((start, start + timedelta(seconds=metadata["duration_actual_s"]), system, index))
                runs.append(result)
            keys = ("steady_average_power_w", "energy_per_original_count_uj", "original_counts_per_s")
            cells.append({"os": system, "case": case, "runs": runs,
                          "medians": {k: statistics.median(r["paired"][k] for r in runs) for k in keys},
                          "independent_resets": 3, "ranking_eligible": False})
    chronology.sort()
    if [(r[2], r[3]) for r in chronology] != [(s, i) for i, order in enumerate(SCHEDULE, 1) for s in order] or \
            any(a[1] >= b[0] for a, b in zip(chronology, chronology[1:])):
        raise ValueError("Actual native run order overlaps or differs from the plan")
    return {"audit": "pass", "independent_arithmetic_replay": "pass", "board": "B1",
            "board_mac": engine.MAC, "case": case, "cells": cells, "independent_resets": 6,
            "energy_measured": True, "original_flash_restored": True, "ranking_eligible": False,
            "new_metric_created": False, "external_independent_replication": False,
            "boundary": "native configurations; whole-board input including downstream lead loss; operator-confirmed sole supply; calibration and sensor lag unverified; no sleep/network or universal OS ranking"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "collect", "audit"))
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--plan", type=Path, help="Locally source-audited five-case plan; revalidated during final audit")
    parser.add_argument("--port", default="/dev/ttyUSB0")
    args = parser.parse_args()
    if args.mode == "plan":
        print(json.dumps(plan(args.case), indent=2))
    elif args.mode == "collect":
        collect(args.root, args.output, args.setup, args.port, args.case, args.plan)
    else:
        result = audit(args.output)
        (args.output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({k: v for k, v in result.items() if k != "cells"}, indent=2))
