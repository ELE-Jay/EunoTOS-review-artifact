#!/usr/bin/env python3
"""Reuse the sealed B1 energy collector for other already-admitted original cases."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import run_esp32_b1_energy as engine
from audit_esp32_tm_energy import WORK_UNITS

BASELINES = {
    "preemptive_scheduling":"esp32-preemptive_scheduling-cohort-b1-v1",
    "synchronization_processing":"esp32-synchronization_processing-cohort-b1-v1",
    "interrupt_processing":"esp32-interrupt_processing-cohort-b1-v1",
    "interrupt_preemption_processing":"esp32-interrupt_preemption_processing-cohort-b1-v3",
}


def profile(case):
    if case not in BASELINES:
        raise ValueError("Only the four missing, complete three-OS original cohorts are admitted")
    return {"case":case,"driver_sha256":engine.sha(Path(__file__)),
        "base_driver_sha256":engine.sha(Path(engine.__file__))}


@contextmanager
def configured(case):
    declared = profile(case)
    previous = engine.CASE,engine.BASELINE,engine.plan,engine.Board
    base_plan,base_board = engine.plan,engine.Board
    def scoped_plan():
        baseline = engine.ROOT/"artifacts/reports"/BASELINES[case]
        observed = engine.audit_baseline(baseline)
        if observed["case"]!=case or observed["independent_resets"]!=9 or \
                [c["os"] for c in observed["cells"]]!=list(engine.SOURCES):
            raise ValueError("Reused case or complete native cohort differs")
        return {**base_plan(),"extension":declared,"work_unit":WORK_UNITS[case]}
    class ScopedBoard(base_board):
        def __init__(self,root,output,*args):
            super().__init__(root,output,*args)
            shutil.copyfile(__file__,output/"kernel-energy-driver.py")
            (output/"kernel-profile.json").write_text(json.dumps(declared,indent=2)+"\n")
    engine.CASE,engine.BASELINE,engine.plan,engine.Board = case,BASELINES[case],scoped_plan,ScopedBoard
    try:
        yield
    finally:
        engine.CASE,engine.BASELINE,engine.plan,engine.Board = previous


def plan(case):
    with configured(case):
        return engine.plan()


def collect(root,output,setup,port,case):
    with configured(case):
        engine.collect(root,output,setup,port)


def audit(output):
    case = json.loads((output/"campaign.json").read_text())["case"]
    declared = profile(case)
    if (output/"kernel-energy-driver.py").read_bytes()!=Path(__file__).read_bytes() or \
            json.loads((output/"kernel-profile.json").read_text())!=declared:
        raise ValueError("Executed case extension source differs")
    with configured(case):
        result = engine.audit(output)
    return {**result,"extension":declared,"work_unit":WORK_UNITS[case],
        "boundary":"unchanged original "+case+" active workload, whole board input plus downstream lead loss; calibration and conversion lag unverified; no sleep/network or universal OS score claim"}


if __name__=="__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("plan","collect","audit"))
    parser.add_argument("--case",choices=tuple(BASELINES))
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--setup",type=Path)
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    if args.mode=="plan":
        result = {case:plan(case) for case in BASELINES} if args.case is None else plan(args.case)
        if args.output is not None:
            args.output.mkdir(parents=True,exist_ok=True)
            (args.output/"plan.json").write_text(json.dumps(result,indent=2)+"\n")
    elif args.mode=="collect":
        if args.case is None or args.output is None or args.setup is None:
            parser.error("An admitted case, fresh output and operator setup are required")
        collect(args.root,args.output,args.setup,args.port,args.case)
        raise SystemExit(0)
    else:
        if args.output is None:
            parser.error("Retained campaign output required")
        result = audit(args.output)
        (args.output/"audit.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
