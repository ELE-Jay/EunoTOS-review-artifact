#!/usr/bin/env python3
"""Reuse admitted B1 images and performance evidence; acquire only missing paired board energy."""
import argparse
from datetime import datetime, timezone, timedelta
import fcntl
import json
import os
from pathlib import Path
import shutil
import statistics
from run_esp32_followup import Board, sha
from run_esp32_b1_message import SOURCES, SCHEDULE, sources, source_proof, audit as audit_baseline
from audit_esp32_followup import envelope, verified
from audit_esp32_powerz import audit as audit_power
from audit_esp32_tm_energy import paired_energy, check_native_rows
from audit_esp32_zephyr_thread import read_raw_capture

ROOT = Path(__file__).resolve().parents[1]
MAC = "34:98:7a:a2:85:28"
CASE = "message_processing"
BASELINE = "esp32-message-cohort-b1-v1"


def setup_statement(path):
    value = json.loads(path.read_text())
    if value.get("board_mac") != MAC or value.get("meter_usb_id") != "5fc9:0063" or value.get("meter_serial") != "086477" or \
            value.get("sole_board_supply_through_meter") is not True or value.get("no_unmetered_data_usb_supply") is not True or \
            value.get("confirmation_source") != "direct_user_message" or not value.get("operator_confirmation") or \
            type(value.get("polarity")) is not int or value["polarity"] not in (-1,1):
        raise ValueError("Current B1/meter supply-path statement missing or incorrectly qualified")
    when = datetime.fromisoformat(value["verified_utc"])
    if when.utcoffset() is None or when > datetime.now(timezone.utc):
        raise ValueError("Operator confirmation must precede acquisition")
    return value


def plan():
    baseline = ROOT/"artifacts/reports"/BASELINE
    observed = audit_baseline(baseline)
    if observed != json.loads((baseline/"audit.json").read_text()) or observed["board_mac"] != MAC:
        raise ValueError("Existing B1 performance evidence no longer passes its source-bound audit")
    proofs = {system:source_proof(system,CASE) for system in SOURCES}
    return {"board_mac":MAC,"case":CASE,"systems":list(SOURCES),"schedule":[list(s) for s in SCHEDULE],
        "reused_performance_evidence":"artifacts/reports/"+BASELINE,
        "reused_performance_audit_sha256":sha(baseline/"audit.json"),"source_proofs":proofs,
        "acquire":"missing same-clock power and original completed work; no separate performance rerun",
        "replace_prior_performance":False,"reuse_old_board_energy_for_b1":False,"new_metric_created":False}


def meter_preflight(folder,setup):
    metadata = json.loads((folder/"metadata.json").read_text())
    if metadata.get("meter_serial") != setup["meter_serial"] or metadata.get("port") is not None or \
            metadata.get("powerz_backend_sha256") != sha(Path(__file__).with_name("capture_esp32_powerz.py")) or \
            datetime.fromisoformat(metadata["started_utc"]) < datetime.fromisoformat(setup["verified_utc"]):
        raise ValueError("Read-only preflight does not bind the current meter, direction setup and backend")
    result = audit_power(folder,polarity=setup["polarity"],boundary_note=setup["operator_confirmation"])
    if result["sample_count"] < 20 or result["whole_trace"]["average_power_w"] <= 0:
        raise ValueError("Insufficient current-direction preflight before any board write")
    return result


def capture_result(folder,build,system,source_proof_value,setup):
    rows = read_raw_capture(folder,1)
    if (folder/"reset1.jsonl").read_bytes() != (folder/"uart.jsonl").read_bytes():
        raise ValueError("Power parser and byte-bound workload parser see different UART records")
    check_native_rows(rows,system,CASE)
    if sum(r["line"].startswith("rst:0x") for r in rows) != 1 or rows[0]["elapsed_s"] > 2:
        raise ValueError("One early independent ESP32 reset is required")
    metadata = json.loads((folder/"metadata.json").read_text())
    origin = datetime.fromisoformat(metadata["started_utc"])
    confirmed = datetime.fromisoformat(setup["verified_utc"])
    if metadata["meter_serial"] != setup["meter_serial"] or confirmed > origin or metadata["uart_unterminated_bytes"] or \
            metadata["powerz_backend_sha256"] != sha(Path(__file__).with_name("capture_esp32_powerz.py")):
        raise ValueError("Meter identity, clock, raw coverage or original sensor backend differs")
    # UTC is a cross-check only: both devices' primary timestamps share the monotonic origin.
    if any(abs((datetime.fromisoformat(r["utc"])-origin).total_seconds()-r["elapsed_s"]) > .05 for r in rows):
        raise ValueError("Host wall/monotonic timing continuity differs by more than 50 ms")
    result = audit_power(folder,polarity=setup["polarity"],boundary_note=setup["operator_confirmation"],tm_os=system,tm_case=CASE)
    metrics = paired_energy(result)
    return {"os":system,"case":CASE,"original_workload":result["original_workload"],"paired":metrics,
        "power_audit":result,"source_proof":source_proof_value,"operator_setup_sha256":setup["statement_sha256"],
        "whole_board_path":"operator confirmed all B1 supply passes through meter; no independent electrical isolation test",
        "board_mac":MAC,"ranking_eligible":False,"old_performance_replaced":False,
        "timing_limit":"host UART receipt and USB query midpoint; sensor conversion delay uncalibrated"}


def collect(root,output,setup_file,port):
    setup = setup_statement(setup_file)
    reuse = plan()
    if not Path(port).is_char_device() or shutil.disk_usage(root).free < 32*1024**2:
        raise ValueError("B1 serial interface absent or insufficient evidence space; refusing board writes")
    with (root/"tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        output.mkdir(parents=True,exist_ok=False)
        (output/"plan.json").write_text(json.dumps(reuse,indent=2)+"\n")
        shutil.copyfile(setup_file,output/"operator-setup.json")
        setup["statement_sha256"] = sha(output/"operator-setup.json")
        for name in ("run_esp32_b1_energy.py","capture_esp32_b1_powerz.py","capture_esp32_powerz.py"):
            shutil.copyfile(Path(__file__).with_name(name),output/name)
        shutil.copyfile(Path(__file__).with_name("run_esp32_followup.py"),output/"board-helper.py")
        for system,(directory,images) in sources(CASE).items():
            folder = output/system
            (folder/"build").mkdir(parents=True)
            for name,saved in images.items():
                file = root/"downloads"/directory/name
                if sha(file) != reuse["source_proofs"][system]["images"][name]:
                    raise ValueError("Remote reused image differs from source-qualified baseline")
                shutil.copyfile(file,folder/"build"/saved)
        board = Board(root,output,MAC,port)
        board.env["PYTHONPATH"] = str(root/"powerz-python")+":"+board.env["PYTHONPATH"]
        report = {"mode":"b1-energy","status":"incomplete","board_mac":MAC,"case":CASE,
            "started_utc":datetime.now(timezone.utc).isoformat(),"original_flash_restored":False,
            "old_cohort_modified":False,"energy_measured":True,"external_independent_replication":False,
            "ranking_eligible":False,"completed_resets":0}
        try:
            board.command([board.python,str(output/"capture_esp32_b1_powerz.py"),"--seconds","3",
                           "--output",str(output/"meter-preflight")],output/"meter-preflight.log",10)
            meter_preflight(output/"meter-preflight",setup)
            board.backup()
            try:
                for index,order in enumerate(SCHEDULE,1):
                    for system in order:
                        folder = output/system/("run%d"%index)
                        folder.mkdir()
                        pairs = board.flash(folder,output/system/"build")
                        command = [board.python,str(output/"capture_esp32_b1_powerz.py"),"--port",port,"--output",str(folder/"capture")]
                        if system == "NuttX": command += ["--send-line","iotosbench"]
                        board.command(command,folder/"capture.log",115)
                        board.verify(pairs,folder/"verify-after.log")
                        result = capture_result(folder/"capture",output/system/"build",system,reuse["source_proofs"][system],setup)
                        (folder/"energy-result.json").write_text(json.dumps(result,indent=2)+"\n")
                        report["completed_resets"] += 1
                        print("ENERGY",system,index,result["paired"]["steady_average_power_w"],result["paired"]["energy_per_original_count_uj"],flush=True)
                report["status"] = "collection_complete_audit_pending"
            finally:
                board.restore()
                report["original_flash_restored"] = True
        finally:
            report["completed_utc"] = datetime.now(timezone.utc).isoformat()
            report["files"] = {p.relative_to(output).as_posix():sha(p) for p in output.rglob("*") if p.is_file() and p.name != "campaign.json"}
            (output/"campaign.json").write_text(json.dumps(report,indent=2)+"\n")


def audit(output):
    campaign = envelope(output,allow_energy=True)
    if campaign["mode"] != "b1-energy" or campaign["board_mac"] != MAC or campaign["completed_resets"] != 9 or campaign["case"] != CASE:
        raise ValueError("Incomplete or different B1 energy workload")
    reuse = plan()
    if reuse != json.loads((output/"plan.json").read_text()):
        raise ValueError("Reused baseline/configuration proof changed")
    for name in ("run_esp32_b1_energy.py","capture_esp32_b1_powerz.py","capture_esp32_powerz.py"):
        if (output/name).read_bytes() != Path(__file__).with_name(name).read_bytes():
            raise ValueError("Unreviewed new-cohort acquisition source")
    setup = setup_statement(output/"operator-setup.json")
    setup["statement_sha256"] = sha(output/"operator-setup.json")
    preflight = meter_preflight(output/"meter-preflight",setup)
    cells,order = [],[]
    for system,(_,images) in sources(CASE).items():
        build = output/system/"build"
        if set(p.name for p in build.iterdir()) != set(images.values()) or any(sha(build/saved) != reuse["source_proofs"][system]["images"][name] for name,saved in images.items()):
            raise ValueError("Energy image is not the reused admitted image")
        runs = []
        for index in (1,2,3):
            folder = output/system/("run%d"%index)
            verified(folder,build,MAC)
            result = capture_result(folder/"capture",build,system,reuse["source_proofs"][system],setup)
            if result != json.loads((folder/"energy-result.json").read_text()):
                raise ValueError("Paired energy or original work count differs")
            metadata = json.loads((folder/"capture/metadata.json").read_text())
            start = datetime.fromisoformat(metadata["started_utc"])
            order.append((start,start+timedelta(seconds=metadata["duration_actual_s"]),system,index))
            runs.append(result)
        keys = ("steady_average_power_w","energy_per_original_count_uj","original_counts_per_s")
        cells.append({"os":system,"case":CASE,"runs":runs,"medians":{k:statistics.median(r["paired"][k] for r in runs) for k in keys},
            "independent_resets":3,"ranking_eligible":False})
    order.sort()
    if [(r[2],r[3]) for r in order] != [(s,i) for i,systems in enumerate(SCHEDULE,1) for s in systems] or any(a[1]>=b[0] for a,b in zip(order,order[1:])):
        raise ValueError("Actual acquisition chronology differs from interleaved original plan")
    return {"audit":"pass","board":"B1","board_mac":MAC,"case":CASE,"cells":cells,"reuse":reuse,
        "independent_resets":9,"original_flash_restored":True,"energy_measured":True,
        "operator_confirmed_whole_board_input":True,"polarity":setup["polarity"],"old_cohort_modified":False,
        "read_only_meter_preflight":preflight,
        "external_independent_replication":False,"ranking_eligible":False,"new_metric_created":False,
        "boundary":"original active message workload, complete board input plus downstream lead loss; calibration and conversion lag unverified; no sleep/network claim"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("plan","collect","audit"))
    parser.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--setup",type=Path)
    parser.add_argument("--port",default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    if args.mode == "plan":
        result = plan()
        if args.output is not None:
            args.output.mkdir(parents=True,exist_ok=True)
            (args.output/"plan.json").write_text(json.dumps(result,indent=2)+"\n")
    elif args.mode == "collect":
        if args.output is None or args.setup is None: parser.error("Fresh output and prior operator setup required")
        collect(args.root,args.output,args.setup,args.port); raise SystemExit(0)
    else:
        if args.output is None: parser.error("Audit requires retained campaign output")
        result = audit(args.output)
        (args.output/"audit.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
