#!/usr/bin/env python3
"""Independent stdlib sensor/window arithmetic; not a second physical experiment."""
import argparse
import csv
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import re
import statistics
from replay_esp32_followup import campaign, digest, raw_rows, require

TITLES = {"message_processing":"Message Processing","preemptive_scheduling":"Preemptive Scheduling",
    "synchronization_processing":"Synchronization Processing","interrupt_processing":"Interrupt Processing",
    "interrupt_preemption_processing":"Interrupt Preemption Processing"}


def trace(folder, polarity):
    require(type(polarity) is int and polarity in (-1, 1), "Explicit fixed polarity required")
    metadata = json.loads((folder/"metadata.json").read_text())
    packets = [json.loads(s) for s in (folder/"meter.jsonl").read_text().splitlines()]
    with (folder/"power.csv").open(newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == ["timestamp_s","voltage_v","current_a"], "Different sensor columns")
        values = [tuple(float(row[k]) for k in reader.fieldnames) for row in reader]
    require(metadata["status"] == "complete" and len(values) == len(packets) == metadata["sample_count"] >= 2,
            "Incomplete sensor trace")
    require(math.isfinite(metadata["duration_actual_s"]) and metadata["duration_actual_s"] > 0,
            "Invalid trace duration")
    powers = []
    for value, packet in zip(values, packets):
        t, v, i = value
        start, end = packet["query_start_s"], packet["query_end_s"]
        raw = bytes.fromhex(packet["packet_hex"])
        require(48 <= len(raw) <= 64 and all(math.isfinite(n) for n in (t,v,i,start,end)),
                "Invalid raw sensor packet")
        require(0 <= start <= end <= metadata["duration_actual_s"] and end-start <= .05 and
                abs(t-(start+end)/2) < 1e-8 and t == packet["elapsed_s"], "Sensor timestamp differs")
        require(v == int.from_bytes(raw[8:12],"little")/1e6 and
                i == int.from_bytes(raw[12:16],"little",signed=True)/1e6 and
                0 <= v <= 60 and -6 <= i <= 6, "Signed raw sensor/CSV differs")
        require(i*polarity >= 0, "Mixed or opposite current direction; no pointwise absolute value")
        powers.append((t,v*i*polarity))
    require(all(0 < b[0]-a[0] <= .5 for a,b in zip(powers,powers[1:])) and
            all(a["query_end_s"] <= b["query_start_s"] for a,b in zip(packets,packets[1:])),
            "Sensor trace discontinuity")
    return metadata, powers


def interval_energy(powers, start, end):
    require(math.isfinite(start) and math.isfinite(end) and
            powers[0][0] <= start < end <= powers[-1][0], "Uncovered original report interval")
    energy = 0.0
    for (a,p), (b,q) in zip(powers,powers[1:]):
        left, right = max(start,a), min(end,b)
        if left < right:
            slope = (q-p)/(b-a)
            energy += (right-left)*((p+slope*(left-a))+(p+slope*(right-a)))/2
    require(math.isfinite(energy) and energy > 0, "Invalid measured interval energy")
    return energy


def paired_trace(folder, rows, polarity, system, case="message_processing"):
    require(case in TITLES,"Unsupported original active workload")
    metadata, powers = trace(folder,polarity)
    lines = [r["line"] for r in rows]
    require(lines.count("Thread-Metric "+system+" ESP32 boot") == 1 and
            sum(s.startswith("rst:0x") for s in lines) == 1 and
            next(r["elapsed_s"] for r in rows if r["line"].startswith("rst:0x")) < 2,
            "Original workload/reset witness differs")
    kind = {"message_processing":"queue","synchronization_processing":"semaphore"}.get(case)
    if kind:
        require(lines.count("Thread-Metric "+kind+" self-check PASS")==1,"Native object self-check missing")
    if case.startswith("interrupt_"):
        require(lines.count("Thread-Metric interrupt source=CPU_FROM_CPU2 peripheral=26 level=1 context=ISR")==1,
                "Matched real interrupt witness missing")
    require(not any(re.search(r"ERROR:|panic|abort|Guru Meditation|Exception|reboot!|ASSERT|FATAL",s,re.I)
                    for s in lines), "Workload error present")
    headings = [(i,int(m[1]),r["elapsed_s"]) for i,r in enumerate(rows) if
                (m := re.search(r"Thread-Metric "+TITLES[case]+r" Test .* Relative Time: (\d+)$",r["line"]))]
    totals = [(i,int(m[1])) for i,s in enumerate(lines) if
              (m := re.fullmatch(r"Time Period Total:\s*(\d+)",s.strip()))]
    require([h[1] for h in headings] == [30,60,90] and len(totals) == 3 and 25 < headings[0][2] < 40 and
            all(29.5 < b[2]-a[2] < 30.5 for a,b in zip(headings,headings[1:])), "Original windows differ")
    require(all(h[0] < t[0] < (headings[i+1][0] if i < 2 else len(rows)) and t[1] > 0
                for i,(h,t) in enumerate(zip(headings,totals))), "Original total/window pairing differs")
    windows = [{"start_s":a[2],"end_s":b[2],"duration_s":b[2]-a[2],
                "energy_j":interval_energy(powers,a[2],b[2]),"completed_original_counts":total[1]}
               for a,b,total in zip(headings,headings[1:],totals[1:])]
    energy, duration, count = (sum(w[k] for w in windows) for k in
                               ("energy_j","duration_s","completed_original_counts"))
    return {"paired_intervals":windows,"steady_energy_j":energy,"steady_duration_s":duration,
            "steady_average_power_w":energy/duration,"completed_original_counts":count,
            "original_counts_per_s":count/duration,"joules_per_original_count":energy/count,
            "energy_per_original_count_uj":energy/count*1e6}


def replay(folder):
    data = campaign(folder,allow_energy=True)
    case = data["case"]
    require(data["mode"] == "b1-energy" and data["board_mac"] == "34:98:7a:a2:85:28" and
            case in TITLES and data["completed_resets"] == 9, "Different B1 energy scope")
    setup = json.loads((folder/"operator-setup.json").read_text())
    plan = json.loads((folder/"plan.json").read_text())
    systems = ["FreeRTOS","Zephyr","NuttX"]
    require(plan["case"]==case and all(plan["source_proofs"][s]["case"]==case for s in systems),
            "Workload/source proof case differs")
    if case!="message_processing":
        extension = json.loads((folder/"kernel-profile.json").read_text())
        require(extension==plan["extension"] and extension["case"]==case and
            extension["driver_sha256"]==digest(folder/"kernel-energy-driver.py") and
            extension["base_driver_sha256"]==digest(folder/"run_esp32_b1_energy.py"),
            "Executed workload extension differs")
    require(setup["board_mac"] == data["board_mac"] == plan["board_mac"] and
            setup["meter_usb_id"] == "5fc9:0063" and setup["meter_serial"] == "086477" and
            setup["sole_board_supply_through_meter"] is True and setup["no_unmetered_data_usb_supply"] is True and
            setup["confirmation_source"] == "direct_user_message" and setup["operator_confirmation"].strip() and
            plan["systems"] == systems and plan["replace_prior_performance"] is False and
            plan["reuse_old_board_energy_for_b1"] is False, "Different board/supply/reuse scope")
    confirmed = datetime.fromisoformat(setup["verified_utc"])
    preflight, preflight_power = trace(folder/"meter-preflight",setup["polarity"])
    require(preflight["meter_serial"] == setup["meter_serial"] and preflight["port"] is None and
            len(preflight_power) >= 20 and any(p > 0 for _,p in preflight_power), "Read-only direction check differs")
    require(confirmed.tzinfo is not None and datetime.fromisoformat(preflight["started_utc"]) >= confirmed,
            "Confirmation must precede preflight")
    cells, chronology = [], []
    names = {"FreeRTOS":{"iotosbench_tm.elf":"application.elf","iotosbench_tm.bin":"application.bin",
                         "bootloader.bin":"bootloader.bin","partition-table.bin":"partitions.bin"},
             "Zephyr":{"zephyr.elf":"application.elf","zephyr.bin":"application.bin"},
             "NuttX":{"nuttx":"application.elf","nuttx.bin":"application.bin",
                      "bootloader-esp32.bin":"bootloader.bin","partition-table-esp32.bin":"partitions.bin"}}
    for system in systems:
        build = folder/system/"build"
        require(set(p.name for p in build.iterdir()) == set(names[system].values()) and
                all(digest(build/saved) == plan["source_proofs"][system]["images"][name]
                    for name,saved in names[system].items()), "Reused image bytes differ")
        runs = []
        for index in (1,2,3):
            capture = folder/system/("run%d"%index)/"capture"
            rows = raw_rows(capture/"reset1.jsonl")
            require((capture/"reset1.jsonl").read_bytes() == (capture/"uart.jsonl").read_bytes(), "UART alias differs")
            metadata = json.loads((capture/"metadata.json").read_text())
            start = datetime.fromisoformat(metadata["started_utc"])
            require(start.tzinfo is not None and start >= confirmed and metadata["uart_unterminated_bytes"] == 0 and
                    metadata["meter_serial"] == setup["meter_serial"] and
                    all(abs((datetime.fromisoformat(r["utc"])-start).total_seconds()-r["elapsed_s"]) <= .05
                        for r in rows), "Meter identity/raw coverage or shared-clock continuity differs")
            result = paired_trace(capture,rows,setup["polarity"],system,case)
            saved = json.loads((capture.parent/"energy-result.json").read_text())
            require(saved["board_mac"] == data["board_mac"] and saved["operator_setup_sha256"] == digest(folder/"operator-setup.json") and
                    all(math.isclose(result[k],saved["paired"][k],rel_tol=1e-10,abs_tol=1e-12)
                        for k in result if k != "paired_intervals"), "Independent energy/work arithmetic differs")
            runs.append(result)
            chronology.append((start,start+timedelta(seconds=metadata["duration_actual_s"]),system,index))
        keys = ("steady_average_power_w","energy_per_original_count_uj","original_counts_per_s")
        cells.append({"os":system,"runs":runs,"medians":{k:statistics.median(r[k] for r in runs) for k in keys}})
    chronology.sort()
    require(plan["schedule"] == [systems,["NuttX","FreeRTOS","Zephyr"],["Zephyr","NuttX","FreeRTOS"]] and
            [(r[2],r[3]) for r in chronology] == [(s,i) for i,order in enumerate(plan["schedule"],1) for s in order] and
            all(a[1] < b[0] for a,b in zip(chronology,chronology[1:])), "Actual interleaved chronology differs")
    return {"replay":"pass","board_mac":data["board_mac"],"independent_resets":9,"cells":cells,
            "energy_measured":True,"ranking_eligible":False,"external_independent_replication":False,
            "scope":"separate stdlib raw-packet/signed-current/byte-bound UART/window/count arithmetic; no new physical run or adapter semantic certification"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    args = parser.parse_args()
    print(json.dumps(replay(args.directory),indent=2))
