#!/usr/bin/env python3
"""Measure retained Tenon image activation at Pi board input; no model or build."""
import argparse
import contextlib
import csv
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
import time

from capture_esp32_powerz import Meter
from replay_esp32_b1_energy import interval_energy, trace
from run_tenonos_paper_tasks import prepare_runtime_helpers
from run_tenonos_policy_sequence import boot_parent
from tenonos_kvm_reproduce import save, sha, utc

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("run_tenonos_energy.py", "capture_esp32_powerz.py", "run_tenonos_policy_sequence.py",
           "run_tenonos_paper_tasks.py", "tenonos_kvm_reproduce.py", "tenonos_orchestrator.py")


def reference_images(plan, root):
    variants = {v["id"]: v for v in plan["variants"]}
    if not variants or len(variants) != len(plan["variants"]):
        raise ValueError("Expected distinct nonempty retained image references")
    for value in variants.values():
        folder = (root / value["build"]).resolve()
        folder.relative_to(root.resolve())
        proof = json.loads((folder / "build-result.json").read_text())
        if sha(folder / "runtime-image") != value["image_sha256"] or sha(folder / ".config") != value["config_sha256"] or \
                (proof["image_sha256"], proof["config_sha256"]) != (value["image_sha256"], value["config_sha256"]):
            raise ValueError("Frozen image/config identity changed")
    return variants


def references(plan, root):
    variants = reference_images(plan, root)
    if len(variants) != 3 or len(plan["schedule"]) != 3 or any(set(r) != set(variants) or len(r) != 3 for r in plan["schedule"]):
        raise ValueError("Expected three counterbalanced trials per retained image")
    return variants


def host_state(ssh):
    code = """import pathlib,subprocess,json,platform
p=pathlib.Path('/sys/devices/system/cpu/cpu0/cpufreq')
print(json.dumps({'model':pathlib.Path('/proc/device-tree/model').read_bytes().decode().rstrip(chr(0)),
'serial':[s.split(':',1)[1].strip() for s in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('Serial')],
'machine':platform.machine(),'governor':(p/'scaling_governor').read_text().strip(),
'frequency_khz':int((p/'scaling_cur_freq').read_text()),
'throttled':subprocess.check_output(['vcgencmd','get_throttled']).decode().strip(),
'temperature':subprocess.check_output(['vcgencmd','measure_temp']).decode().strip(),
'qemu_running':any(p.joinpath('comm').read_text().startswith('qemu-system') for p in pathlib.Path('/proc').iterdir() if p.name.isdigit() and p.joinpath('comm').exists())}))"""
    return json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])], timeout=20))


def governor(ssh, name):
    if name not in ("performance", "powersave", "ondemand", "conservative", "schedutil", "userspace"):
        raise ValueError("Unrecognized recorded governor")
    code = "from pathlib import Path;Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor').write_text(" + repr(name) + ")"
    subprocess.run([*ssh, shlex.join(["sudo", "-n", "python3", "-c", code])], check=True, timeout=20)


def sample(meter, folder, origin, stop, ready, errors, interval):
    metadata = {"status": "incomplete", "started_utc": utc(), "host_monotonic_start_s": origin,
                "interval_requested_s": interval, "meter": "POWER-Z KM003C", "usb_id": "5fc9:0063",
                "meter_serial": meter.util.get_string(meter.device, meter.device.iSerialNumber),
                "port": None, "sample_count": 0, "timestamp_semantics": "one leon query midpoint/activation clock",
                "calibration": "instrument default; external calibration and sensor conversion delay not verified"}
    try:
        if metadata["meter_serial"] != "086477":
            raise ValueError("Different instrument serial")
        with (folder / "power.csv").open("x", newline="") as csv_file, (folder / "meter.jsonl").open("x") as raw:
            writer = csv.writer(csv_file)
            writer.writerow(["timestamp_s", "voltage_v", "current_a"])
            while True:
                before, after, packet, voltage, current = meter.read()
                elapsed = (before + after) / 2 - origin
                writer.writerow([elapsed, voltage, current])
                raw.write(json.dumps({"elapsed_s": elapsed, "query_start_s": before - origin,
                                      "query_end_s": after - origin, "packet_hex": packet.hex()}) + "\n")
                csv_file.flush()
                raw.flush()
                metadata["sample_count"] += 1
                ready.set()
                if stop.is_set():
                    break
                time.sleep(max(0, interval - (time.monotonic() - before)))
        metadata["status"] = "complete"
    except BaseException as error:
        errors.append(repr(error))
        ready.set()
    finally:
        metadata["duration_actual_s"] = time.monotonic() - origin
        save(folder / "metadata.json", metadata)


def activation(folder, value, ssh, host, socket, pi_workspace, helpers, polarity, interval):
    folder.mkdir(parents=True, exist_ok=False)
    meter = Meter()
    origin = time.monotonic()
    stop, ready, errors = threading.Event(), threading.Event(), []
    worker = threading.Thread(target=sample, args=(meter, folder, origin, stop, ready, errors, interval))
    row = {"variant": value["id"], "status": "incomplete", "started_utc": utc()}
    save(folder / "activation.json", row)
    worker.start()
    try:
        if not ready.wait(3) or errors:
            raise ValueError("Meter did not produce the leading sample: " + repr(errors))
        row["start_s"] = time.monotonic() - origin
        save(folder / "activation.json", row)
        with (folder / "activation.log").open("x") as log, contextlib.redirect_stdout(log):
            row["runtime"] = boot_parent(folder / "runtime", ROOT / value["build"], ssh, host, socket,
                                         pi_workspace, helpers, "/dev/shm/iotos-tenon-v4-energy-" + folder.name)
        row["end_s"] = time.monotonic() - origin
        row["status"] = "complete"
    except BaseException as error:
        row.update(status="failed", error=repr(error), end_s=time.monotonic() - origin)
        raise
    finally:
        stop.set()
        worker.join(timeout=3)
        meter.close()
        if worker.is_alive() or errors:
            row.update(status="failed", meter_errors=errors or ["Sampler did not stop"])
        save(folder / "activation.json", row)
    if row["status"] != "complete":
        raise ValueError("Incomplete activation or meter capture")
    _, powers = trace(folder, polarity)
    energy = interval_energy(powers, row["start_s"], row["end_s"])
    row.update(duration_s=row["end_s"] - row["start_s"], energy_j=energy)
    row["average_power_w"] = energy / row["duration_s"]
    save(folder / "activation.json", row)
    return row


def run(plan_path, output, host, socket, pi_workspace, polarity, preflight):
    if ROOT != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Run only on leon in a new persistent capture folder")
    output.resolve().relative_to((ROOT / "artifacts/reports").resolve())
    plan = json.loads(plan_path.read_text())
    variants = references(plan, ROOT)
    probe, _ = trace(preflight, polarity)
    if probe["meter_serial"] != "086477" or probe["sample_count"] < 20 or probe["port"] is not None:
        raise ValueError("Current read-only instrument preflight missing")
    if plan["guest"] != {"accelerator": "kvm", "vcpus": 1, "memory_bytes": 134217728, "fresh_boots_per_activation": 3}:
        raise ValueError("Frozen guest envelope differs")
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host]
    initial = host_state(ssh)
    if "Raspberry Pi 4" not in initial["model"] or initial["machine"] != "aarch64" or initial["qemu_running"] or initial["throttled"] != "throttled=0x0":
        raise ValueError("Pi is not idle, healthy or the expected model")
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output / "protocol.json")
    shutil.copytree(preflight, output / "meter-preflight")
    (output / "sources").mkdir()
    for name in SOURCES:
        shutil.copyfile(ROOT / "tools" / name, output / "sources" / name)
    setup = {"verified_utc": utc(), "target": "Raspberry Pi 4B", "confirmation_source": "direct_user_message",
             "operator_confirmation": "已经把 POWER-Z 改串到树莓派 4B 的供电线上了",
             "answers_pi_only_supply_request": True, "sole_board_supply_through_meter": True,
             "meter_serial": "086477", "polarity": polarity, "initial_host": initial}
    save(output / "operator-setup.json", setup)
    result = {"status": "incomplete", "started_utc": utc(), "trials": [], "model_calls": 0, "rebuilds": 0,
              "protocol_sha256": sha(plan_path), "source_sha256": {n: sha(ROOT / "tools" / n) for n in SOURCES}}
    save(output / "campaign.json", result)
    helpers = None
    try:
        governor(ssh, "performance")
        helpers, ids = prepare_runtime_helpers(ssh, host, socket, pi_workspace)
        result["source_commits"] = ids["source_commits"]
        for index, sequence in enumerate(plan["schedule"], 1):
            for name in sequence:
                if any(sha(ROOT / "tools" / n) != h for n, h in result["source_sha256"].items()):
                    raise ValueError("Registered collector or reused runtime helper changed")
                references(plan, ROOT)
                time.sleep(plan["cooldown_between_activations_s"])
                trial = "R%d-%s" % (index, name)
                before = host_state(ssh)
                if before["governor"] != "performance" or before["throttled"] != "throttled=0x0" or before["qemu_running"]:
                    raise ValueError("Host envelope changed before activation")
                row = activation(output / trial, variants[name], ssh, host, socket, pi_workspace,
                                 helpers, polarity, plan["instrument"]["query_interval_s"])
                row.update(id=trial, round=index, host_before=before, host_after=host_state(ssh))
                result["trials"].append(row)
                save(output / trial / "activation.json", row)
                save(output / "campaign.json", result)
                print(json.dumps({"trial": trial, "duration_s": row["duration_s"], "energy_j": row["energy_j"]}), flush=True)
                if row["host_after"]["throttled"] != "throttled=0x0":
                    raise ValueError("Pi reported throttling during collection")
        result["status"] = "complete"
    except BaseException as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        try:
            governor(ssh, initial["governor"])
            result["host_after_restore"] = host_state(ssh)
            result["governor_restored"] = result["host_after_restore"]["governor"] == initial["governor"]
            if not result["governor_restored"]:
                raise ValueError("Host governor restoration differs")
        except BaseException as error:
            result.update(status="failed", restoration_error=repr(error), governor_restored=False)
        result["ended_utc"] = utc()
        save(output / "campaign.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=ROOT / "registry/tenonos_energy_rpi4_v1.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host", default="pi@192.168.31.76")
    parser.add_argument("--socket", default="/tmp/iotos-pi-energy.sock")
    parser.add_argument("--pi-workspace", default="/home/pi/tenonos-benchmark-v1")
    parser.add_argument("--polarity", type=int, choices=(-1, 1), required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    args = parser.parse_args()
    with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(args.plan, args.output.resolve(), args.host, args.socket, args.pi_workspace, args.polarity, args.preflight)
