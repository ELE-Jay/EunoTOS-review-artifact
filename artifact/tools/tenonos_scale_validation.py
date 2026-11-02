#!/usr/bin/env python3
"""Validate retained configurations at a new original-test iteration scale."""
import argparse
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess

from import_iotos_subjects import config_text
from tenonos_kvm_reproduce import boot, command, save, sha, sources, utc

ROOT = Path(__file__).resolve().parents[1]


def scaled_header(raw, before=500, after=2000):
    anchor = ("#define RST_BENCHMARKS_COUNT %d\n" % before).encode()
    if raw.count(anchor) != 1 or before != 500 or after != 2000:
        raise ValueError("Unexpected original iteration parameter")
    return raw.replace(anchor, ("#define RST_BENCHMARKS_COUNT %d\n" % after).encode())


def configuration(path):
    values, duplicates = config_text(path.read_text())
    if duplicates:
        raise ValueError("Duplicate native configuration options")
    return values


def original_units(outcome):
    values = outcome["original_printed_values"]
    return all(len(rows) == 1 and rows[0]["unit"] == ("count" if name.startswith("timer_deviation") else "cycle")
               for name, rows in values.items()) and len(values) == 6


def source_path_rebinding(before, after, original, scaled):
    changes = {n: [before.get(n), after.get(n)] for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    expected = {"CONFIG_UK_APP": [json.dumps(str(original)), json.dumps(str(scaled))]}
    if changes != expected:
        raise ValueError("Scale validation changed more than the declared source-path binding")
    return changes


def on_pi(workspace, output):
    from tenonos_kvm_reproduce import original_results
    if output.parent != Path("/dev/shm") or not output.name.startswith("iotos-tenon-v4-scale-"):
        raise ValueError("Unsafe temporary validation directory")
    baseline_ids = sources(workspace, True, "abi")
    original = workspace / "apps/app-rtos-benchmark-abi"
    names = subprocess.check_output(["git", "-C", str(original), "ls-files", "-z"]).decode().split("\0")[:-1]
    app = output / "source/app-rtos-benchmark-scale"
    app.mkdir(parents=True, exist_ok=False)
    before, after = {}, {}
    for name in names:
        source, copied = original / name, app / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, copied)
        before[name] = sha(source)
    header = app / "include/rst_cfg.h"
    header.write_bytes(scaled_header(header.read_bytes()))
    after = {n: sha(app / n) for n in names}
    save(output / "source-proof.json", {"upstream_and_adapter_identity": baseline_ids,
         "original_sha256": before, "scaled_sha256": after, "changed_files": [n for n in names if before[n] != after[n]],
         "parameter": {"original": 500, "validation": 2000}, "test_bodies_changed": False})
    build = output / "build"
    build.mkdir()
    shutil.copyfile(output / "input.config", build / "input.defconfig")
    make = ["make", "-C", str(workspace / "tenon-c11"), "A=" + str(app), "O=" + str(build / "build"),
            "C=" + str(build / ".config"), "CROSS_COMPILE=", "COMPILER=gcc", "L=" + str(workspace / "libs")]
    for name, argv in (("compiler", ["gcc", "--version"]),
                       ("configure", [*make, "UK_DEFCONFIG=" + str(build / "input.defconfig"), "defconfig"]),
                       ("build", ["timeout", "--kill-after=10", "900", *make, "-j2"])):
        if command(build, name, argv)["returncode"]:
            raise ValueError("Native scale-profile build failed: " + name)
    images = list((build / "build").glob("*_qemu-arm64"))
    if len(images) != 1:
        raise ValueError("Expected one linked scale-validation image")
    shutil.copyfile(images[0], build / "runtime-image")
    binding = source_path_rebinding(configuration(output / "input.config"), configuration(build / ".config"), original, app)
    save(output / "configuration-rebinding.json", {"changes": binding, "other_options_identical": True,
         "original_config_sha256": sha(output / "input.config"), "scaled_config_sha256": sha(build / ".config")})
    save(build / "build-result.json", {"application": "app-rtos-benchmark-scale", "image": str(build / "runtime-image"),
         "image_sha256": sha(build / "runtime-image"), "config_sha256": sha(build / ".config"),
         "input_defconfig_sha256": sha(build / "input.defconfig"), "c11_timer_fix": True,
         "source_commits": sources(workspace, True, True), "compiler": "gcc", "iterations": 2000,
         "source_profile_sha256": sha(output / "source-proof.json"), "ranking_eligible": False})
    boot(workspace, build, output / "boots", "kvm")
    outcomes = []
    for index in (1, 2, 3):
        prefix = output / "boots" / ("boot" + str(index))
        step = json.loads(prefix.with_suffix(".json").read_text())
        outcome = original_results(prefix.with_suffix(".stdout").read_bytes(), prefix.with_suffix(".stderr").read_bytes(),
                                   step["returncode"])
        outcomes.append(outcome)
        if not outcome["original_output_complete"] or not original_units(outcome):
            raise ValueError("Incomplete original test output or different units")
    if sources(workspace, True, "abi") != baseline_ids or any(sha(app / n) != h for n, h in after.items()):
        raise ValueError("Upstream or separate scale-profile source changed")
    save(output / "result.json", {"pass": True, "fresh_guests": 3, "original_iterations": 500,
         "validation_iterations": 2000, "outcomes": outcomes, "model_calls": 0,
         "whole_live_ram_peak_bytes": None, "ranking_eligible": False})


def retained_profiles(root, plan):
    history = root / plan["history_campaign"]
    if sha(history / "campaign.json") != plan["history_campaign_sha256"] or sha(root / plan["history_audit"]) != plan["history_audit_sha256"]:
        raise ValueError("Frozen generation history or audit changed")
    campaign = json.loads((history / "campaign.json").read_text())
    variants = json.loads((root / plan["reference_registry"]).read_text())["variants"]
    grouped = {v["config_sha256"]: {**v, "aliases": []} for v in variants}
    for h in campaign["histories"]:
        for r in h["rounds"]:
            for phase, key in (("parent", "parent_build"), ("retained", "retained_build")):
                build = root / r[key]
                digest = sha(build / ".config")
                if digest not in grouped:
                    raise ValueError("History configuration not covered by frozen profiles")
                grouped[digest]["aliases"].append({"history": h["id"], "round": r["round"], "phase": phase,
                                                  "config_sha256": digest, "image_sha256": sha(build / "runtime-image")})
    if len(grouped) != 3 or any(not v["aliases"] for v in grouped.values()):
        raise ValueError("Incomplete retained-configuration coverage")
    for digest, value in grouped.items():
        if sha(root / value["build"] / ".config") != digest:
            raise ValueError("Representative configuration differs")
    return list(grouped.values())


def collect(plan_path, output, socket, host, workspace):
    from run_tenonos_energy import governor, host_state
    if ROOT != Path("/home/reviewer/esp32-pilot/audit-workspace") or output.exists():
        raise ValueError("Run on leon using a new persistent output folder")
    output.resolve().relative_to((ROOT / "artifacts/reports").resolve())
    plan = json.loads(plan_path.read_text())
    profiles = retained_profiles(ROOT, plan)
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host]
    state = host_state(ssh)
    if state["qemu_running"] or state["throttled"] != "throttled=0x0":
        raise ValueError("Pi is not ready for an independent validation run")
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output / "protocol.json")
    (output / "sources").mkdir()
    names = ("tenonos_scale_validation.py", "tenonos_kvm_reproduce.py", "import_iotos_subjects.py")
    for name in names:
        shutil.copyfile(ROOT / "tools" / name, output / "sources" / name)
    result = {"status": "incomplete", "registered_utc": utc(), "profiles": profiles, "completed": [], "model_calls": 0,
              "plan_sha256": sha(plan_path), "source_sha256": {n: sha(output / "sources" / n) for n in names},
              "host_initial": state, "prospective_before_generation": False}
    save(output / "campaign.json", result)
    try:
        governor(ssh, "performance")
        for value in profiles:
            folder = output / value["id"]
            folder.mkdir()
            shutil.copyfile(ROOT / value["build"] / ".config", folder / "input.config")
            before = host_state(ssh)
            if before["qemu_running"] or before["throttled"] != "throttled=0x0" or before["governor"] != "performance":
                raise ValueError("Pi envelope changed before scale validation")
            remote = "/dev/shm/iotos-tenon-v4-scale-" + output.name + "-" + value["id"]
            subprocess.run([*ssh, shlex.join(["mkdir", "-m", "700", remote])], check=True, timeout=20)
            subprocess.run([*ssh, shlex.join(["mkdir", remote + "/helpers"])], check=True, timeout=20)
            scp = ["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes"]
            subprocess.run([*scp, str(folder / "input.config"), host + ":" + remote + "/"], check=True, timeout=30)
            subprocess.run([*scp, *[str(output / "sources" / n) for n in names], host + ":" + remote + "/helpers/"],
                           check=True, timeout=30)
            argv = ["timeout", "--kill-after=10", "1850", "python3", remote + "/helpers/tenonos_scale_validation.py",
                    "on-pi", "--workspace", workspace, "--output", remote]
            with (folder / "remote.stdout").open("xb") as out, (folder / "remote.stderr").open("xb") as err:
                step = subprocess.run([*ssh, shlex.join(argv)], stdout=out, stderr=err, timeout=1880)
            excludes = ["--exclude=/build/build/"] if step.returncode == 0 else []
            subprocess.run(["rsync", "-a", *excludes, "-e", shlex.join(ssh[:-1]),
                            host + ":" + remote + "/", str(folder) + "/"], check=True, timeout=120)
            code = "from pathlib import Path;import hashlib,json;r=Path(" + repr(remote) + ");print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob('*') if p.is_file() and '__pycache__' not in p.parts" + (" and p.relative_to(r).parts[:2]!=('build','build')" if step.returncode == 0 else "") + "}))"
            manifest = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])], timeout=30))
            if any(sha(folder / n) != digest for n, digest in manifest.items()):
                raise ValueError("Returned scale-validation evidence differs")
            save(folder / "runtime-transfer-check.json", {"files": manifest, "all_equal": True,
                 "remote_returncode": step.returncode, "omitted_regenerable_subtrees":
                 (["build/build"] if step.returncode == 0 else []) + ["helpers/__pycache__"]})
            subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", remote])], check=True, timeout=20)
            after = host_state(ssh)
            if step.returncode or after["qemu_running"] or after["throttled"] != "throttled=0x0":
                raise ValueError("Scale profile failed; original evidence retained, no automatic retry")
            result["completed"].append({"id": value["id"], "config_sha256": value["config_sha256"],
                                        "host_before": before, "host_after": after, "passed": True})
            save(output / "campaign.json", result)
            print(json.dumps({"profile": value["id"], "fresh_guests": 3, "passed": True}), flush=True)
        result["status"] = "complete"
    except BaseException as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        try:
            governor(ssh, state["governor"])
            result["host_after_restore"] = host_state(ssh)
            result["governor_restored"] = result["host_after_restore"]["governor"] == state["governor"]
            if not result["governor_restored"]:
                result["status"] = "failed"
        except BaseException as error:
            result.update(status="failed", restoration_error=repr(error))
        result["ended_utc"] = utc()
        save(output / "campaign.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "on-pi"))
    parser.add_argument("--plan", type=Path, default=ROOT / "registry/tenonos_scale_validation_rpi4_v1.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", default="/home/pi/tenonos-benchmark-v1")
    parser.add_argument("--socket", default="/tmp/iotos-pi-energy.sock")
    parser.add_argument("--host", default="pi@192.168.31.76")
    args = parser.parse_args()
    if args.action == "on-pi":
        on_pi(Path(args.workspace), args.output)
    else:
        with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collect(args.plan, args.output.resolve(), args.socket, args.host, args.workspace)
