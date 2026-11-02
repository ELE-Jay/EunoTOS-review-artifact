#!/usr/bin/env python3
"""Qualify additional native references before freezing expanded model tasks."""
import argparse
import contextlib
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from import_iotos_subjects import config_text
from run_tenonos_paper_tasks import evaluate_pi, prepare_runtime_helpers
from tenonos_kvm_reproduce import command, save, sha, utc
from tenonos_orchestrator import kconfig

ROOT = Path(__file__).resolve().parents[1]
PLAN = "registry/tenonos_task_expansion_feasibility_v1.json"


def reference_options(plan, profile):
    inherited = dict(plan["fixed_options"])
    if profile["application"] == "app-rtos-benchmark-abi":
        inherited.update(plan["rtos_options"])
    explicit = profile["options"]
    return {**{k: v for k, v in inherited.items() if k not in explicit}, **explicit}


def option_differences(options, resolved, symbols):
    differences = {}
    for name, expected in options.items():
        symbol = symbols.get(name)
        if symbol is None:
            raise ValueError("Unknown requested native symbol: " + name)
        actual = resolved.get("CONFIG_" + name, "n")
        # Native Kconfig may canonicalize hex numbers; compare their values.
        numeric = expected.startswith("0x") or expected.lstrip("-").isdigit()
        try:
            equal = int(actual, 0) == int(expected, 0) if numeric else actual == expected
        except ValueError:
            equal = False
        if not equal:
            differences[name] = {"required": expected, "resolved": actual}
    return differences


def native_reference(folder, workspace, profile, options):
    task = {"id": profile["id"], "application": profile["application"],
            "required_options": options, "protocol_id": "native-reference-feasibility-only"}
    candidate = folder / "candidate"
    candidate.mkdir()
    save(candidate / "task.json", task)
    fragment = candidate / "candidate.defconfig"
    fragment.write_text("".join("CONFIG_%s=%s\n" % pair for pair in options.items()))
    validation = folder / "native-check"
    validation.mkdir()
    parsed = kconfig(workspace, profile["application"], validation / "parsed-kconfig")
    step = command(validation, "configure", [
        "timeout", "--kill-after=5", "90", "make", "-C", workspace / "tenon-c11",
        "A=" + str(workspace / "apps" / profile["application"]),
        "L=" + str(workspace / "libs"), "O=" + str(validation / "build"),
        "C=" + str(validation / ".config"), "ARCH=arm64",
        "UK_DEFCONFIG=" + str(fragment), "defconfig"])
    if step["returncode"]:
        raise RuntimeError("Native configuration infrastructure failed; inspect retained logs")
    resolved, duplicates = config_text((validation / ".config").read_text())
    if duplicates:
        raise ValueError("Duplicate resolved native settings")
    differences = option_differences(options, resolved, parsed.syms)
    save(validation / "result.json", {"requested_differences": differences,
        "native_config_sha256": sha(validation / ".config"), "requested": options})
    save(candidate / "generation.json", {"subject": "Public Tenon feasible reference",
        "origin": "hand-specified-reference-not-model-output", "generator_invoked": False,
        "valid_candidate": not differences, "candidate_sha256": sha(fragment),
        "options": options, "generation_wall_s": 0})
    return not differences


def qualify(root, output, socket, host, pi_workspace, plan_path=None):
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace"):
        raise ValueError("Build, execute and retain experimental evidence on leon")
    output.relative_to(root / "artifacts/reports")
    if output.exists():
        raise ValueError("Existing feasibility batch must be inspected, not overwritten")
    plan_path = plan_path or root / PLAN
    plan_path.resolve().relative_to(root)
    plan = json.loads(plan_path.read_text())
    if len({p["id"] for p in plan["profiles"]}) != len(plan["profiles"]):
        raise ValueError("Duplicate reference IDs")
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host]
    output.mkdir(parents=True)
    (output / "sources").mkdir()
    names = [Path(__file__).name, "tenonos_kvm_reproduce.py", "tenonos_orchestrator.py",
             "run_tenonos_paper_tasks.py", "import_iotos_subjects.py",
             "tenonos_runtime_oracle.py", "tenonos_runtime_oracle.c", "tenonos_memory_observer.py"]
    for name in names:
        shutil.copyfile(root / "tools" / name, output / "sources" / name)
    shutil.copyfile(plan_path, output / "protocol.json")
    registration = {"registered_utc": utc(), "protocol_sha256": sha(plan_path),
        "source_sha256": {n: sha(output / "sources" / n) for n in names},
        "model_calls": 0, "formal_model_trials": 0, "reference_count": len(plan["profiles"])}
    save(output / "registration.json", registration)
    helpers = None
    results = {"status": "running", "references": [], "model_calls": 0,
               "formal_model_trials": 0, "new_ram_or_energy_measurements": False}
    workspace = Path("/home/reviewer/esp32-pilot/tenonos-reproduction-v1")
    try:
        helpers, identity = prepare_runtime_helpers(ssh, host, socket, str(pi_workspace))
        save(output / "runtime-source-identity.json", identity)
        for profile in plan["profiles"]:
            if sha(plan_path) != registration["protocol_sha256"] or any(
                    sha(root / "tools" / n) != h for n, h in registration["source_sha256"].items()):
                raise ValueError("Registered source or protocol changed during collection")
            folder = output / profile["id"]
            folder.mkdir()
            record = {"id": profile["id"], "application": profile["application"],
                      "native_valid": False, "native_runtime_pass": False,
                      "behavior_verified": False, "feasible": False}
            results["references"].append(record)
            before = time.monotonic()
            with (folder / "native.log").open("x") as log, contextlib.redirect_stdout(log):
                record["native_valid"] = native_reference(folder, workspace, profile, reference_options(plan, profile))
            if record["native_valid"]:
                remote = "/dev/shm/iotos-tenon-v4-" + output.name + "-" + profile["id"]
                with (folder / "runtime.log").open("x") as log, contextlib.redirect_stdout(log):
                    value = evaluate_pi(folder, ssh, host, socket, str(pi_workspace), remote,
                                        lambda: 1800 - (time.monotonic() - before), helpers)
                if value.get("failure"):
                    record["runtime_failure"] = value["failure"]
                record["native_runtime_pass"] = all(value[k] for k in
                    ("built", "booted", "functional", "constraints", "all_requested_options_preserved"))
                if profile["application"] == "app-helloworld":
                    record["behavior_verified"] = record["native_runtime_pass"]
                    record["feasible"] = record["native_runtime_pass"]
            record["elapsed_s"] = time.monotonic() - before
            save(output / "result.json", results)
            print(profile["id"], "native", record["native_valid"], "runtime", record["native_runtime_pass"], flush=True)
        rtos = [r for r in results["references"] if r["application"] == "app-rtos-benchmark-abi" and r["native_runtime_pass"]]
        if rtos:
            variants = [{"id": r["id"], "build": str((output / r["id"] / "evaluation/build").relative_to(root)),
                         "config_sha256": sha(output / r["id"] / "evaluation/build/.config"),
                         "image_sha256": sha(output / r["id"] / "evaluation/build/runtime-image")} for r in rtos]
            inventory = output / "behavior-references.json"
            save(inventory, {"variants": variants})
            behavior = json.loads((root / plan["rtos_behavior_judge"]).read_text())
            behavior.update(id=plan["id"] + "-behavior", profiles=[v["id"] for v in variants],
                            reference_registry=str(inventory.relative_to(root)), reference_registry_sha256=sha(inventory))
            save(output / "behavior-protocol.json", behavior)
            from tenonos_runtime_oracle import collect
            collect(output / "behavior", socket, host, pi_workspace, output / "behavior-protocol.json")
            qualified = json.loads((output / "behavior/campaign.json").read_text())
            for r in rtos:
                match = next(v for v in qualified["completed"] if v["profile"] == r["id"])
                r["behavior_verified"] = match["admitted"]
                r["feasible"] = r["native_runtime_pass"] and r["behavior_verified"]
        results.update(status="complete", finished_utc=utc(),
                       feasible_reference_count=sum(r["feasible"] for r in results["references"]))
    except BaseException as error:
        results.update(status="stopped", error=repr(error), finished_utc=utc())
        raise
    finally:
        save(output / "result.json", results)
        if helpers:
            subprocess.run([*ssh, "rm -rf -- " + helpers], check=True, timeout=20)
    return results


def audit(output):
    """Replay stage admission from retained native outputs, not reported flags."""
    from tenonos_kvm_reproduce import hello_result, original_results
    from tenonos_runtime_oracle import evaluate as behavior
    registration = json.loads((output / "registration.json").read_text())
    if sha(output / "protocol.json") != registration["protocol_sha256"]:
        raise ValueError("Frozen protocol differs")
    for name, digest in registration["source_sha256"].items():
        if sha(output / "sources" / name) != digest:
            raise ValueError("Frozen helper differs")
    plan = json.loads((output / "protocol.json").read_text())
    reported = json.loads((output / "result.json").read_text())
    if reported["status"] != "complete" or len(reported["references"]) != len(plan["profiles"]):
        raise ValueError("Incomplete feasibility campaign")
    rows, original_guests, observer_guests = [], 0, 0
    for profile, row in zip(plan["profiles"], reported["references"]):
        if row["id"] != profile["id"]:
            raise ValueError("Reference order differs")
        folder = output / row["id"]
        options = reference_options(plan, profile)
        task = json.loads((folder / "candidate/task.json").read_text())
        resolved, duplicates = config_text((folder / "native-check/.config").read_text())
        if duplicates or task["required_options"] != options:
            raise ValueError("Native input differs")
        check = json.loads((folder / "native-check/result.json").read_text())
        if check["native_config_sha256"] != sha(folder / "native-check/.config"):
            raise ValueError("Native configuration differs")
        different = {n: {"required": v, "resolved": resolved.get("CONFIG_" + n, "n")}
                     for n, v in options.items() if resolved.get("CONFIG_" + n, "n") != v}
        if different != check["requested_differences"] or row["native_valid"] != (not different):
            raise ValueError("Native admission differs")
        passed, witnessed = False, False
        if row["native_valid"]:
            transfer = json.loads((folder / "runtime-transfer-check.json").read_text())
            for n, digest in transfer["files"].items():
                name = transfer["file_overrides"].get(n, n)
                path = (folder / name).resolve()
                path.relative_to(folder.resolve())
                if sha(path) != digest:
                    raise ValueError("Transferred runtime evidence differs")
            build = folder / "evaluation/build"
            if (build / "build-result.json").exists():
                proof = json.loads((build / "build-result.json").read_text())
                generation = json.loads((folder / "candidate/generation.json").read_text())
                if proof["image_sha256"] != sha(build / "runtime-image") or \
                        proof["config_sha256"] != sha(build / ".config") or \
                        proof["input_defconfig_sha256"] != sha(folder / "candidate/candidate.defconfig") or \
                        generation["candidate_sha256"] != proof["input_defconfig_sha256"]:
                    raise ValueError("Reference build identity differs")
                cfg, duplicate = config_text((build / ".config").read_text())
                gates = [not duplicate and all(cfg.get("CONFIG_" + n, "n") == v for n, v in options.items())]
                boots = folder / "evaluation/boots"
                saved = json.loads((boots / "boot-result.json").read_text())
                gates.append(saved["image_sha256"] == proof["image_sha256"] and len(saved["runs"]) == 3)
                for run in saved["runs"]:
                    step = json.loads((boots / ("boot%d.json" % run["index"])).read_text())
                    text = (boots / ("boot%d.stdout" % run["index"])).read_bytes()
                    error = (boots / ("boot%d.stderr" % run["index"])).read_bytes()
                    is_rtos = profile["application"] == "app-rtos-benchmark-abi"
                    gate = (original_results if is_rtos else hello_result)(text, error, step["returncode"])
                    gates.append(gate["functional_probe_pass"])
                    if not is_rtos:
                        observed = any(line.startswith(b"Arguments:") for line in text.splitlines())
                        gates.append(observed == (options["APPHELLOWORLD_PRINTARGS"] == "y"))
                    original_guests += 1
                passed = all(gates)
            if passed and profile["application"] == "app-rtos-benchmark-abi":
                observer = output / "behavior" / profile["id"]
                transfer = json.loads((observer / "runtime-transfer-check.json").read_text())
                for n, digest in transfer["files"].items():
                    if sha(observer / n) != digest:
                        raise ValueError("Behavioral evidence differs")
                observed_config, _ = config_text((observer / "build/.config").read_text())
                native_config, _ = config_text((folder / "evaluation/build/.config").read_text())
                changes = {n for n in observed_config.keys() | native_config.keys()
                           if observed_config.get(n) != native_config.get(n)}
                if changes != {"CONFIG_UK_APP"}:
                    raise ValueError("Behavioral observer changed configuration controls")
                facts = []
                for index in (1, 2, 3):
                    boots = observer / "boots"
                    stdout = (boots / ("boot%d.stdout" % index)).read_bytes()
                    stderr = (boots / ("boot%d.stderr" % index)).read_bytes()
                    step = json.loads((boots / ("boot%d.json" % index)).read_text())
                    facts.append(original_results(stdout, stderr, step["returncode"])["functional_probe_pass"] and
                                 behavior(stdout.decode())["admitted"])
                    observer_guests += 1
                witnessed = all(facts)
            elif passed:
                witnessed = True
        feasible = passed and witnessed
        if (passed, witnessed, feasible) != (row["native_runtime_pass"], row["behavior_verified"], row["feasible"]):
            raise ValueError("Replayed reference admission differs")
        rows.append({"id": row["id"], "feasible": feasible})
    return {"audit": "pass", "references": rows, "feasible_reference_count": sum(r["feasible"] for r in rows),
            "original_guest_captures": original_guests, "behavior_guest_captures": observer_guests,
            "model_calls": 0, "source_sha256": sha(Path(__file__))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--socket", default="/tmp/iotos-pi-energy.sock")
    parser.add_argument("--host", default="pi@192.168.31.76")
    parser.add_argument("--pi-workspace", type=Path, default=Path("/home/pi/tenonos-benchmark-v1"))
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run and retain evidence on leon")
    if args.audit_only:
        result = audit(args.output.resolve())
        save(args.output.resolve() / "audit.json", result)
        print(json.dumps(result, indent=2))
        sys.exit(0)
    with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        qualify(ROOT, args.output.resolve(), args.socket, args.host, args.pi_workspace,
                args.plan.resolve() if args.plan else None)
