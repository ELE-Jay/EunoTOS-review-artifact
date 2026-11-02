#!/usr/bin/env python3
"""Build a locked ESP32 task with an external config; never generate or flash."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from import_iotos_subjects import config_text

BUILD_METADATA = {"CONFIG_TAINT", "CONFIG_TAINT_BLOBS"}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fragment_values(text, allowed):
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            match = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=([yn])", line)
            if not match or match[1] not in allowed:
                raise ValueError("Candidate may only set the declared scheduler/wait-queue choices")
        elif line.startswith("# CONFIG_"):
            match = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
            if not match or match[1] not in allowed:
                raise ValueError("Undeclared candidate configuration")
    values, duplicates = config_text(text)
    if duplicates:
        raise ValueError("Duplicate candidate configuration")
    return values


def configuration_changes(before, after, requested, execution):
    allowed = set(execution["zephyr_candidate_controls"] + execution["zephyr_derived_controls"])
    old, _ = config_text(before)
    new, _ = config_text(after)
    changes = {k: [old.get(k, "n"), new.get(k, "n")] for k in sorted(old.keys() | new.keys())
               if old.get(k, "n") != new.get(k, "n")}
    if set(changes) - allowed - BUILD_METADATA:
        raise ValueError("Resolved config changed the frozen profile: " + ", ".join(sorted(set(changes) - allowed)))
    if any(changes[k] != ["n", "y"] for k in set(changes) & BUILD_METADATA):
        raise ValueError("Unexpected HAL blob metadata change")
    return changes


def native_resolution(requested, config):
    resolved, _ = config_text(config)
    return {k: {"submitted": v, "resolved": resolved.get(k, "n")}
            for k, v in requested.items() if resolved.get(k, "n") != v}


def build(bundle, output, root, fragment=None):
    job = json.loads((bundle / "job.json").read_text())
    if job["schema"] != "iotos-esp32-candidate-build-v1" or job["execution"]["primary_target"] != "ESP32-WROOM-32":
        raise ValueError("Not an ESP32 task bundle")
    for name, expected in job["files"].items():
        path = (bundle / name).resolve()
        path.relative_to(bundle.resolve())
        if sha(path) != expected:
            raise ValueError("Frozen task changed: " + name)
    requested = fragment_values(fragment.read_text(), job["execution"]["zephyr_candidate_controls"]) if fragment else {}
    output.mkdir(parents=True, exist_ok=False)
    started, wall = datetime.now(timezone.utc).isoformat(), time.monotonic()
    report = {"schema": job["schema"], "target": "ESP32-WROOM-32", "case": job["case"],
        "job_sha256": sha(bundle / "job.json"), "protocol_sha256": job["protocol_sha256"],
        "reference_id": job["reference"]["id"], "status": "started", "started_utc": started,
        "external_fragment_supplied": fragment is not None, "generated_origin_verified": False,
        "runtime_measurements": 0, "ranking_eligible": False}

    def command(args, name, env):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)

    try:
        app = output / "app"
        shutil.copytree(bundle / "app", app)
        workspace = root / "zephyr-v3.7.0-work"
        upstream = Path.home() / "esp32-pilot/threadx-6.2.1_rel/utility/benchmarks/thread_metric"
        for path in (bundle / "original").glob("*.c"):
            if sha(upstream / path.name) != sha(path):
                raise ValueError("Original workload changed")
        for name in ("tm_api.h", "tm_porting_layer.h"):
            if sha(upstream / name) != sha(bundle / "original" / name):
                raise ValueError("Original test interface changed")
        toolchain = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf"
        env = dict(os.environ, ZEPHYR_BASE=str(workspace / "zephyr"), ZEPHYR_TOOLCHAIN_VARIANT="espressif",
            ESPRESSIF_TOOLCHAIN_PATH=str(toolchain), CPATH=str(workspace / "modules/hal/espressif/components/xtensa/esp32/include"),
            PATH=str(workspace / "pyenv/bin") + ":" + str(root / "bin") + ":" + os.environ["PATH"])
        cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
        directory = output / "build"
        args = [cmake, "-G", "Ninja", "-S", str(app), "-B", str(directory),
            "-DBOARD=esp32_devkitc_wroom/esp32/procpu", "-DTM_TEST=" + job["case"],
            "-DTM_IRQ_FROM_CPU2=" + ("ON" if job["case"].startswith("interrupt_") else "OFF"),
            "-DZEPHYR_MODULES=" + str(workspace / "modules/hal/espressif"),
            "-DCONFIG_SIZE_OPTIMIZATIONS=y", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
        if fragment:
            shutil.copyfile(fragment, output / "candidate.conf")
            args += ["-DEXTRA_CONF_FILE=" + str(output / "candidate.conf")]
            report["candidate_sha256"] = sha(output / "candidate.conf")
        command([str(toolchain / "bin/xtensa-esp32-elf-gcc"), "--version"], "compiler.txt", env)
        if "13.2.0" not in (output / "compiler.txt").read_text():
            raise ValueError("Wrong compiler")
        command(args, "configure.log", env)
        report["config_changes"] = configuration_changes((bundle / "reference.config").read_text(),
            (directory / "zephyr/.config").read_text(), requested, job["execution"])
        resolution = native_resolution(requested, (directory / "zephyr/.config").read_text())
        if resolution:
            report["native_resolution"] = resolution
            report["configuration_interpretation"] = "Native Kconfig resolves fragment choices; task requirements are checked against the actual resolved configuration, not against every intermediate assignment."
        if set(report["config_changes"]) & BUILD_METADATA:
            module = directory / "Kconfig/Kconfig.modules"
            if "select TAINT_BLOBS" not in module.read_text():
                raise ValueError("HAL blob metadata must come from module configuration")
            shutil.copyfile(module, output / "Kconfig.modules")
            report["metadata_boundary"] = "HAL blob taint markers differ from the historical config; this is not a byte-identical firmware or an automatic reuse of its measurements."
        if not fragment and set(report["config_changes"]) - BUILD_METADATA:
            raise ValueError("Control build must reproduce the original configuration")
        command([cmake, "--build", str(directory), "--parallel", "2"], "build.log", env)
        for source, name in ((directory / "zephyr/.config", "config"),
                             (directory / "zephyr/zephyr.elf", "application.elf"),
                             (directory / "zephyr/zephyr.bin", "application.bin"),
                             (directory / "compile_commands.json", "compile_commands.json")):
            shutil.copyfile(source, output / name)
        report.update(status="cross_build_pass", images={n: sha(output / n) for n in ("application.elf", "application.bin")},
            config_sha256=sha(output / "config"),
            boundary="Clean cross-build and resolved-config control only. New images still need source/ELF semantics, authentic generation provenance and independent real-board capture audits.")
    except Exception as exc:
        report.update(status="failed", error=str(exc))
        raise
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_s=time.monotonic()-wall)
        (output / "build-result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def audit_candidate(bundle, built, *, control=False):
    """Replay a benchmark-owned build; generation provenance is checked separately."""
    job = json.loads((bundle / "job.json").read_text())
    report = json.loads((built / "build-result.json").read_text())
    if report["job_sha256"] != sha(bundle / "job.json") or report["status"] != "cross_build_pass" or \
            (control and report["external_fragment_supplied"]) or report["generated_origin_verified"] or \
            report["runtime_measurements"] != 0 or report["ranking_eligible"]:
        raise ValueError("Control was incorrectly promoted to generated/runtime evidence")
    for name, expected in job["files"].items():
        if sha(bundle / name) != expected or (name.startswith("app/") and sha(built / name) != expected):
            raise ValueError("Original task/adapter changed")
    requested = {}
    if report["external_fragment_supplied"]:
        if sha(built / "candidate.conf") != report["candidate_sha256"]:
            raise ValueError("Candidate configuration changed")
        requested = fragment_values((built / "candidate.conf").read_text(),job["execution"]["zephyr_candidate_controls"])
    changes = configuration_changes((bundle / "reference.config").read_text(),
        (built / "config").read_text(), requested, job["execution"])
    if native_resolution(requested, (built / "config").read_text()) != report.get("native_resolution", {}):
        raise ValueError("Native configuration resolution record differs")
    if changes != report["config_changes"] or (control and set(changes) - BUILD_METADATA):
        raise ValueError("Configuration declaration differs")
    if changes and "select TAINT_BLOBS" not in (built / "Kconfig.modules").read_text():
        raise ValueError("No HAL metadata witness")
    if sha(built / "config") != report["config_sha256"] or any(sha(built / n) != v for n,v in report["images"].items()):
        raise ValueError("Config or image changed")
    elf = (built / "application.elf").read_bytes()
    if elf[:6] != b"\x7fELF\x01\x01" or int.from_bytes(elf[18:20], "little") != 94 or \
            b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in elf:
        raise ValueError("Not the declared 32-bit Xtensa/GCC13 image")
    rows = [r for r in json.loads((built / "compile_commands.json").read_text())
            if "/app/src/" in r["file"] and Path(r["file"]).name in ("main.c", "port.c", "test.c")]
    if len(rows) != 3 or {Path(r["file"]).name for r in rows} != {"main.c", "port.c", "test.c"}:
        raise ValueError("Incomplete original application compile evidence")
    for row in rows:
        args = shlex.split(row["command"])
        if "esp-13.2.0_20230928" not in args[0] or "-DTM_TEST_"+job["case"]+"=1" not in args or \
                [v for v in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)",v)][-1:] != ["-Os"]:
            raise ValueError("Original compile profile changed")
    return {"audit":"pass", "target":report["target"], "case":report["case"],
        "config_changes":changes, "source_bound":True, "new_runtime_measurements":0,
        "generated_origin_verified":False, "ranking_eligible":False, "images":report["images"]}


def audit_control(folder):
    """Replay the retained original-configuration control without a toolchain."""
    return audit_candidate(folder / "task", folder / "control-build-metadata-aligned", control=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--fragment", type=Path)
    args = parser.parse_args()
    if args.check:
        result = audit_control(args.check)
    elif args.bundle is None or args.output is None:
        parser.error("build requires --bundle and --output")
    else:
        result = build(args.bundle.resolve(), args.output.resolve(), args.root.resolve(), args.fragment)
    print(json.dumps(result, indent=2))
