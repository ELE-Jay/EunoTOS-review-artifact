#!/usr/bin/env python3
"""Supplement C2 with unchanged Zephyr semaphore correctness tests, not scores."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
from urllib.request import urlopen

from import_iotos_subjects import config_text
from run_esp32_followup import Board

SUITE = "tests/kernel/semaphore/semaphore"
FILES = [SUITE + "/" + n for n in ("CMakeLists.txt", "prj.conf", "testcase.yaml", "src/main.c")]
FILES += ["kernel/sem.c", "kernel/sched.c", "kernel/include/wait_q.h", "kernel/include/priority_q.h"]
MAIN_SHA = "f96177bc13b364850e6b5e59459d5aba5b2dfb843bd49888d172c0a9223554db"
MAC = "34:98:7a:a2:85:28"
PROFILES = {"baseline": {"CONFIG_SCHED_DUMB": "y", "CONFIG_WAITQ_DUMB": "y"},
            "C2": {"CONFIG_SCHED_MULTIQ": "y", "CONFIG_WAITQ_SCALABLE": "y"}}
COMMON = {"CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC": "240000000", "CONFIG_SYS_CLOCK_TICKS_PER_SEC": "100",
          "CONFIG_TICKLESS_KERNEL": "n", "CONFIG_TIMESLICING": "n", "CONFIG_SMP": "n",
          "CONFIG_TEST_USERSPACE": "n", "CONFIG_USERSPACE": "n", "CONFIG_SIZE_OPTIMIZATIONS": "y"}
POLICIES = {"CONFIG_SCHED_DUMB", "CONFIG_SCHED_SCALABLE", "CONFIG_SCHED_MULTIQ",
            "CONFIG_WAITQ_DUMB", "CONFIG_WAITQ_SCALABLE", "CONFIG_RBTREE"}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def expected_tests(source):
    return re.findall(r"^ZTEST(?:_USER)?\((?:semaphore|semaphore_1cpu),\s*(test_\w+)\)", source, re.M)


def prepare(output):
    output.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        path = output / "upstream" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with urlopen("https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/" + name, timeout=60) as response:
            path.write_bytes(response.read())
    if sha(output / "upstream" / SUITE / "src/main.c") != MAIN_SHA:
        raise ValueError("Original semaphore suite differs")
    tests = expected_tests((output / "upstream" / SUITE / "src/main.c").read_text())
    if len(tests) != 24 or len(set(tests)) != 24:
        raise ValueError("Unexpected original kernel-mode test set")
    for profile, choices in PROFILES.items():
        (output / (profile + ".conf")).write_text("".join(k + "=" + v + "\n" for k, v in {**COMMON, **choices}.items()))
    save(output / "protocol.json", {"schema": "esp32-waitq-oracle-v1", "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "source": "https://github.com/zephyrproject-rtos/zephyr/tree/v3.7.0/" + SUITE,
        "release": "v3.7.0", "board_mac": MAC, "common": COMMON, "profiles": PROFILES,
        "order": list(PROFILES), "resets_per_profile": 5, "capture_timeout_s": 120,
        "required_tests": tests, "excluded": "Five CONFIG_USERSPACE null-pointer cases are not compiled; kernel-mode only.",
        "qualification": "Supplementary oracle on separate test images, not the historical C2 task image or a generated attempt.",
        "ranking_eligible": False, "generated_task_runs": 0,
        "files": {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}})


def protocol(prepared):
    data = json.loads((prepared / "protocol.json").read_text())
    if data["schema"] != "esp32-waitq-oracle-v1" or data["profiles"] != PROFILES or data["common"] != COMMON or \
            data["order"] != list(PROFILES) or data["resets_per_profile"] != 5 or data["capture_timeout_s"] != 120 or \
            data["board_mac"] != MAC or data["ranking_eligible"] or data["generated_task_runs"] != 0:
        raise ValueError("Supplementary oracle protocol changed")
    for name, value in data["files"].items():
        path = (prepared / name).resolve()
        path.relative_to(prepared.resolve())
        if sha(path) != value:
            raise ValueError("Prepared source/configuration changed: " + name)
    main = prepared / "upstream" / SUITE / "src/main.c"
    if sha(main) != MAIN_SHA or data["required_tests"] != expected_tests(main.read_text()) or len(data["required_tests"]) != 24:
        raise ValueError("Required original tests changed")
    return data


def build(prepared, output, root):
    protocol(prepared)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(prepared, output / "prepared")
    workspace = root / "zephyr-v3.7.0-work"
    for name in FILES:
        if sha(workspace / "zephyr" / name) != sha(prepared / "upstream" / name):
            raise ValueError("Installed Zephyr source differs: " + name)
    toolchain = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf"
    env = dict(os.environ, ZEPHYR_BASE=str(workspace / "zephyr"), ZEPHYR_TOOLCHAIN_VARIANT="espressif",
               ESPRESSIF_TOOLCHAIN_PATH=str(toolchain), CPATH=str(workspace / "modules/hal/espressif/components/xtensa/esp32/include"),
               PATH=str(workspace / "pyenv/bin") + ":" + str(root / "bin") + ":" + os.environ["PATH"])
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    for profile in PROFILES:
        folder = output / profile
        folder.mkdir()
        working = output.parent / (output.name + "-objects-" + profile)
        if working.exists():
            raise ValueError("Refusing to reuse a build directory")
        commands = [([str(toolchain / "bin/xtensa-esp32-elf-gcc"), "--version"], "compiler.txt"),
            ([cmake, "-G", "Ninja", "-S", str(prepared / "upstream" / SUITE), "-B", str(working),
              "-DBOARD=esp32_devkitc_wroom/esp32/procpu", "-DZEPHYR_MODULES=" + str(workspace / "modules/hal/espressif"),
              "-DEXTRA_CONF_FILE=" + str(prepared / (profile + ".conf")), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log"),
            ([cmake, "--build", str(working), "--parallel", "2"], "build.log")]
        for args, log in commands:
            with (folder / log).open("x") as stream:
                subprocess.run(args, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=1200)
        for source, name in (("zephyr/.config", "config"), ("zephyr/zephyr.elf", "application.elf"),
                             ("zephyr/zephyr.bin", "application.bin"), ("compile_commands.json", "compile_commands.json")):
            shutil.copyfile(working / source, folder / name)
        print("BUILT", profile, flush=True)
    save(output / "build-audit.json", audit_build(output))


def audit_build(output):
    data = protocol(output / "prepared")
    configs, images = {}, {}
    for profile, choices in PROFILES.items():
        folder = output / profile
        config, duplicates = config_text((folder / "config").read_text())
        required = {**COMMON, **choices, "CONFIG_MP_MAX_NUM_CPUS": "1", "CONFIG_KERNEL_COHERENCE": "n"}
        if duplicates or any(config.get(k, "n") != v for k, v in required.items()):
            raise ValueError("Resolved common/policy configuration differs: " + profile)
        if any(config.get(k, "n") == "y" for k in POLICIES - choices.keys() - {"CONFIG_RBTREE"}):
            raise ValueError("Additional scheduler/wait-queue choice enabled")
        elf = (folder / "application.elf").read_bytes()
        if elf[:6] != b"\x7fELF\x01\x01" or int.from_bytes(elf[18:20], "little") != 94 or \
                b"GCC: (crosstool-NG esp-13.2.0_20230928) 13.2.0" not in elf:
            raise ValueError("Wrong target/compiler")
        rows = json.loads((folder / "compile_commands.json").read_text())
        for suffix in (SUITE + "/src/main.c", "kernel/sem.c", "kernel/sched.c"):
            matches = [r for r in rows if r["file"].endswith("/" + suffix)]
            if len(matches) != 1:
                raise ValueError("Missing original source compile record: " + suffix)
            args = shlex.split(matches[0]["command"])
            if "esp-13.2.0_20230928" not in args[0] or [v for v in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", v)][-1:] != ["-Os"]:
                raise ValueError("Wrong compile optimization/profile")
        configs[profile] = config
        images[profile] = {n: sha(folder / n) for n in ("config", "application.elf", "application.bin")}
    changes = {k: [configs["baseline"].get(k, "n"), configs["C2"].get(k, "n")]
               for k in configs["baseline"].keys() | configs["C2"].keys()
               if configs["baseline"].get(k, "n") != configs["C2"].get(k, "n")}
    if set(changes) - POLICIES:
        raise ValueError("Undeclared inter-profile differences: " + str(changes))
    return {"audit": "pass", "protocol_sha256": sha(output / "prepared/protocol.json"), "config_changes": changes,
            "images": images, "required_tests": data["required_tests"], "ranking_eligible": False}


def capture_result(rows, tests):
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    resets = [r for r in rows if r["line"].startswith("rst:0x")]
    if len(resets) != 1 or resets[0]["elapsed_s"] > 2 or lines.count("PROJECT EXECUTION SUCCESSFUL") != 1:
        raise ValueError("Independent reset/completion missing")
    starts = re.findall(r"^START - (test_\w+)$", "\n".join(lines), re.M)
    outcomes = re.findall(r"^(PASS|FAIL|SKIP|BLOCK) - (test_\w+)\b", "\n".join(lines), re.M)
    if sorted(starts) != sorted(tests) or sorted(outcomes) != sorted(("PASS", n) for n in tests):
        raise ValueError("Original test cases missing, repeated, skipped or failed")
    if any(re.search(r"PROJECT EXECUTION FAILED|TESTSUITE .* failed|Guru Meditation|Brownout|watchdog|ZEPHYR FATAL", line, re.I) for line in lines):
        raise ValueError("Unexpected runtime failure")
    return {"passed": len(tests), "failed": 0, "skipped": 0, "tests": sorted(tests)}


def collect(prepared, output, root, port):
    proof = audit_build(prepared)
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        shutil.copytree(prepared, output / "build")
        for name in ("esp32_waitq_oracle.py", "run_esp32_followup.py", "capture_esp32_uart.py"):
            shutil.copyfile(Path(__file__).parent / name, output / name)
        campaign = {"schema": "esp32-waitq-oracle-v1", "status": "incomplete", "board_mac": MAC,
            "started_utc": datetime.now(timezone.utc).isoformat(), "original_flash_restored": False,
            "old_cohort_modified": False, "energy_measured": False, "external_independent_replication": False,
            "generated_task_runs": 0, "ranking_eligible": False}
        board = Board(root, output, MAC, port)
        def interrupted(signum, frame):
            raise InterruptedError("Collection interrupted; restoring original Flash")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        try:
            board.backup()
            try:
                signal.alarm(1800)
                for profile in PROFILES:
                    captures = output / profile
                    captures.mkdir()
                    pairs = board.flash(captures, output / "build" / profile)
                    for i in range(1, 6):
                        board.capture(captures, i, 120, "PROJECT EXECUTION SUCCESSFUL",
                                      capture_script=Path(__file__).parent / "capture_esp32_uart.py")
                        board.verify(pairs, captures / ("verify-run%d.log" % i))
                        rows = [json.loads(line) for line in (captures / ("reset%d.jsonl" % i)).read_text().splitlines()]
                        save(captures / ("result%d.json" % i), capture_result(rows, proof["required_tests"]))
                        print("PASS", profile, i, "24 original cases", flush=True)
                    board.verify(pairs, captures / "verify-after.log")
                campaign["status"] = "collection_complete_audit_pending"
            finally:
                signal.alarm(0)
                board.restore()
                campaign["original_flash_restored"] = True
        except Exception as exc:
            campaign["error"] = str(exc)
            raise
        finally:
            campaign["completed_utc"] = datetime.now(timezone.utc).isoformat()
            campaign["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*")
                                  if p.is_file() and p.name != "campaign.json"}
            save(output / "campaign.json", campaign)


def audit(output):
    from audit_esp32_followup import envelope, independent_captures, verified
    campaign = envelope(output)
    if campaign["schema"] != "esp32-waitq-oracle-v1" or campaign["board_mac"] != MAC or \
            campaign["generated_task_runs"] != 0 or campaign["ranking_eligible"]:
        raise ValueError("Oracle qualification differs")
    proof = audit_build(output / "build")
    if proof != json.loads((output / "build/build-audit.json").read_text()):
        raise ValueError("Build audit differs")
    results, times = {}, []
    for profile in PROFILES:
        folder = output / profile
        verified(folder, output / "build" / profile, MAC)
        captures = independent_captures(folder, range(1, 6))
        results[profile] = []
        for i, rows in enumerate(captures, 1):
            verified(folder, output / "build" / profile, MAC, logs=("verify-run%d.log" % i,))
            result = capture_result(rows, proof["required_tests"])
            if result != json.loads((folder / ("result%d.json" % i)).read_text()):
                raise ValueError("Original test outcome replay differs")
            results[profile].append(result)
            times.append(tuple(datetime.fromisoformat(rows[n]["utc"]) for n in (0, -1)))
    if any(a[0] >= a[1] for a in times) or any(a[1] >= b[0] for a, b in zip(times, times[1:])):
        raise ValueError("Captures overlap or violate the frozen profile order")
    return {"schema": campaign["schema"], "audit": "pass", "build": proof, "results": results,
        "independent_resets": 10, "original_cases_per_reset": 24, "passed_case_instances": 240,
        "original_flash_restored": True, "generated_task_runs": 0, "ranking_eligible": False,
        "whole_ram_peak_measured": False, "energy_measured": False,
        "boundary": "Kernel-mode functional oracle on separate test images. No generated OS result, timing score or retroactive task-image admission."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "build", "collect", "audit"))
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.output.resolve())
    elif args.command in ("build", "collect"):
        if args.prepared is None:
            parser.error("--prepared is required")
        globals()[args.command](args.prepared.resolve(), args.output.resolve(), args.root.resolve(), **({"port": args.port} if args.command == "collect" else {}))
    else:
        result = audit(args.output.resolve())
        save(args.output / "audit.json", result)
        print(json.dumps(result, indent=2))
