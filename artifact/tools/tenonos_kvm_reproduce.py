#!/usr/bin/env python3
"""Reproduce pinned upstream Tenon examples; never generate OS configurations."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

PINS = {
    "tenon": "756aa1ca78a3d4c21b99580482aeead4041b0ab1",
    "board-support-package": "757734df33e8fdf5584680dcc0c19c39ae25ad48",
    "apps/app-helloworld": "1add85d53193c5cfc8d9285cbd6905a85ffcc309",
}
BENCHMARK_PINS = {"apps/app-rtos-benchmark": "fc52f0965e600a3eef75490590210db69180013c",
                  "apps/app-rtos-benchmark-current": "0b71b8e722acfab4733eb99b07b67fbe8472c31d",
                  "libs/lib-tlsf": "dddc46c14a31c0e9dd1b9ba5a19fbb1e384370d3"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def command(folder, name, argv):
    receipt = folder / (name + ".json")
    if receipt.exists():
        raise ValueError("Refusing to overwrite a recorded step: " + name)
    record = {"argv": [str(x) for x in argv], "started_utc": utc(), "state": "started",
              "recorder_sha256": sha(Path(__file__))}
    save(receipt, record)
    before = time.monotonic()
    with (folder / (name + ".stdout")).open("xb") as out, (folder / (name + ".stderr")).open("xb") as err:
        result = subprocess.run(record["argv"], stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    record.update(state="finished", returncode=result.returncode, finished_utc=utc(),
                  elapsed_seconds=time.monotonic() - before,
                  stdout_sha256=sha(folder / (name + ".stdout")),
                  stderr_sha256=sha(folder / (name + ".stderr")))
    save(receipt, record)
    print(name, result.returncode, flush=True)
    return record


def timer_compatibility(original, patched):
    label = b"\nupdate_next_tick:\n"
    if original.count(label) != 1 or patched != original.replace(label, b"\nupdate_next_tick:;\n"):
        raise ValueError("Unexpected timer compatibility patch")
    return {"path": "lib/tntimer/tntimer.c", "original_sha256": hashlib.sha256(original).hexdigest(),
            "patched_sha256": hashlib.sha256(patched).hexdigest(),
            "change": "one empty statement after the label; periodic/tickless selection unchanged"}


def sources(workspace, c11_timer_fix=False, benchmark=False):
    result = {}
    for relative, expected in {**PINS, **(BENCHMARK_PINS if benchmark else {})}.items():
        repo = workspace / relative
        actual = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"])
        if actual != expected or dirty:
            raise ValueError("Source identity or tracked worktree differs: " + relative)
        result[relative] = actual
    if c11_timer_fix:
        repo = workspace / "tenon-c11"
        actual = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"])
        if actual != PINS["tenon"] or dirty != b" M lib/tntimer/tntimer.c\n":
            raise ValueError("Unexpected patched kernel identity or tracked changes")
        original = subprocess.check_output(["git", "-C", str(repo), "show", "HEAD:lib/tntimer/tntimer.c"])
        result["kernel_patch"] = timer_compatibility(original, (repo / "lib/tntimer/tntimer.c").read_bytes())
    if benchmark == "abi":
        repo = workspace / "apps/app-rtos-benchmark-abi"
        patches = {"adapter/os/tenonos/rst_isr.c": "738792173125d862712cf17d40640a3f1c3488a761d2ac321cfe537982d1a707",
                   "adapter/os/tenonos/rst_task.c": "71c41a94f0ccdf644b0afb0f266afe072e3048df42816bf2a8893dcece304bed"}
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"])
        expected_dirty = "".join(" M " + path + "\n" for path in patches).encode()
        if head != BENCHMARK_PINS["apps/app-rtos-benchmark-current"] or dirty != expected_dirty or \
                any(sha(repo / path) != digest for path, digest in patches.items()):
            raise ValueError("Unexpected RTOS adapter compatibility changes")
        result["rtos_adapter_patch"] = {"commit": head, "files": patches,
            "change": "Typed IRQ callback and registration status; save full extended task context and reject failed allocations; original test bodies unchanged"}
    return result


def hello_result(stdout, stderr, returncode):
    text = stdout.decode("utf-8", errors="replace")
    error = bool(re.search(r"panic|unhandled exception|assertion.*fail|could not access kvm|failed to initialize kvm", 
                           text + stderr.decode("utf-8", errors="replace"), re.I))
    observed = "powered by tenonos" in text.casefold() and \
               len(re.findall(r"(?m)^Hello world!\r?$", text)) == 1
    return {"application_output_observed": observed, "error_marker": error,
            "clean_guest_exit": returncode == 0,
            "functional_probe_pass": observed and not error and returncode == 0}


def guest_memory(config):
    values = re.findall(r"^CONFIG_VIRTUALIZE_PLAT_MEM_SIZE=(0x[0-9a-fA-F]+|[0-9]+)$", config, re.M)
    if len(values) != 1:
        raise ValueError("Guest memory is not declared by the compiled page-table configuration")
    memory = int(values[0], 0)
    if not 32 * 1024**2 <= memory <= 2 * 1024**3 or memory % 1024**2:
        raise ValueError("Guest memory cannot be safely instantiated on this host")
    return memory


def original_results(stdout, stderr, returncode):
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", stdout.decode("utf-8", errors="replace"))
    headings = ["RST: task switch benchmark", "RST: 50 task switch benchmark", "RST: task preempt benchmark",
                "RST: semaphore shuffle benchmark", "RST: interrupt latency benchmark",
                "RST: timer deviation under interrupt interference"]
    expected = {"average_task_switch_time, in cpu cycles": 1, "average_multi_task_switch_time, in cpu cycles": 1,
                "average_task_preempt_time, in cpu cycles": 1, "average_semaphore_shuffle_time, in cpu cycles": 1,
                "interrupt_latency_time, in cpu cycles": 1,
                "timer_deviation_under_interrupt_interference, in count of generic timer": 1}
    values = {key: re.findall(re.escape("R-Rhealstone: " + key) + r" - (-?[0-9]+) (cycle|count)", text)
              for key in expected}
    counts = {key: len(items) for key, items in values.items()}
    error = bool(re.search(r"panic|unhandled exception|assertion.*fail|\[E/RST\]",
                          text + stderr.decode("utf-8", errors="replace"), re.I))
    complete = counts == expected and all(text.count(h) == 1 for h in headings) and returncode == 0 and not error
    return {"format_profile": "app-rtos-benchmark-0b71b8e", "original_result_counts": counts,
            "original_printed_values": {key: [{"value": int(v), "unit": u} for v, u in items]
                                        for key, items in values.items()}, "original_output_complete": complete,
            "clean_guest_exit": returncode == 0, "error_marker": error,
            "functional_probe_pass": complete, "runtime_semantic_admission": False,
            "boundary": "Output completeness only; counter fidelity, actual task/IRQ semantics and correctness require separate audit."}


def probe(workspace, output):
    output.mkdir(parents=True, exist_ok=False)
    commands = {"model": ["cat", "/proc/device-tree/model"], "kernel": ["uname", "-a"],
        "os": ["cat", "/etc/os-release"], "architecture": ["dpkg", "--print-architecture"],
        "cpu": ["lscpu", "-J"], "memory": ["free", "-b"], "disk": ["df", "-B1", str(workspace)],
        "kvm": ["ls", "-l", "/dev/kvm"], "identity": ["id"],
        "qemu": ["qemu-system-aarch64", "--version"],
        "packages": ["dpkg-query", "-W", "git", "make", "gcc", "clang", "bison", "flex",
                     "libncurses-dev", "libelf-dev", "qemu-system-arm", "jq", "ca-certificates"]}
    outcomes = {name: command(output, name, argv)["returncode"] for name, argv in commands.items()}
    save(output / "probe-result.json", {"source_commits": sources(workspace), "returncodes": outcomes,
        "generator_invoked": False, "ranking_eligible": False, "probe_completed_utc": utc()})


def build(workspace, output, defconfig=None, cross_compile="", compiler="gcc", c11_timer_fix=False,
          application="app-helloworld"):
    benchmark = "abi" if application == "app-rtos-benchmark-abi" else application.startswith("app-rtos-benchmark")
    source_ids = sources(workspace, c11_timer_fix, benchmark)
    defconfig = defconfig or workspace / "board-support-package/kvm/defconfig"
    output.mkdir(parents=True, exist_ok=False)
    (output / "input.defconfig").write_bytes(defconfig.read_bytes())
    make = ["make", "-C", workspace / ("tenon-c11" if c11_timer_fix else "tenon"),
            "A=" + str(workspace / "apps" / application),
            "O=" + str(output / "build"), "C=" + str(output / ".config"),
            "CROSS_COMPILE=" + cross_compile, "COMPILER=" + compiler]
    if benchmark:
        make.append("L=" + str(workspace / "libs"))
    version = command(output, "compiler", [cross_compile + compiler, "--version"])
    if version["returncode"]:
        raise RuntimeError("Requested compiler unavailable")
    configure = command(output, "configure", [*make,
        "UK_DEFCONFIG=" + str(defconfig), "defconfig"])
    if configure["returncode"]:
        raise RuntimeError("Original KVM defconfig failed; see captured logs")
    compiled = command(output, "build", ["timeout", "--kill-after=10", "900", *make, "-j2"])
    if compiled["returncode"]:
        raise RuntimeError("Build failed; see captured logs")
    images = list((output / "build").glob("*_qemu-arm64"))
    if len(images) != 1:
        raise ValueError("Expected exactly one original ARM64 QEMU image")
    shutil.copyfile(images[0], output / "runtime-image")
    result = {"source_commits": source_ids,
              "source_worktrees_unchanged": sources(workspace, c11_timer_fix, benchmark) == source_ids,
              "upstream_sources_unmodified": not c11_timer_fix and benchmark != "abi", "c11_timer_fix": c11_timer_fix,
              "application": application,
              "image": str(images[0]), "image_sha256": sha(images[0]),
              "retained_image": "runtime-image", "image_bytes": images[0].stat().st_size,
              "input_defconfig_sha256": sha(output / "input.defconfig"),
              "config_sha256": sha(output / ".config"), "generator_invoked": False,
              "compiler": cross_compile + compiler,
              "compiler_version_stdout_sha256": sha(output / "compiler.stdout"),
              "ranking_eligible": False, "purpose": "upstream example build and functional deployment probe"}
    save(output / "build-result.json", result)
    print(json.dumps(result, indent=2))


def boot(workspace, build_dir, output, accelerator, resume=False):
    proof = json.loads((build_dir / "build-result.json").read_text())
    image = Path(proof["image"])
    application = proof.get("application", "")
    benchmark = "abi" if application == "app-rtos-benchmark-abi" else application.startswith("app-rtos-benchmark")
    if sha(image) != proof["image_sha256"] or sources(workspace, proof.get("c11_timer_fix", False), benchmark) != proof["source_commits"]:
        raise ValueError("Build image or source identity changed")
    config = build_dir / ".config"
    if sha(config) != proof["config_sha256"]:
        raise ValueError("Build configuration changed")
    memory = guest_memory(config.read_text())
    if resume:
        previous = output / "boot-result.json"
        prior = json.loads(previous.read_text())
        if prior["image_sha256"] != proof["image_sha256"] or prior["accelerator"] != accelerator or \
                prior["guest_memory_bytes"] != memory:
            raise ValueError("Retained boot envelope differs; cannot resume")
        previous.rename(output / "boot-result.before-format-fix.json")
    else:
        output.mkdir(parents=True, exist_ok=False)
    cpu = "host" if accelerator == "kvm" else "cortex-a53"
    user = subprocess.check_output(["id", "-un"]).decode().strip()
    privilege = ["sudo", "-n", "setpriv", "--reuid=" + user,
                 "--regid=kvm", "--init-groups"] if accelerator == "kvm" else []
    argv = [*privilege, "timeout", "--kill-after=5", "300" if benchmark else "60", "qemu-system-aarch64",
            "-machine", "virt,gic-version=2", "-accel", accelerator, "-cpu", cpu,
            "-smp", "1", "-m", str(memory // 1024**2) + "M",
            "-nographic", "-monitor", "none", "-nic", "none",
            "-no-reboot",
            "-kernel", str(image)]
    runs, reused = [], []
    for index in range(1, 4):
        name = "boot" + str(index)
        path = output / (name + ".json")
        if resume and path.exists():
            status = json.loads(path.read_text())
            if status["state"] != "finished" or status["argv"] != [str(x) for x in argv] or \
                    status["stdout_sha256"] != sha(output / (name + ".stdout")) or \
                    status["stderr_sha256"] != sha(output / (name + ".stderr")):
                raise ValueError("Retained run is incomplete or differs; inspect its actual process before proceeding")
            reused.append(index)
        else:
            status = command(output, name, argv)
        verdict = (original_results if benchmark else hello_result)((output / (name + ".stdout")).read_bytes(),
                               (output / (name + ".stderr")).read_bytes(), status["returncode"])
        runs.append({"index": index, **verdict})
        if not verdict["functional_probe_pass"]:
            break
    save(output / "boot-result.json", {"image_sha256": proof["image_sha256"], "accelerator": accelerator,
        "guest_memory_bytes": memory,
        "reused_boot_indices": reused,
        "runs": runs, "all_three_pass": len(runs) == 3 and all(r["functional_probe_pass"] for r in runs),
        "generator_invoked": False, "ranking_eligible": False,
        "boundary": "Fresh virtual guests on the Raspberry Pi Linux host; not native bare-metal or performance/energy evidence."})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "build", "boot"))
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--defconfig", type=Path)
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--cross-compile", default="")
    parser.add_argument("--c11-timer-fix", action="store_true")
    parser.add_argument("--application", choices=("app-helloworld", "app-rtos-benchmark", "app-rtos-benchmark-current", "app-rtos-benchmark-abi"), default="app-helloworld")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--accelerator", choices=("kvm", "tcg"), default="kvm")
    args = parser.parse_args()
    if args.action == "probe":
        probe(args.workspace.resolve(), args.output.resolve())
    elif args.action == "build":
        build(args.workspace.resolve(), args.output.resolve(), args.defconfig.resolve() if args.defconfig else None,
              args.cross_compile, args.compiler, args.c11_timer_fix, args.application)
    else:
        if args.build_dir is None:
            parser.error("boot requires --build-dir")
        boot(args.workspace.resolve(), args.build_dir.resolve(), args.output.resolve(), args.accelerator, args.resume)
