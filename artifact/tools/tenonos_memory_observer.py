#!/usr/bin/env python3
"""Collect native Tenon allocator statistics, separately from historical scores."""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from import_iotos_subjects import config_text
from tenonos_kvm_reproduce import boot, command, save, sha, sources, utc

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ("tenonos_memory_observer.py", "tenonos_memory_probe.c", "tenonos_tlsf_stats.patch",
           "tenonos_kvm_reproduce.py", "import_iotos_subjects.py")
PHASES = ("before-suite", "after-suite", "validation-allocated", "validation-released")
TLSF_BASE_SHA = "fa3749c5437af5fc2ae00a7c30c8bac67997049ee5608ebcb43c6f7ddd44a601"
TLSF_ADDITIONS = (b"#if TLSF_STATISTIC\n    /* Account new-area capacity before free_ex removes its free block. */\n    tlsf->used_size += area_size;\n#endif\n",
                  b"#if TLSF_STATISTIC\n    if (tlsf->used_size > tlsf->max_size)\n        tlsf->max_size = tlsf->used_size;\n#endif\n")


def unrepaired_tlsf(raw):
    for addition in TLSF_ADDITIONS:
        if raw.count(addition) != 1:
            raise ValueError("Expected exactly the statistics-only new-area repair")
        raw = raw.replace(addition, b"")
    if hashlib.sha256(raw).hexdigest() != TLSF_BASE_SHA:
        raise ValueError("Observer changed other native TLSF source")
    return raw


def instrument_main(raw):
    old = b"int main(int argc __unused, char *argv[] __unused)"
    if raw.count(old) != 1:
        raise ValueError("Pinned main entry differs")
    return raw.replace(old, b"int iotos_original_main(int argc __unused, char *argv[] __unused)")


def parse_memory(text):
    rows = re.findall(r"(?m)^IOTOS_MEMORY phase=(\S+) allocator=(tlsf|buddy) current=(\d+) peak=(\d+)\r?$", text)
    if tuple(r[0] for r in rows) != PHASES or len({r[1] for r in rows}) != 1 or \
            len(re.findall(r"(?m)^IOTOS_MEMORY_VALIDATION pass=1\r?$", text)) != 1:
        raise ValueError("Memory phase coverage differs")
    values = [{"phase": phase, "allocator": allocator, "current": int(current), "peak": int(peak)}
              for phase, allocator, current, peak in rows]
    if any(not 0 < r["current"] <= r["peak"] < 128 * 1024**2 for r in values) or \
            any(a["peak"] > b["peak"] for a, b in zip(values, values[1:])) or \
            values[2]["current"] < values[1]["current"] + 65536 or values[3]["current"] != values[1]["current"]:
        raise ValueError("Disabled, inconsistent or non-reclaiming native memory statistics")
    return values


def retain_link_inputs(image, build, kernel):
    elf = image.with_name(image.name + ".dbg")
    selected = {"linked-symbols.elf": elf, "mkbootinfo.py": kernel / "support/scripts/mkbootinfo.py",
                "mklinux.py": kernel / "support/scripts/mklinux.py"}
    for name, source in selected.items():
        shutil.copyfile(source, build / name)
    save(build / "linked-inputs.json", {"files": {name: sha(build / name) for name in selected},
         "measured_image_sha256": sha(image), "retained_before_guest_execution": True})


def on_pi(workspace, output, lifecycle=False, native_threads=False):
    if output.parent != Path("/dev/shm") or not output.name.startswith("iotos-tenon-v4-memory-"):
        raise ValueError("Unsafe temporary operation path")
    identity = sources(workspace, True, "abi")
    original = workspace / "apps/app-rtos-benchmark-abi"
    app = output / "source/app-rtos-benchmark-memory"
    app.mkdir(parents=True)
    names = subprocess.check_output(["git", "-C", str(original), "ls-files", "-z"]).decode().split("\0")[:-1]
    for name in names:
        dest = app / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / name, dest)
    before = {n: sha(app / n) for n in names}
    (app / "main.c").write_bytes(instrument_main((app / "main.c").read_bytes()))
    with (app / "Makefile.uk").open("a") as stream:
        stream.write("\nAPPRHEALSTONEBENCHMARK_SRCS-y += $(APPRHEALSTONEBENCHMARK_BASE)/iotos_memory.c\n")
        if lifecycle:
            from audit_tenonos_memory_lifecycle import WRAPPED
            stream.write('APPRHEALSTONEBENCHMARK_LDFLAGS-y += ' + ' '.join('-Wl,--wrap='+n for n in WRAPPED) + '\n')
    probe = "tenonos_memory_lifecycle.c" if lifecycle else "tenonos_memory_probe.c"
    shutil.copyfile(Path(__file__).with_name(probe), app / "iotos_memory.c")
    if native_threads:
        with (app / 'iotos_memory.c').open('ab') as stream:
            stream.write(b'\n' + Path(__file__).with_name('tenonos_native_threads.c').read_bytes())
    values, duplicates = config_text((output / "input.config").read_text())
    if duplicates:
        raise ValueError("Duplicate reference options")
    tlsf = values.get("CONFIG_LIBTLSF") == "y"
    if not tlsf and values.get("CONFIG_LIBUKALLOCBBUDDY") != "y":
        raise ValueError("Unrecognized default allocator")
    build = output / "build"
    build.mkdir()
    raw = (output / "input.config").read_text()
    if not tlsf:
        if raw.count("# CONFIG_LIBUKALLOC_IFSTATS is not set\n") != 1:
            raise ValueError("Expected native statistics initially disabled")
        raw = raw.replace("# CONFIG_LIBUKALLOC_IFSTATS is not set\n", "CONFIG_LIBUKALLOC_IFSTATS=y\n")
    (build / "input.defconfig").write_text(raw)
    make = ["make", "-C", str(workspace / "tenon-c11"), "A=" + str(app), "O=" + str(build / "build"),
            "C=" + str(build / ".config"), "L=" + str(workspace / "libs"), "CROSS_COMPILE=", "COMPILER=gcc"]
    if lifecycle:
        if native_threads:
            from audit_tenonos_native_threads import NATIVE_WRAPPED
        flags = ('uk_alloc_register',) + (NATIVE_WRAPPED if native_threads else ())
        make.append('UK_LDFLAGS=' + ' '.join('-Wl,--wrap='+n for n in flags))
    if tlsf:
        make.append("LIBTLSF_CFLAGS-y=-DTLSF_STATISTIC=1")
        patches = output / "source/tlsf-patches"
        shutil.copytree(workspace / "libs/lib-tlsf/patches", patches)
        shutil.copyfile(Path(__file__).with_name("tenonos_tlsf_stats.patch"), patches / "03-iotos-statistics.patch")
        make.append("LIBTLSF_PATCHDIR=" + str(patches))
    for name, argv in (("compiler", ["gcc", "--version"]),
                       ("configure", [*make, "UK_DEFCONFIG=" + str(build / "input.defconfig"), "defconfig"]),
                       ("build", ["timeout", "--kill-after=10", "900", *make, "-j2"])):
        if command(build, name, argv)["returncode"]:
            raise ValueError("Native memory build failed: " + name)
    images = list((build / "build").glob("*_qemu-arm64"))
    if len(images) != 1:
        raise ValueError("Expected one linked observation image")
    retain_link_inputs(images[0], build, workspace / "tenon-c11")
    if lifecycle:
        from audit_tenonos_memory_lifecycle import linked_preflight
        linked_preflight(build / 'linked-symbols.elf', build / 'lifecycle-disassembly.txt', tlsf)
        if native_threads:
            from audit_tenonos_native_threads import linked_native
            save(build/'native-thread-code.json', linked_native(build/'linked-symbols.elf'))
    shutil.copyfile(images[0], build / "runtime-image")
    actual, duplicates = config_text((build / ".config").read_text())
    changes = {n: [values.get(n, "n"), actual.get(n, "n")] for n in values.keys() | actual.keys()
               if values.get(n, "n") != actual.get(n, "n")}
    allowed = {"CONFIG_UK_APP"} | (set() if tlsf else {"CONFIG_LIBUKALLOC_IFSTATS"})
    if duplicates or set(changes) != allowed or actual["CONFIG_UK_APP"] != json.dumps(str(app)):
        raise ValueError("Observer changed more than its source binding/native statistics")
    save(output / "source-proof.json", {"identity": identity, "original_app_sha256": before,
         "observer_app_sha256": {n: sha(app / n) for n in [*names, "iotos_memory.c"]},
         "config_changes": changes, "tlsf": tlsf, "test_bodies_changed": False})
    # Preserve the native counter implementation, not just its printed result.
    selected = {"alloc.h": workspace / "tenon-c11/lib/ukalloc/include/uk/alloc.h",
                "alloc_impl.h": workspace / "tenon-c11/lib/ukalloc/include/uk/alloc_impl.h",
                "stats.c": workspace / "tenon-c11/lib/ukalloc/stats.c",
                "bbuddy.c": workspace / "tenon-c11/lib/ukallocbbuddy/bbuddy.c",
                "glue.c": workspace / "libs/lib-tlsf/glue.c"}
    if lifecycle:
        selected.update({'alloc.c':workspace/'tenon-c11/lib/ukalloc/alloc.c',
                         'thread.c':workspace/'tenon-c11/lib/ukthread/thread.c',
                         'thread.h':workspace/'tenon-c11/lib/ukthread/include/uk/thread.h'})
    if native_threads:
        selected.update({'boot.c':workspace/'tenon-c11/lib/ukboot/boot.c',
                         'sched.c':workspace/'tenon-c11/lib/uksched/sched.c'})
    if tlsf:
        origin = build / "build/libtlsf/origin/TLSF-2.4.6/src"
        selected.update({"tlsf.c": origin / "tlsf.c", "tlsf.h": origin / "tlsf.h"})
    compile_commands = [build / "build" / n for n in (("libtlsf/tlsf.o.cmd", "libtlsf/glue.o.cmd") if tlsf else
                        ("libukallocbbuddy/bbuddy.o.cmd", "libukalloc/stats.o.cmd"))]
    if tlsf and any("-DTLSF_STATISTIC=1" not in p.read_text() for p in compile_commands):
        raise ValueError("Native statistics flag absent from the actual compile command")
    selected.update({p.parent.name + "-" + p.name: p for p in compile_commands})
    native = output / "source/native-statistics"
    native.mkdir()
    for name, path in selected.items():
        shutil.copyfile(path, native / name)
    if tlsf:
        (native / "tlsf-without-observer-fix.c").write_bytes(unrepaired_tlsf((native / "tlsf.c").read_bytes()))
        selected["tlsf-without-observer-fix.c"] = native / "tlsf-without-observer-fix.c"
    save(output / "native-statistics.json", {n: sha(native / n) for n in selected})
    save(build / "build-result.json", {"application": "app-rtos-benchmark-memory", "image": str(build / "runtime-image"),
         "image_sha256": sha(build / "runtime-image"), "config_sha256": sha(build / ".config"),
         "source_commits": sources(workspace, True, True), "c11_timer_fix": True, "ranking_eligible": False})
    boot(workspace, build, output / "boots", "kvm")
    proof = json.loads((output / "boots/boot-result.json").read_text())
    if not proof["all_three_pass"]:
        raise ValueError("Original six-case suite failed")
    rows = [parse_memory((output / ("boots/boot%d.stdout" % i)).read_text()) for i in (1, 2, 3)]
    if lifecycle:
        from audit_tenonos_memory_lifecycle import replay
        if native_threads:
            from audit_tenonos_native_threads import replay
        save(output/'lifecycle-result.json', [replay((output/('boots/boot%d.stdout'%i)).read_text()) for i in (1,2,3)])
    if sources(workspace, True, "abi") != identity:
        raise ValueError("Pinned source worktree changed")
    save(output / "memory-result.json", {"pass": True, "fresh_guests": 3, "snapshots": rows,
         "whole_live_ram_peak_bytes": None, "ranking_eligible": False, "model_calls": 0})


def retain_pi_evidence(ssh, host, socket, remote, folder, returncode, prefix="iotos-tenon-v4-memory-"):
    if Path(remote).parent != Path("/dev/shm") or not Path(remote).name.startswith(prefix):
        raise ValueError("Unsafe recovery path")
    excludes = ["--exclude=/build/build/"] if returncode == 0 else []
    subprocess.run(["rsync", "-aL", *excludes, "-e", shlex.join(ssh[:-1]), host + ":" + remote + "/", str(folder) + "/"],
                   check=True, timeout=600)
    code = "from pathlib import Path;import hashlib,json;r=Path(" + repr(remote) + ");print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob('*') if p.is_file() and '__pycache__' not in p.parts" + (" and p.relative_to(r).parts[:2]!=('build','build')" if returncode == 0 else "") + "}))"
    manifest = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])], timeout=60))
    if any(sha(folder / n) != h for n, h in manifest.items()):
        raise ValueError("Returned Pi evidence differs; retain remote files")
    save(folder / "runtime-transfer-check.json", {"all_equal": True, "files": manifest, "remote_returncode": returncode,
         "symlinked_build_sources_retained_as_bytes": True})
    subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", remote])], check=True, timeout=20)


def on_pi_elf(output):
    if output.parent != Path("/dev/shm") or not output.name.startswith("iotos-tenon-v4-memory-"):
        raise ValueError("Unsafe ELF rebuild path")
    recovery = output / "elf-recovery-v5"
    recovery.mkdir()
    shutil.copyfile(Path(__file__), recovery / "recorder.py")
    build = output / "build"
    proof = json.loads((build / "build-result.json").read_text())
    stamps = re.findall(rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", (build / "runtime-image").read_bytes())
    if len(stamps) != 1:
        raise ValueError("Expected exactly one native recorded HOSTUTC value")
    argv = [*json.loads((build / "build.json").read_text())["argv"], "HOSTUTC=" + stamps[0].decode()]
    metadata_object = build / "build/libuklibid/libinfo.global.o"
    if metadata_object.exists():
        metadata_object.unlink()
    if command(recovery, "rebuild", argv)["returncode"]:
        raise ValueError("ELF rebuild failed")
    images = list((build / "build").glob("*_qemu-arm64"))
    elfs = list((build / "build").glob("*_qemu-arm64.dbg"))
    if len(images) != 1 or len(elfs) != 1 or sha(images[0]) != proof["image_sha256"]:
        raise ValueError("Rebuilt image is not byte-identical to the measured image")
    shutil.copyfile(elfs[0], recovery / "linked-symbols.elf")
    kernel = Path(argv[argv.index("-C") + 1])
    shutil.copyfile(kernel / "support/scripts/mkbootinfo.py", recovery / "mkbootinfo.py")
    for name, step in (("strip", ["strip", "-s", str(recovery / "linked-symbols.elf"), "-o", str(recovery / "linked.elf")]),
                       ("bootinfo", ["python3", str(recovery / "mkbootinfo.py"), str(recovery / "linked.elf"),
                                     str(recovery / "bootinfo.bin"), "-a", "arm64"]),
                       ("embed-bootinfo", ["objcopy", str(recovery / "linked.elf"),
                                           "--update-section", ".uk_bootinfo=" + str(recovery / "bootinfo.bin")])):
        if command(recovery, name, step)["returncode"]:
            raise ValueError("Native ELF packaging failed: " + name)
    if command(recovery, "objcopy", ["objcopy", "-O", "binary", str(recovery / "linked.elf"),
                                     str(recovery / "objcopy-image.bin")])["returncode"]:
        raise ValueError("ELF objcopy failed")
    shutil.copyfile(kernel / "support/scripts/mklinux.py", recovery / "mklinux.py")
    if command(recovery, "native-header", ["python3", str(recovery / "mklinux.py"),
               str(recovery / "objcopy-image.bin"), str(recovery / "linked-symbols.elf")])["returncode"] or \
            sha(recovery / "objcopy-image.bin") != proof["image_sha256"]:
        raise ValueError("Linked ELF does not reproduce the measured flat image")
    save(recovery / "result.json", {"pass": True, "new_guest_boots": 0,
         "measured_image_sha256": proof["image_sha256"], "linked_elf_sha256": sha(recovery / "linked.elf"),
         "objcopy_image_sha256": sha(recovery / "objcopy-image.bin"), "recorder_sha256": sha(recovery / "recorder.py"),
         "native_build_metadata_hostutc": stamps[0].decode(), "metadata_taken_from_measured_image": True})


def recover_elf(folder, socket, host):
    if ROOT != Path("/home/reviewer/esp32-pilot/audit-workspace") or not folder.exists():
        raise ValueError("Recover existing measured evidence on leon")
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host]
    campaign = json.loads((folder / "campaign.json").read_text())
    for completed in campaign["completed"]:
        p = folder / completed["profile"]
        original = json.loads((p / "build/build-result.json").read_text())
        remote = str(Path(original["image"]).parents[1])
        if Path(remote).parent != Path("/dev/shm") or not Path(remote).name.startswith("iotos-tenon-v4-memory-"):
            raise ValueError("Wrong original operation path")
        subprocess.run([*ssh, shlex.join(["mkdir", "-p", "-m", "700", remote])], check=True, timeout=20)
        subprocess.run(["rsync", "-aL", "--exclude=/build/build/", "-e", shlex.join(ssh[:-1]), str(p) + "/",
                        host + ":" + remote + "/"], check=True, timeout=120)
        subprocess.run([*ssh, shlex.join(["mkdir", "-p", remote + "/elf-helpers"])], check=True, timeout=20)
        helpers = [ROOT / "tools" / n for n in ("tenonos_memory_observer.py", "tenonos_kvm_reproduce.py", "import_iotos_subjects.py")]
        subprocess.run(["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes", *[str(n) for n in helpers],
                        host + ":" + remote + "/elf-helpers/"], check=True, timeout=30)
        with (p / "elf-recovery-v5-remote.log").open("xb") as stream:
            step = subprocess.run([*ssh, shlex.join(["python3", remote + "/elf-helpers/tenonos_memory_observer.py",
                                  "on-pi-elf", "--output", remote])], stdout=stream, stderr=subprocess.STDOUT, timeout=950)
        excludes = ["--exclude=/build/build/"] if step.returncode == 0 else []
        subprocess.run(["rsync", "-aL", *excludes, "-e", shlex.join(ssh[:-1]), host + ":" + remote + "/elf-recovery-v5/",
                        str(p / "elf-recovery-v5") + "/"], check=True, timeout=120)
        code = "from pathlib import Path;import hashlib,json;r=Path(" + repr(remote + "/elf-recovery-v5") + ");print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob('*') if p.is_file()}))"
        manifest = json.loads(subprocess.check_output([*ssh, shlex.join(["python3", "-c", code])], timeout=30))
        if any(sha(p / "elf-recovery-v5" / n) != h for n, h in manifest.items()):
            raise ValueError("ELF recovery transfer differs")
        save(p / "elf-recovery-v5-transfer.json", {"files": manifest, "all_equal": True, "remote_returncode": step.returncode})
        if step.returncode:
            raise ValueError("ELF recovery failed; retain remote rebuild files")
        subprocess.run([*ssh, shlex.join(["rm", "-rf", "--", remote])], check=True, timeout=20)
        print(json.dumps({"profile": completed["profile"], "byte_identical_elf_recovery": True}), flush=True)


def collect(plan_path, output, socket, host, workspace, lifecycle=False, native_threads=False):
    from run_tenonos_energy import reference_images, host_state, governor
    root = Path("/home/reviewer/esp32-pilot/audit-workspace")
    if ROOT != root or output.exists():
        raise ValueError("Collect only on leon in a new persistent folder")
    output.resolve().relative_to((root / "artifacts/reports").resolve())
    plan = json.loads(plan_path.read_text())
    reference_plan = json.loads((root / plan["reference_registry"]).read_text())
    variants = reference_images(reference_plan, root)
    if not plan['profiles'] or len(set(plan['profiles'])) != len(plan['profiles']) or not set(plan['profiles']) <= set(variants):
        raise ValueError('Invalid memory-study profile selection')
    ssh = ["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host]
    initial = host_state(ssh)
    if initial["qemu_running"] or initial["throttled"] != "throttled=0x0":
        raise ValueError("Pi is busy or throttled")
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output / "protocol.json")
    shutil.copyfile(root / plan["reference_registry"], output / "references.json")
    (output / "helpers").mkdir()
    helpers = HELPERS + (('tenonos_memory_lifecycle.c','audit_tenonos_memory_lifecycle.py') if lifecycle else ())
    if native_threads:
        helpers += ('tenonos_native_threads.c','audit_tenonos_native_threads.py')
    for name in helpers:
        shutil.copyfile(root / "tools" / name, output / "helpers" / name)
    campaign = {"status": "incomplete", "registered_utc": utc(), "host_initial": initial,
                "protocol_sha256": sha(plan_path), "source_sha256": {n: sha(output / "helpers" / n) for n in helpers},
                "model_calls": 0, "completed": []}
    save(output / "campaign.json", campaign)
    try:
        governor(ssh, "performance")
        for name in plan["profiles"]:
            profile = variants[name]
            folder = output / name
            folder.mkdir()
            shutil.copyfile(root / profile["build"] / ".config", folder / "input.config")
            remote = "/dev/shm/iotos-tenon-v4-memory-" + output.name + "-" + name
            subprocess.run([*ssh, shlex.join(["mkdir", "-m", "700", remote])], check=True, timeout=20)
            subprocess.run([*ssh, shlex.join(["mkdir", remote + "/helpers"])], check=True, timeout=20)
            scp = ["scp", "-o", "ControlPath=" + socket, "-o", "BatchMode=yes"]
            subprocess.run([*scp, str(folder / "input.config"), host + ":" + remote + "/"], check=True, timeout=30)
            subprocess.run([*scp, *[str(output / "helpers" / n) for n in helpers], host + ":" + remote + "/helpers/"], check=True, timeout=30)
            before = host_state(ssh)
            if lifecycle:
                save(folder/'host-before.json', before)
            argv = ["timeout", "--kill-after=10", "1850", "python3", remote + "/helpers/tenonos_memory_observer.py",
                    "on-pi-native-threads" if native_threads else "on-pi-lifecycle" if lifecycle else "on-pi",
                    "--workspace", workspace, "--output", remote]
            with (folder / "remote.stdout").open("xb") as out, (folder / "remote.stderr").open("xb") as err:
                step = subprocess.run([*ssh, shlex.join(argv)], stdout=out, stderr=err, timeout=1880)
            retain_pi_evidence(ssh, host, socket, remote, folder, step.returncode)
            after = host_state(ssh)
            if lifecycle:
                save(folder/'host-after.json', after)
            if step.returncode or after["qemu_running"] or before["governor"] != "performance" or \
                    after["throttled"] != "throttled=0x0" or after["governor"] != "performance":
                raise ValueError("Memory profile failed; evidence retained without automatic retry")
            campaign["completed"].append({"profile": name, "host_before": before, "host_after": after})
            save(output / "campaign.json", campaign)
            print(json.dumps({"profile": name, "fresh_guests": 3, "pass": True}), flush=True)
        campaign["status"] = "complete"
    except BaseException as error:
        campaign.update(status="failed", error=repr(error))
        raise
    finally:
        governor(ssh, initial["governor"])
        campaign["host_after_restore"] = host_state(ssh)
        campaign["governor_restored"] = campaign["host_after_restore"]["governor"] == initial["governor"]
        save(output / "campaign.json", campaign)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("collect", "collect-lifecycle", "collect-native-threads", "on-pi", "on-pi-lifecycle", "on-pi-native-threads", "recover", "on-pi-elf", "recover-elf"))
    p.add_argument("--workspace", type=Path, default=Path("/home/pi/tenonos-benchmark-v1"))
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--socket", default="/tmp/iotos-pi-energy.sock")
    p.add_argument("--host", default="pi@192.168.31.76")
    p.add_argument("--remote", help="Existing failed operation; recover bytes, never rerun guests")
    p.add_argument('--plan', type=Path, help='Explicit frozen memory protocol; default retains the original protocol')
    a = p.parse_args()
    if a.action in ("on-pi", "on-pi-lifecycle", "on-pi-native-threads"):
        on_pi(a.workspace.resolve(), a.output.resolve(), a.action != 'on-pi', a.action == 'on-pi-native-threads')
    elif a.action == "on-pi-elf":
        on_pi_elf(a.output.resolve())
    elif a.action == "recover-elf":
        recover_elf(a.output.resolve(), a.socket, a.host)
    elif a.action == "recover":
        if ROOT != Path("/home/reviewer/esp32-pilot/audit-workspace") or not a.output.exists() or not a.remote:
            p.error("Recover existing evidence on leon with --remote")
        a.output.resolve().relative_to((ROOT / "artifacts/reports").resolve())
        ssh = ["ssh", "-S", a.socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", a.host]
        retain_pi_evidence(ssh, a.host, a.socket, a.remote, a.output.resolve(), 1)
    else:
        with (Path.home() / "esp32-pilot/.tenonos-paper-campaign.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            native_threads = a.action == 'collect-native-threads'
            lifecycle = a.action in ('collect-lifecycle','collect-native-threads')
            plan = ('tenonos_native_threads_rpi4_v1.json' if native_threads else
                    'tenonos_memory_lifecycle_rpi4_v1.json' if lifecycle else 'tenonos_memory_rpi4_v1.json')
            collect(a.plan.resolve() if a.plan else ROOT / 'registry' / plan, a.output.resolve(), a.socket, a.host,
                    str(a.workspace), lifecycle, native_threads)
