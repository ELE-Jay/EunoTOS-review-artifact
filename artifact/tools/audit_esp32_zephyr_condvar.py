#!/usr/bin/env python3
"""Audit unchanged Zephyr condition-variable cases on RIOT and NuttX."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile
from audit_esp32_zephyr_thread import ROOT, REFERENCE, SHARED, CONDVAR_TAGS, capture, check_manifest, digest, UPSTREAM, ZEPHYR_UPSTREAM
from audit_esp32_resources import audit_elf_image

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_condvar"
COHORTS = (("riot", "v1"), ("nuttx", "v1"))
ORIGINALS = ("condvar.c", "timing_sc.c", "timing_sc.h", "utils.h")
NATIVE = {
    "riot": ("core/thread.c", "core/sched.c", "core/include/thread.h", "core/include/sched.h",
             "core/mutex.c", "core/include/mutex.h", "core/cond.c", "core/include/cond.h",
             "sys/sema/sema.c", "sys/include/sema.h", "cpu/esp32/irq_arch.c", "cpu/esp_common/esp-xtensa/thread_arch.c"),
    "nuttx": ("sched/pthread/pthread_create.c", "sched/pthread/pthread_join.c", "sched/pthread/pthread_exit.c",
              "sched/pthread/pthread_condwait.c", "sched/pthread/pthread_condsignal.c", "sched/pthread/pthread_mutex.c",
              "sched/pthread/pthread_mutexinit.c", "sched/pthread/pthread_mutextimedlock.c", "sched/pthread/pthread_mutexunlock.c",
              "sched/pthread/pthread_mutexinconsistent.c", "libs/libc/pthread/pthread_condinit.c", "libs/libc/pthread/pthread_attr_setstack.c",
              "libs/libc/semaphore/sem_getvalue.c", "sched/semaphore/sem_post.c", "sched/semaphore/sem_wait.c",
              "sched/semaphore/sem_setprotocol.c", "sched/sched/sched_foreach.c", "include/pthread.h", "sched/pthread/pthread.h",
              "arch/xtensa/src/common/xtensa_usestack.c", "arch/xtensa/src/common/xtensa_releasestack.c",
              "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/common/xtensa_timer.h", "tools/version.sh"),
}


def capture_condvar(directory, index, os):
    boot = capture(directory, index, os, condvar_subset=True)
    lines = [json.loads(line)["line"] for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    objects = [line for line in lines if line.startswith(("CONDVAR ORIGINAL MUTEX ", "CONDVAR ORIGINAL OBJECT "))]
    if os == "riot":
        if objects != ["CONDVAR ORIGINAL MUTEX locked_without_waiters=1", "CONDVAR ORIGINAL OBJECT waiters_empty=1"]:
            raise ValueError("original RIOT retained mutex/empty condvar state differs")
    else:
        mutex = re.fullmatch(r"CONDVAR ORIGINAL MUTEX owner=(\d+) locks=1 flags=3", objects[0]) if len(objects) == 2 else None
        if not mutex or int(mutex[1]) <= 0 or objects[1] != "CONDVAR ORIGINAL OBJECT semaphore_value=0":
            raise ValueError("original NuttX owner-dead robust mutex/empty condvar state differs")
    boot["final_original_objects"] = objects
    return boot


def audit(directory, os, verify_upstream=False):
    for manifest in ("image.sha256", "capture.sha256"):
        check_manifest(directory, manifest)
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}
    if not {"application.elf", "application.bin", "application.map", "config", "compiler.txt", "build.log", "disassembly.txt",
            "bootloader.bin", "partitions.bin", "port.c", "include/zephyr/kernel.h", *(
                "source/" + name for name in ORIGINALS), *("native-source/" + name for name in NATIVE[os])} <= names:
        raise ValueError("original/native/build/image coverage incomplete")
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{extension}" for i in (1, 2, 3) for extension in ("jsonl", "raw"))} <= names:
        raise ValueError("acquisition coverage incomplete")
    original = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in ORIGINALS:
        row = original["src/" + name]
        if row["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or row["sha256"] != digest(directory / "source" / name) or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original condvar body/statistics changed")
    for path in (PORT / os).rglob("*"):
        if path.is_file() and path.read_bytes() != (directory / "build-files" / path.relative_to(PORT / os)).read_bytes():
            raise ValueError("inspected native adapter/build selection differs")
    for name in ("port.c", "include/zephyr/kernel.h"):
        if (directory / name).read_bytes() != (PORT / os / name).read_bytes():
            raise ValueError("actually compiled adapter differs")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                path.read_bytes() != (directory / "include" / path.relative_to(SHARED)).read_bytes():
            raise ValueError("original timing/format adapter differs")
    provenance = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in NATIVE[os]:
            with urlopen(UPSTREAM[os] + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / "native-source" / name):
                raise ValueError(("native implementation differs from fixed official revision", name))
            records.append({"path": name, "url": UPSTREAM[os] + name, "sha256": sha})
        provenance.write_text(json.dumps(records, indent=2) + "\n")
    records = json.loads(provenance.read_text())
    if len(records) != len(NATIVE[os]) or {row["path"] for row in records} != set(NATIVE[os]) or any(
            row["url"] != UPSTREAM[os] + row["path"] or row["sha256"] != digest(directory / "native-source" / row["path"])
            for row in records):
        raise ValueError("native condvar/mutex/thread source provenance differs")
    config, compiler = (directory / "config").read_text(), (directory / "compiler.txt").read_text()
    if os == "riot":
        for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                            ("THREAD_PRIORITY_MAIN", 10), ("MODULE_CORE_THREAD", 1), ("MODULE_SEMA", 1)):
            if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
                raise ValueError("native RIOT single-core/FIFO/clock profile differs")
        if "MODULE_SCHED_ROUND_ROBIN" in config or "MODULE_CORE_MUTEX_PRIORITY_INHERITANCE" in config or "12.2.0" not in compiler:
            raise ValueError("native RIOT tickless/plain-mutex/compiler profile differs")
    else:
        required = {"CONFIG_BUILD_FLAT=y", "CONFIG_EXAMPLES_ZEPHYR_CONDVAR=y", "CONFIG_USEC_PER_TICK=1000000",
                    "CONFIG_RR_INTERVAL=0", "CONFIG_PRIORITY_INHERITANCE=y", "CONFIG_PTHREAD_MUTEX_TYPES=y",
                    "CONFIG_PTHREAD_MUTEX_ROBUST=y", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240"}
        if not required <= set(config.splitlines()) or {"CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y", "CONFIG_DISABLE_PTHREAD=y",
                                                       "CONFIG_PTHREAD_MUTEX_UNSAFE=y"} & set(config.splitlines()) or "13.2.0" not in compiler:
            raise ValueError("native NuttX FIFO/clock/recursive-owned-robust mutex profile differs")
        if 'CONFIG_VERSION_STRING="12.2.1"' not in (directory / "version-metadata").read_text() or \
                not re.search(r'#define CONFIG_VERSION_STRING\s+"12.2.1"', (directory / "version-header.h").read_text()):
            raise ValueError("native snapshot version metadata differs")
    commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    for name in ("condvar.c", "timing_sc.c", "port.c", *(name for name in NATIVE[os] if name.endswith(".c"))):
        if os == "riot":
            suffix = "app-riot/" + name if name in ("condvar.c", "timing_sc.c", "port.c") else name
            selected = [args for args in commands if Path(args[0]).name == "xtensa-esp32-elf-gcc" and any(
                not arg.startswith("-") and (arg.endswith("/" + suffix) or arg == suffix) for arg in args)]
        else:
            selected = [args for args in commands if Path(args[0]).name == "xtensa-esp32-elf-gcc" and any(
                not arg.startswith("-") and Path(arg).name == Path(name).name for arg in args) and
                (not name.startswith("sched/") or "-D__KERNEL__" in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("original/native condvar compilation differs", name))
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    disassembly = (directory / "disassembly.txt").read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")

        def symbol(name):
            found = symbols.get_symbol_by_name(name)
            if not found:
                raise ValueError(("native/original entry not linked", name))
            result = max(found, key=lambda row: row["st_size"])
            if result["st_shndx"] == "SHN_UNDEF" or not result["st_size"]:
                raise ValueError(("native/original body missing", name))
            return result

        def body(name):
            start = symbol(name)["st_value"]
            match = re.search(r"^" + format(start, "x") + r" <" + re.escape(name) + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
            if not match:
                raise ValueError(("native/original disassembly missing", name))
            return match[1]

        def calls(name, target, count=None):
            matches = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <" + re.escape(target) + r">$", body(name), re.M)
            if not matches or (count is not None and len(matches) != count):
                raise ValueError(("native/original operation not actually called", name, target))
            section = elf.get_section(symbol(name)["st_shndx"])
            data, base, destination = section.data(), section["sh_addr"], symbol(target)["st_value"]
            for address, encoding, label in matches:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != 0x25 or (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination or \
                        data[address - base:address - base + 3] != bytes.fromhex(encoding)[::-1]:
                    raise ValueError("native/original call bytes or encoded target differ")

        if not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body("z_impl_timing_timestamp_get")):
            raise ValueError("timestamp does not read native CCOUNT")
        calls("start_thread_entry", "k_condvar_wait", 1)
        calls("start_thread_entry", "k_mutex_lock", 1)
        calls("alt_thread_entry", "k_condvar_signal", 1)
        calls("condvar_blocking_ops", "k_thread_create", 2)
        calls("condvar_blocking_ops", "timing_cycles_to_ns_avg", 2)
        if os == "riot":
            calls("k_condvar_wait", "cond_wait", 1)
            calls("k_condvar_signal", "cond_signal", 1)
            calls("k_mutex_lock", "mutex_lock_internal", 1)
            calls("cond_wait", "mutex_unlock", 1)
            calls("cond_wait", "mutex_lock_internal", 1)
            calls("cond_wait", "sched_set_status", 1)
            calls("cond_signal", "_cond_signal", 1)
            calls("_cond_signal", "sched_set_status", 1)
            calls("_cond_signal", "sched_switch", 1)
            calls("k_thread_join", "thread_kill_zombie", 1)
            calls("thread_entry", "mutex_unlock_and_sleep", 1)
        else:
            calls("k_condvar_wait", "pthread_cond_wait", 1)
            calls("k_condvar_signal", "pthread_cond_signal", 1)
            calls("k_mutex_lock", "pthread_mutex_lock", 1)
            calls("k_thread_create", "pthread_create", 1)
            calls("k_thread_join", "pthread_join", 1)
            calls("nx_pthread_exit", "nxtask_exithook", 1)
            calls("nxtask_exithook", "nxtask_recover", 1)
            calls("nxtask_recover", "pthread_mutex_inconsistent", 1)
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("installed image/board binding differs")
    captures = [capture_condvar(directory, index, os) for index in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("independent condition-variable boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in CONDVAR_TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 original condition-variable kernel subset", "os": "RIOT" if os == "riot" else "NuttX",
            "metric_count": 2, "original_iterations": 1000, "resets": 3, "captures": captures, "metrics": metrics,
            "clock_mhz": 240, "cores": 1, "tick_hz": "native-tickless" if os == "riot" else 1,
            "compiler": "12.2.0" if os == "riot" else "13.2.0", "worker_stack_bytes": 1792,
            "original_source_files": 4, "native_source_files": len(NATIVE[os]), "original_test_body_unchanged": True,
            "original_subtracts_timestamp_overhead": False, "ranking_eligible": False, "unmodified_official_native_suite": False,
            "original_explicitly_unlocks_mutex_before_exit": False, "general_object_cleanup_claim_eligible": False,
            "boundary": "original atomic wait/unlock/reacquire and signal-to-higher-priority-worker endpoints, 1000 loops and integer means; no overhead subtraction; native API/adapter costs retained; original returns with mutex held, final native object states recorded rather than repaired; RIOT plain non-PI mutex versus NuttX recursive owned PI/robust mutex; no cross-OS rank or general resource-cleanup claim"}


def render_table(results):
    lines = ["| Original Zephyr condition-variable subset / OS | Original case | Original means, ns (three boots) |", "| --- | --- | --- |"]
    for result in results:
        for tag in CONDVAR_TAGS:
            lines.append(f"| Original condvar port / {result['os']} / {tag} | {tag} | " +
                         " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("os", choices=NATIVE)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.os, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
