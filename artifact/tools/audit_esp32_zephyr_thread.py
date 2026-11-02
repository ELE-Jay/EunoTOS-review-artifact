#!/usr/bin/env python3
"""Audit original Zephyr thread lifecycle means on four native OS adapters."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import statistics
import struct
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from run_esp32_followup import check_uart_chronology, read_raw_capture
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_zephyr_latency_alios import UPSTREAM as RHINO_UPSTREAM, hardware_tick_divisors
from audit_esp32_zephyr_latency_freertos import ROOT, REFERENCE
from audit_esp32_zephyr_original import LATENCY, UPSTREAM as ZEPHYR_UPSTREAM

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_thread"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos/include"
LABELS = {"freertos": "FreeRTOS", "alios": "AliOS-Rhino", "riot": "RIOT", "nuttx": "NuttX"}
TAGS = tuple("thread." + name + ".kernel.from.kernel" for name in ("create", "start", "suspend", "resume", "abort"))
ORIGINALS = ("thread.c", "timing_sc.c", "timing_sc.h", "utils.h")
NATIVE = {
    "freertos": ("FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/list.c", "FreeRTOS-Kernel/portable/xtensa/port.c"),
    "alios": ("kernel/rhino/k_task.c", "kernel/rhino/k_sem.c", "kernel/rhino/k_sched.c",
              "kernel/rhino/include/k_task.h", "platform/arch/xtensa/lx6/xtensa_init.c",
              "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h"),
    "riot": ("core/thread.c", "core/sched.c", "core/include/thread.h", "core/include/sched.h", "core/lib/include/clist.h",
             "core/mutex.c", "core/include/mutex.h", "sys/sema/sema.c", "sys/include/sema.h",
             "cpu/esp32/irq_arch.c", "cpu/esp_common/esp-xtensa/thread_arch.c"),
    "nuttx": ("sched/task/task_init.c", "sched/task/task_activate.c", "sched/task/task_delete.c",
              "sched/task/task_terminate.c", "sched/sched/sched_releasetcb.c", "sched/group/group_suspendchildren.c",
              "sched/group/group_continue.c", "sched/signal/sig_dispatch.c", "sched/signal/sig_default.c",
              "sched/sched/sched_setparam.c", "sched/semaphore/sem_post.c", "sched/semaphore/sem_wait.c",
              "sched/semaphore/sem_setprotocol.c", "arch/xtensa/src/common/xtensa_usestack.c",
              "arch/xtensa/src/common/xtensa_releasestack.c", "include/nuttx/sched.h",
              "arch/xtensa/src/esp32/esp32_timerisr.c", "arch/xtensa/src/common/xtensa_timer.h", "tools/version.sh"),
}
UPSTREAM = {"freertos": "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/components/freertos/",
            "alios": RHINO_UPSTREAM, "riot": RIOT_UPSTREAM,
            "nuttx": "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/"}
COMPILERS = {"freertos": "13.2.0", "alios": "5.2.0", "riot": "12.2.0", "nuttx": "13.2.0"}
COHORTS = (("freertos", "v1"), ("alios", "v1"), ("riot", "v2"), ("nuttx", "v1"))
YIELD_TAGS = ("thread.yield.preemptive.ctx.k_to_k",)
CONDVAR_TAGS = ("condvar.wait.blocking.k_to_k", "condvar.signal.wake+ctx.k_to_k")
EVENT_TAGS = ("events.post.immediate.kernel", "events.set.immediate.kernel", "events.wait.immediate.kernel",
              "events.wait_all.immediate.kernel", "events.wait.blocking.k_to_k", "events.set.wake+ctx.k_to_k",
              "events.wait_all.blocking.k_to_k", "events.post.wake+ctx.k_to_k")
EVENT_NATIVE = {
    "freertos": NATIVE["freertos"] + ("FreeRTOS-Kernel/event_groups.c", "FreeRTOS-Kernel/include/freertos/event_groups.h",
                                     "FreeRTOS-Kernel/portable/xtensa/portasm.S"),
    "alios": NATIVE["alios"] + ("kernel/rhino/k_event.c", "kernel/rhino/include/k_event.h"),
}
ISR_TAGS = ("isr.resume.interrupted.thread.kernel", "isr.resume.different.thread.kernel")
ISR_NATIVE = tuple("components/freertos/" + name for name in NATIVE["freertos"]) + (
    "components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S",
    "components/esp_hw_support/intr_alloc.c", "components/xtensa/xtensa_intr.c")
ISR_NATIVE_ALIOS = NATIVE["alios"] + ("kernel/rhino/k_sys.c", "kernel/rhino/include/k_err.h",
    "platform/arch/xtensa/lx6/xtensa_intr.c", "platform/arch/xtensa/lx6/include/port.h",
    "platform/mcu/esp32/espos/platform/rhino/espos_scheduler.c")
ISR_NATIVE_RIOT = NATIVE["riot"] + ("cpu/esp_common/vendor/xtensa/xtensa_intr.c",
    "cpu/esp_common/vendor/xtensa/portasm.S", "cpu/esp_common/vendor/xtensa/xtensa_vectors.S",
    "sys/ztimer/util.c", "sys/include/ztimer.h")
ISR_NATIVE_NUTTX = NATIVE["nuttx"] + ("arch/xtensa/src/esp32/esp32_irq.c",
    "arch/xtensa/src/esp32/esp32_irq.h", "arch/xtensa/src/common/xtensa_irqdispatch.c",
    "arch/xtensa/src/common/xtensa_switchcontext.c", "arch/xtensa/src/common/xtensa.h",
    "sched/irq/irq_attach.c", "sched/irq/irq_dispatch.c", "sched/signal/sig_usleep.c",
    "sched/signal/sig_nanosleep.c", "sched/signal/sig_timedwait.c", "sched/semaphore/sem_trywait.c",
    "include/nuttx/irq.h", "include/nuttx/signal.h")
RIOT_ISR_CONTROL = {"int_to_thread", "alt_thread_entry", "start_thread_entry", "test_isr", "software_isr",
                    "irq_offload", "k_sem_give", "k_sem_take", "main", "sema_post", "mutex_unlock", "sched_switch"}
NUTTX_ISR_CONTROL = {"int_to_thread", "alt_thread_entry", "start_thread_entry", "test_isr", "software_isr",
                     "irq_offload", "k_sem_give", "k_sem_take", "zephyr_isr_main", "nxsem_post",
                     "up_switch_context", "xtensa_irq_dispatch", "irq_dispatch", "original_tick_synch"}


def event_control_rows(directory, disassembly, elf, symbols, *, isr=False, isr_os="alios"):
    prefix = "isr-control-v2" if isr else "event-control-v3"
    output = "isr-control-flow-v2.txt" if isr else "event-control-flow-v3.txt"
    collector = "collect-" + prefix + ".py"
    source = "tools/collect_esp32_zephyr_isr_control.py" if isr else "tools/collect_esp32_zephyr_events_control_v3.py"
    if isr and isr_os == "riot":
        source = "tools/collect_esp32_zephyr_isr_riot_control.py"
    elif isr and isr_os == "nuttx":
        source = "tools/collect_esp32_zephyr_isr_nuttx_control.py"
    marker = "ISR CONTROL" if isr else "EVENT CONTROL"
    check_manifest(directory, prefix + ".sha256")
    names = {line.split(maxsplit=1)[1] for line in (directory / (prefix + ".sha256")).read_text().splitlines()}
    if names != {"application.elf", "image.sha256", "capture.sha256", output, collector} or \
            (directory / collector).read_bytes() != (ROOT / source).read_bytes():
        raise ValueError("event branch supplement/image/source binding differs")
    expected = {"int_to_thread", "alt_thread_entry", "start_thread_entry", "test_isr", "software_isr",
                "irq_offload", "k_sem_give", "k_sem_take", "controller_entry", "espos_isr_enter",
                "espos_isr_exit", "krhino_intrpt_exit"} if isr else {
                    "event_ops_entry", "start_thread_entry", "alt_thread_entry", "event_wait", "k_event_set"}
    if isr and isr_os == "riot":
        expected = RIOT_ISR_CONTROL
    elif isr and isr_os == "nuttx":
        expected = NUTTX_ISR_CONTROL
    return read_control_rows((directory / output).read_text(), marker, elf, symbols, expected)


def read_control_rows(control, marker, elf, symbols, expected, *, noreturn=(), indirect_targets=None):
    result, entries, outgoing = {}, {}, {}
    for name, entry, text in re.findall(r"^" + marker + r" ([\w.$]+) ([0-9a-f]+)\n(.*?)(?=^" + marker + r" |\Z)",
                                       control, re.M | re.S):
        symbol = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
        start, end, entry = symbol["st_value"], symbol["st_value"] + symbol["st_size"], int(entry, 16)
        if not start <= entry < end or entry in entries.setdefault(name, set()):
            raise ValueError("event control block outside original/native body or duplicated")
        entries[name].add(entry)
        rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", text, re.M)
        if not rows or int(rows[0][0], 16) != entry:
            raise ValueError("event branch disassembly start differs")
        section = elf.get_section(symbol["st_shndx"])
        data, base, position = section.data(), section["sh_addr"], entry
        targets, terminated = set(), False
        for address, encoding, instruction in rows:
            address = int(address, 16)
            encoded = bytes.fromhex(encoding)[::-1]
            if address != position or not start <= address < end or address + len(encoded) > end or \
                    data[address - base:address - base + len(encoded)] != encoded:
                raise ValueError("event branch instruction bytes/coverage differ from frozen ELF")
            row = f"{address:x}: {encoding} {instruction}"
            body = result.setdefault(name, {})
            if address in body and body[address] != row:
                raise ValueError("conflicting repeated control instruction")
            body[address] = row
            position += len(encoded)
            call = re.fullmatch(r"call(0|8)\s+([0-9a-f]+) <([\w.$]+)>", instruction)
            if call and call[3] in noreturn:
                callee = max(symbols.get_symbol_by_name(call[3]), key=lambda row: row["st_size"])
                value = int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if value & 0x3f != (0x05 if call[1] == "0" else 0x25) or (address & ~3) + 4 + offset * 4 != callee["st_value"] or \
                        int(call[2], 16) != callee["st_value"]:
                    raise ValueError("noreturn control terminator encoded target differs")
                terminated = True
                break
            if indirect_targets and (name, address) in indirect_targets:
                if instruction != "jx\ta8" or encoding != "0008a0":
                    raise ValueError("native indirect control jump encoding differs")
                targets.update(indirect_targets[name, address])
                terminated = True
                break
            branch = re.match(r"(j|b[\w.]+|loop[\w.]*)" +
                              r"\s+.*?([0-9a-f]+) <" + re.escape(name) + r"(?:\+0x[0-9a-f]+)?>$", instruction)
            if branch:
                targets.add(int(branch[2], 16))
                if branch[1] != "j":
                    targets.add(position)
                terminated = True
                break
            if re.match(r"ret(?:w)?(?:\.n)?\b", instruction):
                terminated = True
                break
        if not terminated or position != int(rows[-1][0], 16) + len(rows[-1][1]) // 2:
            raise ValueError("event control block termination differs")
        outgoing.setdefault(name, {})[entry] = targets
    if set(result) != expected:
        raise ValueError("event control-flow functions incomplete")
    for name in expected:
        start = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])["st_value"]
        reached, pending = set(), [start]
        while pending:
            entry = pending.pop()
            if entry in reached:
                continue
            if entry not in outgoing[name]:
                raise ValueError("reachable event branch not decoded")
            reached.add(entry)
            pending.extend(outgoing[name][entry])
        if reached != entries[name]:
            raise ValueError("unreachable event control block")
    return result


def capture(directory, index, os, *, yield_subset=False, condvar_subset=False, events_subset=False, isr_subset=False):
    if sum((yield_subset, condvar_subset, events_subset, isr_subset)) > 1:
        raise ValueError("mixed original subsets")
    tags = ISR_TAGS if isr_subset else EVENT_TAGS if events_subset else CONDVAR_TAGS if condvar_subset else YIELD_TAGS if yield_subset else TAGS
    rows = read_raw_capture(directory, index)
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    if yield_subset or condvar_subset or events_subset or isr_subset:
        if any(line.startswith("THREAD ") for line in lines):
            raise ValueError("lifecycle UART substituted for yield subset")
        prefix = "ISR " if isr_subset else "EVENTS " if events_subset else "CONDVAR " if condvar_subset else "YIELD "
        lines = ["THREAD " + line[len(prefix):] if line.startswith(prefix) else line for line in lines]
        if condvar_subset:
            lines = [line.replace("THREAD NATIVE JOIN ", "THREAD NATIVE RETIRE ") for line in lines]
    tick = "native-tickless" if os == "riot" else "1"
    begin = f"THREAD PORT BEGIN {LABELS[os]} Zephyr-3.7.0-subset iterations=1000 clock=240 cores=1 tick={tick} stack=1792"
    if lines.count(begin) != 1 or lines.count("THREAD PORT END") != 1 or lines[-1] != "THREAD PORT END" or \
            sum("rst:0x" in line for line in lines) != 1 or any(re.search(
                r"THREAD PORT FAIL|FAILED|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("native reset/profile/completion differs")
    if os == "freertos":
        if sum("2nd stage bootloader" in line for line in lines) != 1 or \
                sum("main_task: Calling app_main()" in line for line in lines) != 1 or \
                sum("cpu freq: 240000000 Hz" in line for line in lines) != 1 or not any(
                "ELF file SHA256:  " + digest(directory / "application.elf")[:9] + "..." in line for line in lines):
            raise ValueError("native boot/clock/full ELF fingerprint differs")
        retire = [match.groups() for line in lines if (match := re.fullmatch(r"THREAD NATIVE RETIRE before=(\d+) after=(\d+)", line))]
        if len(retire) != 1 or retire[0][0] != retire[0][1] or int(retire[0][0]) < 2:
            raise ValueError("native task registry not restored")
    elif os in ("riot", "nuttx"):
        if os == "riot" and (lines.count("main(): This is RIOT! (Version: 2024.10-devel)") != 1 or lines.count("Single core mode") != 1):
            raise ValueError("native RIOT boot/version/core differs")
        if os == "nuttx":
            if lines.count("NuttShell (NSH) NuttX-12.2.1") != 1 or lines.count("THREAD NATIVE VERSION NuttX 12.2.1") != 1 or \
                    sum("2nd stage bootloader" in line for line in lines) != 1:
                raise ValueError("native NuttX boot/version differs")
            data, segments, offset = (directory / "application.bin").read_bytes(), [], 24
            for _ in range(data[1]):
                address, size = struct.unpack_from("<II", data, offset)
                segments.append((address, size))
                offset += size + 8
            observed = [(int(n), int(address, 16), int(size)) for line in lines if (match := re.search(
                r"esp_image: segment (\d+): paddr=[0-9a-f]+ vaddr=([0-9a-f]+) size=[0-9a-f]+h \(\s*(\d+)\)", line))
                for n, address, size in [match.groups()]]
            if observed != [(i, address, size) for i, (address, size) in enumerate(segments)]:
                raise ValueError("native NuttX boot image segment binding differs")
        retire = [match.groups() for line in lines if (match := re.fullmatch(r"THREAD NATIVE RETIRE before=(\d+) after=(\d+)", line))]
        if len(retire) != 1 or retire[0][0] != retire[0][1] or int(retire[0][0]) < 2:
            raise ValueError("native thread registry not restored")
    else:
        retire = None
        if lines.count("Welcome to AliOS Things") != 1 or lines.count("bootload image") != 1 or \
                lines.count("THREAD NATIVE TICK divisor=240000000") != 1:
            raise ValueError("native boot/hardware timer differs")
    overheads = [int(match[1]) for line in lines if (match := re.fullmatch(r"THREAD ORIGINAL TIMESTAMP_OVERHEAD (\d+) cycles", line))]
    if len(overheads) != 1 or not 0 < overheads[0] < 2 ** 32:
        raise ValueError("original timestamp calibration missing")
    pending, inputs, metrics = None, None, {}
    for line in lines:
        if isr_subset and (match := re.fullmatch(r"THREAD ORIGINAL ADJUSTMENT phase=(\d+) irq_calls=(\d+) overhead=(\d+)", line)):
            if pending is not None or inputs is not None:
                raise ValueError("original ISR adjustment order differs")
            phase, irq_calls, overhead = map(int, match.groups())
            if phase != len(metrics) + 1 or irq_calls != phase * 1000:
                raise ValueError("original ISR loop/context counts differ")
            pending = {"overhead": overhead, "phase": phase, "irq_calls": irq_calls}
        elif isr_subset and (match := re.fullmatch(r"THREAD ORIGINAL INPUT numerator=(\d+) count=(\d+) overhead=(\d+)", line)):
            numerator, count, overhead = map(int, match.groups())
            if pending is None or inputs is not None or overhead != pending["overhead"]:
                raise ValueError("unbound original ISR mean input")
            inputs = {"numerator": numerator, "count": count}
        elif (condvar_subset or events_subset) and (match := re.fullmatch(r"THREAD ORIGINAL INPUT numerator=(\d+) count=(\d+) raw=(\d+) overhead=(\d+)", line)):
            if pending is not None or inputs is not None:
                raise ValueError("unbound original condvar mean input")
            numerator, count, raw, overhead = map(int, match.groups())
            pending, inputs = {"raw": raw, "overhead": overhead}, {"numerator": numerator, "count": count}
        elif match := re.fullmatch(r"THREAD ORIGINAL RAW cycles=(\d+) overhead=(\d+)", line):
            if condvar_subset or events_subset:
                raise ValueError("unexpected subtraction trace in original condvar test")
            if pending is not None or inputs is not None:
                raise ValueError("original raw total/mean order differs")
            pending = dict(zip(("raw", "overhead"), map(int, match.groups())))
        elif match := re.fullmatch(r"THREAD ORIGINAL INPUT numerator=(\d+) count=(\d+)", line):
            if pending is None or inputs is not None:
                raise ValueError("unbound original mean input")
            inputs = dict(zip(("numerator", "count"), map(int, match.groups())))
        elif match := LATENCY.fullmatch(line):
            tag, _, cycles, ns = match.groups()
            if isr_subset:
                if pending is None or inputs is None or tag not in tags or tag in metrics or inputs["count"] != 1000 or \
                        pending["overhead"] != overheads[0] or not 0 < inputs["numerator"] < 2 ** 32 or \
                        int(cycles) != inputs["numerator"] // 1000 or int(ns) != inputs["numerator"] * 1000 // 240 // 1000:
                    raise ValueError("original ISR calibration/count/mean formula differs")
                metrics[tag] = {"mean_ns": int(ns), "mean_cycles": int(cycles), "original_input": {**pending, **inputs},
                                "unadjusted_accumulator_separately_captured": False}
                pending, inputs = None, None
                continue
            subtraction = tag in EVENT_TAGS[4:6] if events_subset else not condvar_subset
            if pending is None or inputs is None or tag not in tags or tag in metrics or inputs["count"] != 1000 or \
                    not 0 < pending["raw"] < 2 ** 32 or pending["overhead"] != overheads[0] or \
                    not 0 < inputs["numerator"] == pending["raw"] - (pending["overhead"] if subtraction else 0) or \
                    int(cycles) != inputs["numerator"] // 1000 or int(ns) != inputs["numerator"] * 1000 // 240 // 1000:
                raise ValueError("original calibration/subtraction/count/mean formula differs")
            metrics[tag] = {"mean_ns": int(ns), "mean_cycles": int(cycles), "original_input": {**pending, **inputs}}
            pending, inputs = None, None
    if tuple(metrics) != tags or pending is not None or inputs is not None:
        raise ValueError("original lifecycle case sequence incomplete")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "metrics": metrics,
            "timestamp_overhead_cycles": overheads[0], "native_registry": retire,
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory, os, verify_upstream=False, *, yield_subset=False, events_subset=False, isr_subset=False):
    if sum((yield_subset, events_subset, isr_subset)) > 1 or (isr_subset and os not in ("freertos", "alios", "riot", "nuttx")):
        raise ValueError("mixed original test subsets")
    port = ROOT / "firmware/bsp/esp32/zephyr_latency_isr" if isr_subset else ROOT / "firmware/bsp/esp32/zephyr_latency_events" if events_subset else \
        ROOT / "firmware/bsp/esp32/zephyr_latency_yield" if yield_subset else PORT
    originals = ("int_to_thread.c", *ORIGINALS[1:]) if isr_subset else ("events.c", *ORIGINALS[1:]) if events_subset else ("thread_switch_yield.c", *ORIGINALS[1:]) if yield_subset else ORIGINALS
    tags = ISR_TAGS if isr_subset else EVENT_TAGS if events_subset else YIELD_TAGS if yield_subset else TAGS
    native = {"freertos": ISR_NATIVE, "alios": ISR_NATIVE_ALIOS, "riot": ISR_NATIVE_RIOT, "nuttx": ISR_NATIVE_NUTTX}[os] if isr_subset else EVENT_NATIVE[os] if events_subset else NATIVE[os] + (("sched/sched/sched_yield.c",) if yield_subset and os == "nuttx" else ())
    upstream = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/" if isr_subset and os == "freertos" else UPSTREAM[os]
    app_name = "zephyr_isr" if isr_subset else "zephyr_events" if events_subset else "zephyr_yield" if yield_subset else "zephyr_thread"
    for name in ("image.sha256", "capture.sha256"):
        check_manifest(directory, name)
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "image.sha256").read_text().splitlines()}
    if not {"application.elf", "application.bin", "application.map", "config", "compiler.txt", "build.log",
            "bootloader.bin", "partitions.bin", "port.c", "include/zephyr/kernel.h", "disassembly.txt", *(
                "source/" + name for name in originals), *("native-source/" + name for name in native)} <= names:
        raise ValueError("original/native source/build/image coverage incomplete")
    names = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= names:
        raise ValueError("acquisition evidence coverage incomplete")
    proof = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in originals:
        if proof["src/" + name]["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["src/" + name]["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original lifecycle body/statistics changed")
    selected_port = port / os if os in ("riot", "nuttx") or (isr_subset and os == "alios") else port
    for name in ("port.c", "include/zephyr/kernel.h"):
        if (directory / name).read_bytes() != (selected_port / name).read_bytes():
            raise ValueError("native adapter differs from inspected source")
    for path in (port / os).rglob("*"):
        if path.is_file() and path.read_bytes() != (directory / "build-files" / path.relative_to(port / os)).read_bytes():
            raise ValueError("native application build selection changed")
    for path in SHARED.rglob("*"):
        if path.is_file() and path.relative_to(SHARED).as_posix() != "zephyr/kernel.h" and \
                path.read_bytes() != (directory / "include" / path.relative_to(SHARED)).read_bytes():
            raise ValueError("original timing/format adapter changed")
    path = directory / "official-native-source.json"
    if verify_upstream:
        sources = []
        for name in native:
            with urlopen(upstream + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(directory / "native-source" / name):
                raise ValueError(("native lifecycle source differs from fixed official revision", name))
            sources.append({"path": name, "url": upstream + name, "sha256": sha})
        path.write_text(json.dumps(sources, indent=2) + "\n")
    sources = json.loads(path.read_text())
    if len(sources) != len(native) or {row["path"] for row in sources} != set(native) or any(
            row["url"] != upstream + row["path"] or row["sha256"] != digest(directory / "native-source" / row["path"])
            for row in sources):
        raise ValueError("native lifecycle source provenance differs")
    config, compiler = (directory / "config").read_text(), (directory / "compiler.txt").read_text()
    if COMPILERS[os] not in compiler:
        raise ValueError("native toolchain profile differs")
    if os == "freertos":
        if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y",
                "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000"} <= set(config.splitlines()) or not re.search(
                r"#define configUSE_TIME_SLICING\s+0\b", (directory / "FreeRTOSConfig.h").read_text()):
            raise ValueError("native scheduler/clock/core/tick profile differs")
        commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
    elif os == "riot":
        for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                            ("THREAD_PRIORITY_MAIN", 10), ("MODULE_CORE_THREAD", 1), ("MODULE_SEMA", 1)):
            if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
                raise ValueError("native RIOT core/clock/thread/semaphore profile differs")
        if "MODULE_SCHED_ROUND_ROBIN" in config or "MODULE_CORE_MUTEX_PRIORITY_INHERITANCE" in config:
            raise ValueError("native RIOT tickless/FIFO profile differs")
        commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                    if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    elif os == "nuttx":
        required = {"CONFIG_BUILD_FLAT=y", "CONFIG_EXAMPLES_" + app_name.upper() + "=y", "CONFIG_USEC_PER_TICK=1000000",
                    "CONFIG_RR_INTERVAL=0", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_SIG_SIGSTOP_ACTION=y"}
        if not required <= set(config.splitlines()) or {"CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y", "CONFIG_MM_KERNEL_HEAP=y"} & \
                set(config.splitlines()) or 'CONFIG_VERSION_STRING="12.2.1"' not in (directory / "version-metadata").read_text() or \
                not re.search(r'#define CONFIG_VERSION_STRING\s+"12.2.1"', (directory / "version-header.h").read_text()):
            raise ValueError("native NuttX task-group/FIFO/clock/tick/version profile differs")
        commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                    if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    else:
        if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="' + app_name + '"', 'AOS_APP_' + app_name.upper() + '=y'} <= set(config.splitlines()):
            raise ValueError("native application selection differs")
        commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                    if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    for name in (*originals[:2], "port.c", *(name for name in native if name.endswith(".c"))):
        app_suffix = "app-" + os + "/" if os in ("freertos", "riot") else "app/example/" + app_name + "/"
        suffix = app_suffix + name if name in (*originals[:2], "port.c") else name
        if isr_subset and name.startswith("components/freertos/"):
            suffix = name.removeprefix("components/freertos/")
        if os == "nuttx":
            selected = [args for args in commands if Path(args[0]).name == "xtensa-esp32-elf-gcc" and any(
                not arg.startswith("-") and Path(arg).name == Path(name).name for arg in args) and
                (not name.startswith("sched/") or "-D__KERNEL__" in args)]
        else:
            selected = [args for args in commands if Path(args[0]).name == "xtensa-esp32-elf-gcc" and any(
                not arg.startswith("-") and (arg.endswith("/" + suffix) or arg == suffix) for arg in args)]
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("original/native lifecycle compilation differs", name))
        if name in (*originals[:2], "port.c") and os in ("freertos", "alios") and "-DTHREAD_OS_" + os.upper() not in selected[0]:
            raise ValueError("native adapter branch not compiled")
        if os == "riot" and name in (*originals[:2], "port.c") and "-DTHREAD_PRIORITY_MAIN=10" not in selected[0]:
            raise ValueError("native RIOT controller priority differs")
        if os == "alios" and "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0]:
            raise ValueError("native C tick override missing")
    divisors = None
    if isr_subset and os == "riot":
        if "#define MODULE_ZTIMER_USEC 1" not in config:
            raise ValueError("native RIOT tickless preparation timer missing")
        for name in ("portasm.S", "xtensa_vectors.S"):
            selected = [args for args in commands if any(arg.endswith("/" + name) for arg in args)]
            if len(selected) != 1:
                raise ValueError("native RIOT interrupt vector/exit not compiled")
    if os == "alios":
        for name in ("portasm.S", "xtensa_vectors.S"):
            selected = [args for args in commands if any(arg.endswith("/" + name) for arg in args)]
            if len(selected) != 1 or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0]:
                raise ValueError("native assembler tick override missing")
        divisors = hardware_tick_divisors(directory)
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    disassembly = (directory / "disassembly.txt").read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        event_rows = event_control_rows(directory, disassembly, elf, symbols, isr=isr_subset, isr_os=os) if \
            events_subset or (isr_subset and os in ("alios", "riot", "nuttx")) else {}

        def body(name):
            found = symbols.get_symbol_by_name(name)
            if not found:
                raise ValueError(("native/original entry not linked", name))
            symbol = max(found, key=lambda row: row["st_size"])
            match = re.search(r"^" + format(symbol["st_value"], "x") + r" <" + re.escape(name) + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
            assembler_entry = yield_subset and os == "freertos" and name in ("vPortYield", "_frxt_dispatch")
            if symbol["st_shndx"] == "SHN_UNDEF" or (not symbol["st_size"] and not assembler_entry) or not match:
                raise ValueError(("native/original body missing", name))
            return match[1]

        def calls(name, target, count=None, window=8):
            text = body(name) + "\n" + "\n".join(event_rows.get(name, {}).values())
            rows = sorted(set(re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call" + str(window) + r"\s+([0-9a-f]+) <" + re.escape(target) + r">$", text, re.M)))
            if not rows or (count is not None and len(rows) != count):
                raise ValueError(("original/native timed operation not called", name, target))
            source = max(symbols.get_symbol_by_name(name), key=lambda row: row["st_size"])
            section = elf.get_section(source["st_shndx"])
            data, base = section.data(), section["sh_addr"]
            destination = max(symbols.get_symbol_by_name(target), key=lambda row: row["st_size"])["st_value"]
            for address, encoding, label in rows:
                address, value = int(address, 16), int(encoding, 16)
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                if data[address - base:address - base + 3] != bytes.fromhex(encoding)[::-1] or value & 0x3f != 0x05 + window * 4 or \
                        (address & ~3) + 4 + offset * 4 != destination or int(label, 16) != destination:
                    raise ValueError("native/original call bytes or encoded target differ from frozen ELF")

        if not re.search(r"\brsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)", body("z_impl_timing_timestamp_get")):
            raise ValueError("original timestamp hook does not read CCOUNT")
        if isr_subset:
            calls("int_to_thread", "irq_offload", 1)
            calls("alt_thread_entry", "irq_offload", 1)
            calls("test_isr", "k_sem_give", 1)
            calls("test_isr", "z_impl_timing_timestamp_get", 1)
            calls("start_thread_entry", "k_sem_take", 2)
            calls("int_to_thread", "k_thread_create", 2)
            calls("int_to_thread", "__wrap_timestamp_overhead_adjustment", 2)
            calls("int_to_thread", "timing_cycles_to_ns_avg", 2)
            calls("int_to_thread", "original_tick_synch", 1)
            if os == "freertos":
                calls("original_tick_synch", "vTaskDelay", 1)
                calls("irq_offload", "xPortEnterCriticalTimeout", 1)
                calls("irq_offload", "vPortExitCritical", 1)
                calls("k_sem_give", "xQueueGiveFromISR", 1)
                calls("k_sem_give", "_frxt_setup_switch", 1)
                calls("software_isr", "xPortInIsrContext", 1)
                calls("app_main", "esp_intr_alloc", 1)
                calls("app_main", "esp_intr_free", 1)
            elif os == "alios":
                calls("original_tick_synch", "krhino_task_sleep", 1)
                calls("espos_isr_enter", "krhino_intrpt_enter", 1)
                calls("espos_isr_exit", "krhino_intrpt_exit", 1)
                calls("krhino_intrpt_exit", "cpu_intrpt_switch", 1)
                calls("k_sem_give", "krhino_sem_give", 1)
                calls("k_sem_take", "krhino_sem_take", 1)
                calls("controller_entry", "esp_intr_alloc", 1)
                calls("controller_entry", "esp_intr_free", 1)
            elif os == "riot":
                calls("original_tick_synch", "ztimer_sleep", 1)
                calls("irq_offload", "irq_disable", 1)
                calls("irq_offload", "irq_restore", 1)
                calls("software_isr", "irq_is_in", 1)
                calls("k_sem_give", "sema_post", 1)
                calls("k_sem_take", "_sema_wait_ztimer", 2)
                calls("sema_post", "mutex_unlock", 1)
                calls("mutex_unlock", "sched_switch", 1)
                calls("sched_switch", "irq_is_in", 1)
                calls("main", "xt_set_interrupt_handler", 2)
                calls("main", "xt_ints_on", 1)
                calls("main", "xt_ints_off", 1)
            else:
                calls("original_tick_synch", "nxsig_usleep", 1)
                calls("nxsig_usleep", "nxsig_nanosleep", 1)
                calls("nxsig_nanosleep", "nxsig_timedwait", 1)
                calls("k_sem_give", "sem_post", 1)
                calls("sem_post", "nxsem_post", 1)
                calls("nxsem_post", "nxsched_add_readytorun", 1)
                calls("nxsem_post", "up_switch_context", 1)
                calls("k_sem_take", "sem_trywait", 1)
                calls("sem_wait_checked", "sem_wait", 1)
                calls("zephyr_isr_main", "esp32_setup_irq", 1)
                calls("zephyr_isr_main", "irq_attach", 2)
                calls("zephyr_isr_main", "up_enable_irq", 1)
                calls("zephyr_isr_main", "up_disable_irq", 1)
                calls("zephyr_isr_main", "esp32_teardown_irq", 1)
                calls("xtensa_int_decode", "xtensa_irq_dispatch", 1)
                calls("xtensa_irq_dispatch", "irq_dispatch", 1)
            if not re.search(r"\bcallx8\b", body("software_isr") + "\n" +
                             "\n".join(event_rows.get("software_isr", {}).values())):
                raise ValueError("original ISR callback not dispatched by hardware handler")
        elif events_subset:
            for target in ("k_event_post", "k_event_set", "k_event_wait", "k_event_wait_all"):
                calls("event_ops_entry", target, 1)
            calls("event_ops_entry", "k_event_clear", 1)
            calls("start_thread_entry", "k_event_set", 1)
            calls("start_thread_entry", "k_event_post", 1)
            calls("alt_thread_entry", "k_event_wait", 1)
            calls("alt_thread_entry", "k_event_wait_all", 1)
            calls("event_ops", "timing_cycles_to_ns_avg", 4)
            calls("event_blocking_ops", "timing_cycles_to_ns_avg", 4)
            calls("event_blocking_ops", "__wrap_timestamp_overhead_adjustment", 2)
            calls("k_event_set", "k_event_clear", 1)
            calls("k_event_set", "k_event_post", 1)
            calls("event_wait", "k_event_clear", 1)
            if os == "freertos":
                calls("k_event_clear", "xEventGroupClearBits", 1)
                calls("k_event_post", "xEventGroupSetBits", 1)
                calls("event_wait", "xEventGroupWaitBits", 1)
                calls("k_event_set", "xPortEnterCriticalTimeout", 1)
                calls("k_event_set", "vPortExitCritical", 1)
            else:
                calls("k_event_clear", "krhino_event_set", 1)
                calls("k_event_post", "krhino_event_set", 1)
                calls("event_wait", "krhino_event_get", 1)
                calls("k_event_set", "krhino_sched_disable", 1)
                calls("k_event_set", "krhino_sched_enable", 1)
        elif yield_subset:
            calls("start_thread_entry", "k_yield")
            calls("alt_thread_entry", "k_yield")
            calls("start_thread_entry", "k_thread_start")
            calls("start_thread_entry", "k_thread_join")
            calls("thread_switch_yield", "k_thread_create", 2)
            calls("thread_switch_yield", "k_thread_join")
            calls("thread_switch_yield", "__wrap_timestamp_overhead_adjustment", 1)
            target = {"freertos": "vPortYield", "alios": "krhino_task_yield", "riot": "thread_yield", "nuttx": "sched_yield"}[os]
            calls("k_yield", target)
            if os == "freertos":
                calls("vPortYield", "_frxt_dispatch", 1, window=0)
                calls("_frxt_dispatch", "vTaskSwitchContext", 1, window=4)
            elif os == "nuttx":
                calls("sched_yield", "nxsched_set_priority", 1)
            elif os == "riot":
                calls("thread_yield", "thread_yield_higher", 1)
        else:
            for target in ("k_thread_create", "k_thread_start", "k_thread_resume", "k_thread_abort"):
                calls("start_thread_entry", target)
            calls("alt_thread_entry", "k_thread_suspend")
            calls("alt_thread_entry", "k_thread_priority_set")
            calls("thread_ops", "__wrap_timestamp_overhead_adjustment", 5)
        calls("__wrap_timestamp_overhead_adjustment", "timestamp_overhead_adjustment", 1)
        native_targets = {"freertos": ("xTaskCreateStaticPinnedToCore", "xTaskGenericNotify", "vTaskSuspend", "vTaskResume", "vTaskDelete"),
                          "alios": ("krhino_task_create", "krhino_task_resume", "krhino_task_suspend", "krhino_task_resume", "krhino_task_del"),
                          "riot": ("thread_create", "thread_wakeup", "thread_sleep", "thread_wakeup", "thread_kill_zombie"),
                          "nuttx": ("nxtask_init", "nxtask_activate", "kill", "kill", "task_delete")}[os]
        for operation, target in zip(("create", "start", "suspend", "resume", "abort"), native_targets):
            if (yield_subset or events_subset or isr_subset) and operation in ("suspend", "resume"):
                continue
            calls("k_thread_" + operation, target)
        if os == "riot":
            calls("k_thread_abort", "sched_set_status")
            if not yield_subset and not isr_subset:
                calls("k_thread_priority_set", "sched_change_priority")
            calls("thread_entry", "mutex_unlock_and_sleep")
        if os == "nuttx":
            if not yield_subset and not isr_subset:
                calls("k_thread_priority_set", "sched_setparam")
            calls("k_thread_abort", "nxsched_get_tcb")
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("installed image/board binding differs")
    captures = [capture(directory, i, os, yield_subset=yield_subset, events_subset=events_subset, isr_subset=isr_subset) for i in (1, 2, 3)]
    if any(datetime.fromisoformat(a["end_utc"]) >= datetime.fromisoformat(b["start_utc"]) for a, b in zip(captures, captures[1:])):
        raise ValueError("independent lifecycle boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in tags}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure original kernel " + ("preemptive yield subset" if yield_subset else "thread lifecycle subset"),
            "os": LABELS[os], "metric_count": len(tags), "resets": 3, "original_iterations": 1000, "metrics": metrics,
            "captures": captures, "clock_mhz": 240, "cores": 1, "tick_hz": "native-tickless" if os == "riot" else 1, "worker_stack_bytes": 1792,
            "compiler": COMPILERS[os], "hardware_tick_divisors": divisors,
            "original_source_files": 4, "native_source_files": len(native), "ranking_eligible": False,
            "unmodified_official_native_suite": False, "original_test_body_unchanged": True,
            "boundary": ("original 1000-iteration same-priority preemptive k_yield start-to-peer-timestamp sequence with original timestamp calibration/subtraction; native yield API and completion adapters; no cooperative or userspace cases; distinct native task representations, compiler and FIFO/tick profiles prevent cross-OS rank" if yield_subset else "original 1000-iteration create/start/self-suspend/resume/noncurrent-abort sequence and subtraction means; native completion adapters; FreeRTOS notification deferred start, Rhino inactive creation, RIOT sleeping creation and composed queue/zombie retirement with TCB inside nominal stack; NuttX separate task groups, native-owned heap TCB, supplied static stack and SIGSTOP/SIGCONT job control; no userspace or cross-OS lifecycle rank")}


def render_table(results):
    lines = ["| Original Zephyr lifecycle subset / OS | Original case | Original means, ns (three boots) |", "| --- | --- | --- |"]
    for result in results:
        for tag in TAGS:
            lines.append(f"| Original lifecycle port / {result['os']} / {tag} | {tag} | " + " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("os", choices=LABELS)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.os, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
