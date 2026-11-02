#!/usr/bin/env python3
"""Audit original Zephyr software-IRQ return/wakeup bodies on native OS ports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from elftools.elf.elffile import ELFFile
from urllib.request import urlopen
from audit_esp32_zephyr_thread import audit as native_audit, capture, digest, ROOT, ISR_TAGS, ISR_NATIVE, UPSTREAM, event_control_rows
from audit_esp32_riot_original import check_manifest

TIMESTAMP_URL = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v3.7.0/subsys/testsuite/include/zephyr/timestamp.h"


def native_dispatch_binding(directory, *, os="riot", thread_metric=False):
    """Bind native deferred context switching and registration to ELF literals."""
    text = (directory / "disassembly.txt").read_text()
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if thread_metric and os != "riot":
            raise ValueError("Thread-Metric extension is specific to RIOT's native dispatch")
        control = {} if thread_metric else event_control_rows(directory, text, elf, symbols, isr=True, isr_os=os)

        def memory(address, size):
            sections = [section for section in elf.iter_sections() if section["sh_type"] != "SHT_NOBITS" and
                        section["sh_addr"] <= address and address + size <= section["sh_addr"] + section["sh_size"]]
            if len(sections) != 1:
                raise ValueError("RIOT native instruction/literal not mapped to ELF")
            section = sections[0]
            offset = address - section["sh_addr"]
            return section.data()[offset:offset + size]

        def bound_literals(name):
            symbol = symbols.get_symbol_by_name(name)[0]
            if name in control:
                rows = "\n".join(control[name].values())
            else:
                body = re.search(r"^" + format(symbol["st_value"], "x") + r" <" + name + r">:\n(.*?)(?=\n\n|\Z)", text, re.M | re.S)
                if not body:
                    raise ValueError("RIOT native exit body missing")
                rows = body[1]
            literals = []
            for address, encoding, instruction in re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", rows, re.M):
                address, value = int(address, 16), int(encoding, 16)
                if symbol["st_size"] and not symbol["st_value"] <= address < symbol["st_value"] + symbol["st_size"]:
                    continue
                if memory(address, len(encoding) // 2) != bytes.fromhex(encoding)[::-1]:
                    raise ValueError("RIOT native dispatch bytes differ")
                match = re.match(r"l32r\s+a(\d+), ([0-9a-f]+) <", instruction)
                if match:
                    offset = value >> 8
                    if offset & 0x8000:
                        offset -= 0x10000
                    target = ((address + 3) & ~3) + offset * 4
                    if value & 0xf != 1 or (value >> 4) & 0xf != int(match[1]) or target != int(match[2], 16):
                        raise ValueError("RIOT native literal encoded target differs")
                    literals.append(struct.unpack("<I", memory(target, 4))[0])
            return literals, rows

        if os == "nuttx":
            registers = symbols.get_symbol_by_name("g_current_regs")[0]["st_value"]
            switch_literals, switch_rows = bound_literals("up_switch_context")
            dispatch_literals, dispatch_rows = bound_literals("xtensa_irq_dispatch")
            handler_literals, _ = bound_literals("software_isr")
            main_literals, _ = bound_literals("zephyr_isr_main")
            delay_literals, _ = bound_literals("original_tick_synch")
            if any(registers not in values for values in (switch_literals, dispatch_literals, handler_literals)) or \
                    not re.search(r"s32i(?:\.n)?\s+a8, a9, 0", switch_rows) or \
                    not re.search(r"l32i(?:\.n)?\s+a2, a3, 0", dispatch_rows) or \
                    symbols.get_symbol_by_name("software_isr")[0]["st_value"] not in main_literals or \
                    1000000 not in delay_literals:
                raise ValueError("NuttX native IRQ context/return/registration/tick literal binding differs")
            return {"native_current_regs_address": registers, "native_preparation_sleep_requested_us": 1000000,
                    "native_irq_backend": "esp32_setup_irq/irq_attach; nxsem_post/up_switch_context; native IRQ return dispatch"}
        flag = symbols.get_symbol_by_name("sched_context_switch_request")[0]["st_value"]
        scheduler, scheduler_rows = bound_literals("sched_switch")
        exit_literals, exit_rows = bound_literals("_frxt_int_exit")
        main_literals, _ = bound_literals("tm_initialize" if thread_metric else "main")
        delay_literals = [] if thread_metric else bound_literals("original_tick_synch")[0]
        if flag not in scheduler or flag not in exit_literals or \
                not re.search(r"movi(?:\.n)?\s+a9, 1", scheduler_rows) or \
                not re.search(r"s32i(?:\.n)?\s+a9, a8, 0", scheduler_rows) or \
                not re.search(r"l32i(?:\.n)?\s+a3, a2, 0", exit_rows) or \
                not re.search(r"beqz(?:\.n)?\s+a3,", exit_rows) or \
                not re.search(r"s32i(?:\.n)?\s+a3, a2, 0", exit_rows) or \
                not re.search(r"call4\s+[0-9a-f]+ <vPortYieldFromInt>", exit_rows) or \
                not re.search(r"call0\s+[0-9a-f]+ <_frxt_dispatch>", exit_rows) or \
                symbols.get_symbol_by_name("software_isr")[0]["st_value"] not in main_literals or \
                not thread_metric and 1000000 not in delay_literals:
            raise ValueError("RIOT native deferred IRQ scheduling/registration/delay binding differs")
        if thread_metric:
            cause, cause_rows = bound_literals("tm_cause_interrupt")
            handler, handler_rows = bound_literals("software_isr")
            _, resume_rows = bound_literals("tm_thread_resume")
            _, vector_rows = bound_literals("_xt_lowint1")
            _, enter_rows = bound_literals("_frxt_int_enter")
            expected = "tm_interrupt_preemption_handler" if "tm_interrupt_preemption_handler" in handler_rows else "tm_interrupt_handler"
            if 0x3ff000e4 not in cause or 0x3ff000e4 not in handler or not re.search(
                    r"s32i(?:\.n)?\s+", cause_rows) or not re.search(r"s32i(?:\.n)?\s+", handler_rows):
                raise ValueError("Thread-Metric hardware trigger/acknowledgement differs")
            checked = 0
            for body, callee, abi in ((handler_rows, "irq_is_in", 8), (handler_rows, expected, 8),
                    (resume_rows, "thread_wakeup", 8), (vector_rows, "_frxt_int_enter", 0),
                    (vector_rows, "_frxt_int_exit", 0), (enter_rows, "_xt_context_save", 0),
                    (exit_rows, "_xt_context_restore", 0)):
                calls = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call" + str(abi) +
                                   r"\s+([0-9a-f]+) <" + callee + r">$", body, re.M)
                if len(calls) != 1:
                    raise ValueError("Thread-Metric native IRQ call missing: " + callee)
                address, encoding, target = (int(v, 16) for v in calls[0])
                displacement = encoding >> 6
                if displacement & (1 << 17): displacement -= 1 << 18
                if encoding & 0x3f != (0x25 if abi == 8 else 0x05) or (address & ~3) + 4 + displacement * 4 != target or \
                        not any(s["st_value"] == target for s in symbols.get_symbol_by_name(callee) or []):
                    raise ValueError("Thread-Metric native IRQ call encoding/target differs")
                checked += 1
            return {"native_switch_flag_address": flag, "encoded_adapter_calls_checked": checked,
                    "source_register": "0x3ff000e4", "callback": expected,
                    "native_deferred_switch": "sched_switch sets request; _frxt_int_exit tests/clears request and calls native dispatch",
                    "not_interrupt_entry_latency": True}
        return {"native_switch_flag_address": flag, "native_tickless_settling_delay_us": 1000000,
                "matrix_route_restoration_verified": False}


def irq_archive_member(archive, member=b"intr_alloc.o"):
    data = archive.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("native SDK is not an ar archive")
    position, matches = 8, []
    while position < len(data):
        header = data[position:position + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("native SDK member header malformed")
        size = int(header[48:58])
        start, end = position + 60, position + 60 + size
        if size < 0 or end + size % 2 > len(data):
            raise ValueError("native SDK member length malformed")
        if header[:16].strip().rstrip(b"/") == member:
            matches.append(data[start:end])
        position = end + size % 2
    if len(matches) != 1:
        raise ValueError("native SDK interrupt member absent or duplicated")
    return matches[0]


def rhino_vector_dispatch(directory, *, allow_literal_annotation=False):
    text = (directory / "disassembly.txt").read_text()
    match = re.search(r"^([0-9a-f]+) <_xt_lowint1>:\n(.*?)(?=\n\n|\Z)", text, re.M | re.S)
    if not match:
        raise ValueError("native Rhino hardware vector body absent")
    rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", match[2], re.M)
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        start = symbols.get_symbol_by_name("_xt_lowint1")[0]["st_value"]
        end = symbols.get_symbol_by_name("_xt_medint2")[0]["st_value"]
        if int(match[1], 16) != start:
            raise ValueError("native vector disassembly/ELF start differs")

        def memory(address, size):
            sections = [section for section in elf.iter_sections() if section["sh_type"] != "SHT_NOBITS" and
                        section["sh_addr"] <= address and address + size <= section["sh_addr"] + section["sh_size"]]
            if len(sections) != 1:
                raise ValueError("native vector instruction/literal not mapped to ELF")
            section = sections[0]
            offset = address - section["sh_addr"]
            return section.data()[offset:offset + size]

        bindings = {}
        for index, (address, encoding, instruction) in enumerate(rows[:-1]):
            suffix = r"(?: \([0-9a-f]+ <[^>]+>\))?" if allow_literal_annotation else ""
            literal = re.fullmatch(r"l32r\s+a4, ([0-9a-f]+) <[^>]+>" + suffix, instruction)
            if not literal or not re.fullmatch(r"callx4\s+a4", rows[index + 1][2]):
                continue
            address, value = int(address, 16), int(encoding, 16)
            offset = value >> 8
            if offset & 0x8000:
                offset -= 0x10000
            target_address = ((address + 3) & ~3) + offset * 4
            next_address, next_encoding = int(rows[index + 1][0], 16), rows[index + 1][1]
            if not start <= address < end or value & 0xff != 0x41 or target_address != int(literal[1], 16) or \
                    memory(address, 3) != bytes.fromhex(encoding)[::-1] or next_address != address + 3 or \
                    next_encoding != "0004d0" or memory(next_address, 3) != bytes.fromhex(next_encoding)[::-1]:
                raise ValueError("native Rhino indirect vector call bytes/target differ")
            destination = struct.unpack("<I", memory(target_address, 4))[0]
            for name in ("espos_isr_enter", "espos_isr_exit"):
                if destination == symbols.get_symbol_by_name(name)[0]["st_value"]:
                    if name in bindings:
                        raise ValueError("duplicated native vector nesting wrapper")
                    bindings[name] = address
        if set(bindings) != {"espos_isr_enter", "espos_isr_exit"} or bindings["espos_isr_enter"] >= bindings["espos_isr_exit"] or \
                sum(bindings["espos_isr_enter"] < int(address, 16) < bindings["espos_isr_exit"] and
                    re.fullmatch(r"callx4\s+a4", instruction) is not None for address, _, instruction in rows) != 2:
            raise ValueError("native vector enter/callback/exit ordering differs")
        return bindings


def capture_isr(directory, index, os="freertos"):
    result = capture(directory, index, os, isr_subset=True)
    lines = [json.loads(line)["line"] for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    sources = [line for line in lines if line.startswith("ISR NATIVE SOURCE ")]
    synch = "ISR ORIGINAL TICK_SYNCH native_tickless_sleep_us=1000000" if os == "riot" else "ISR ORIGINAL TICK_SYNCH native_ticks=1"
    if len(sources) != 1 or not re.fullmatch(r"ISR NATIVE SOURCE peripheral=26 requested_level=1 cpu=0 input=\d+", sources[0]) or \
            lines.count(synch) != 1 or \
            lines.count("ISR NATIVE COMPLETE irq_calls=2000 adjustments=2 means=2 released=1") != 1:
        raise ValueError("native ISR source/tick/count/release evidence differs")
    if not (lines.index(sources[0]) < next(i for i, line in enumerate(lines) if line.startswith("ISR PORT BEGIN ")) <
            lines.index(synch) <
            next(i for i, line in enumerate(lines) if line.startswith("ISR ORIGINAL ADJUSTMENT "))):
        raise ValueError("native ISR setup/tick/sample order differs")
    result.update(native_interrupt_source=26, requested_interrupt_level=1,
                  native_cpu_input=int(sources[0].split("input=")[1]), actual_handler_calls=2000)
    if os == "riot" and result["native_cpu_input"] != 0:
        raise ValueError("native RIOT fixed level-1 IRQ input differs")
    if os == "nuttx" and result["native_cpu_input"] != 1:
        raise ValueError("native NuttX frozen-profile level-1 IRQ input differs")
    if os == "alios":
        if lines.count("ISR NATIVE NEST restored=0 arch=0 workers_retired=1") != 1:
            raise ValueError("native Rhino ISR nesting/worker retirement differs")
        result["native_arch_and_kernel_interrupt_nesting_restored"] = True
    return result


def audit(directory, verify_upstream=False, *, os="freertos"):
    result = native_audit(directory, os, verify_upstream, isr_subset=True)
    if os == "freertos":
        check_manifest(directory, "compiled-native.sha256")
        names = {line.split(maxsplit=1)[1] for line in (directory / "compiled-native.sha256").read_text().splitlines()}
        if names != {"application.elf", "image.sha256", "capture.sha256", "compile_commands.json", "collect-native.py", *(
                "compiled-native-source/" + name for name in ISR_NATIVE)} or \
                (directory / "collect-native.py").read_bytes() != (ROOT / "tools/collect_esp32_zephyr_isr_native.py").read_bytes() or any(
                    (directory / "compiled-native-source" / name).read_bytes() != (directory / "native-source" / name).read_bytes()
                    for name in ISR_NATIVE):
            raise ValueError("actual native compilation/image/capture binding differs")
    elif os == "alios":
        library = "platform/mcu/esp32/lib/libesp32.a"
        archive = directory / "native-source" / library
        library_proof = directory / "official-sdk-source.json"
        url = UPSTREAM["alios"] + library
        if verify_upstream:
            with urlopen(url, timeout=60) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(archive):
                raise ValueError("native SDK interrupt archive differs from fixed official revision")
            library_proof.write_text(json.dumps({"url": url, "sha256": sha}, indent=2) + "\n")
        if json.loads(library_proof.read_text()) != {"url": url, "sha256": digest(archive)} or \
                irq_archive_member(archive) != (directory / "sdk-intr_alloc.o").read_bytes():
            raise ValueError("native SDK interrupt archive/member differs")
        map_text = (directory / "application.map").read_text()
        if "platform/mcu/esp32/lib/libesp32.a" not in (directory / "link.opts").read_text() or \
                "libesp32.a(intr_alloc.o)" not in map_text or any(not re.search(
                    r"\.text\." + name + r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*libesp32\.a\(intr_alloc\.o\)", map_text)
                    for name in ("esp_intr_alloc", "esp_intr_free", "esp_intr_get_cpu", "esp_intr_get_intno")):
            raise ValueError("native SDK interrupt member not bound to linked firmware")
        result["prebuilt_native_irq_archive_sha256"] = digest(archive)
        result["prebuilt_native_irq_archive_source_rebuilt"] = False
        result["native_vector_indirect_nesting_calls"] = rhino_vector_dispatch(directory)
    elif os == "riot":
        result.update(native_dispatch_binding(directory))
    else:
        result.update(native_dispatch_binding(directory, os="nuttx"))
    timestamp = directory / "native-source/zephyr-timestamp.h"
    proof_path = directory / "official-timestamp-source.json"
    if verify_upstream:
        with urlopen(TIMESTAMP_URL, timeout=30) as response:
            sha = hashlib.sha256(response.read()).hexdigest()
        if sha != digest(timestamp):
            raise ValueError("original tick synchronization header changed")
        proof_path.write_text(json.dumps({"url": TIMESTAMP_URL, "sha256": sha}, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if proof != {"url": TIMESTAMP_URL, "sha256": digest(timestamp)} or \
            "#define TICK_SYNCH()  k_sleep(K_TICKS(1))" not in timestamp.read_text():
        raise ValueError("original tick synchronization source binding differs")
    suffix = "_" + os if os in ("alios", "riot", "nuttx") else ""
    if (directory / "build-script.sh").read_bytes() != (ROOT / ("tools/build_esp32_zephyr_isr" + suffix + ".sh")).read_bytes() or \
            (directory / "runner.sh").read_bytes() != (ROOT / ("tools/run_esp32_zephyr_isr" + suffix + ".sh")).read_bytes() or \
            (directory / "include/zephyr/irq_offload.h").read_bytes() != \
            (ROOT / "firmware/bsp/esp32/zephyr_latency_isr/include/zephyr/irq_offload.h").read_bytes():
        raise ValueError("native ISR build/run/interface differs")
    result["captures"] = [capture_isr(directory, index, os) for index in (1, 2, 3)]
    result.update(benchmark="Zephyr 3.7.0 original software-IRQ kernel return/wakeup subset",
                  actual_handler_calls_per_boot=2000, software_generated_interrupt=True,
                  external_gpio_interrupt_entry_measured=False,
                  unadjusted_accumulator_separately_captured=False,
                  original_tick_synchronization_header_sha256=digest(timestamp),
                  original_one_native_tick_synchronization_preserved=os in ("freertos", "alios"),
                  boundary="unchanged original int_to_thread.c, two kernel cases, 1000 iterations and mean/calibration subtraction; actual native CPU_FROM_CPU2 peripheral 26 level-1 IRQ, native ISR give and deferred high-priority reschedule, not a direct C callback or external GPIO entry test; start timestamp is after ISR semaphore give, excluding the give and IRQ entry; interrupted return includes native critical-exit/synchronous completion checks; original one-native-tick synchronization preserved; measured post-subtraction mean inputs captured, unadjusted accumulator not separately observed or reconstructed as raw evidence; static semaphore lazy initialization outside the ISR and measured wake loop, native worker registry restored; no full suite, generic irq_offload or cross-OS rank")
    if os == "alios":
        result["boundary"] = result["boundary"].replace("native worker registry restored", "original worker creation flags retired and native architecture/kernel ISR nesting restored; no total task-registry census") + \
            "; Rhino existing vector calls ESPOS/native kernel enter before the timestamp and exit/deferred rescheduling after it; adapter does not duplicate kernel nesting; post-callback restoration checks retained; GCC5 and native 1-Hz assembly profile; SDK IRQ allocator is a fixed official prebuilt archive/member, not source rebuilt"
        result["isr_control_flow_sha256"] = digest(directory / "isr-control-flow-v2.txt")
        result["excluded_initial_firmware"] = {
            "v1": "archive collection failure; never flashed or measured",
            "v2": "45-second reset-loop diagnostic rejected; incorrect pre-callback nesting expectation; zero original means",
            "v3": "diagnostic build only; never flashed or measured"}
    if os == "riot":
        result["boundary"] = result["boundary"].replace("original one-native-tick synchronization preserved",
            "RIOT has no native periodic kernel tick; original TICK_SYNCH preparation changed to native ztimer 1000000-us settling sleep, not original kernel-tick phase alignment") + \
            "; RIOT native sema_post/mutex_unlock/sched_switch sets the native ISR exit switch flag; input 0 disabled and handler cleared after measurement, interrupt matrix route not restored; GCC12.2 native tickless profile; no equal-method or cross-OS rank claim"
        result["isr_control_flow_sha256"] = digest(directory / "isr-control-flow-v2.txt")
        result["excluded_initial_firmware"] = {"v1": "source archival path failed after build; never flashed or measured"}
    if os == "nuttx":
        result["native_preparation_one_tick_timeout_requested"] = True
        result["boundary"] = result["boundary"].replace("original one-native-tick synchronization preserved",
            "one-native-tick preparation timeout requested via NuttX signal sleep; original Zephyr preparation synchronization not claimed identical") + \
            "; NuttX 12.2.1 flat task-group profile, native heap TCBs and 1792-byte supplied stacks, SIGSTOP completion parking outside timed loops, SEM_PRIO_NONE signaling; nxsig_usleep/nxsig_nanosleep/nxsig_timedwait native tick rounding extends physical preparation; synchronous offload includes a bounded pending-IRQ completion spin, not subtracted; native allocator setup/attach and disable/detach/teardown calls retained, not complete heap/peripheral census; GCC13.2/FIFO/1-Hz profile"
        result["isr_control_flow_sha256"] = digest(directory / "isr-control-flow-v2.txt")
        result["excluded_initial_firmware"] = {"v1": "configuration rejected absent optional condvar application symbol; no compilation, flash or measurement",
            "v2": "first reset rejected premature offload completion check before original means; diagnostic only"}
    return result


def render_table(result):
    lines = ["| Original Zephyr software-IRQ subset / OS | Original case | Original means, ns (three boots) |", "| --- | --- | --- |"]
    for tag in ISR_TAGS:
        lines.append(f"| Original software-IRQ port / {result['os']} / {tag} | {tag} | " +
                     " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--os", choices=("freertos", "alios", "riot", "nuttx"), default="freertos")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.verify_upstream, os=args.os), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
