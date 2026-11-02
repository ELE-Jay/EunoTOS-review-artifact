#!/usr/bin/env python3
"""Audit native FreeRTOS allocation/task lifetimes, not whole live-RAM scores."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from build_esp32_freertos_ram_lifetimes import native_edits, patched
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_hartstone_series import audit as series
from audit_esp32_resources import audit_elf_image, static_footprint
from audit_esp32_ram_census import region_accounting
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
REFERENCE = ROOT / "artifacts/reports/hartstone-native-us-fifo-v1/freertos/ph4"
UPSTREAM = "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/components/"
TLSF_COMMIT = "d2e28f872472ffc6a704faae65ddee1f24e2dfba"
TLSF_PIN = "https://api.github.com/repos/espressif/esp-idf/contents/components/heap/tlsf?ref=v5.2.5"
NATIVE = tuple("freertos/" + n for n in (
    "FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
    "FreeRTOS-Kernel/portable/xtensa/include/freertos/portmacro.h", "heap_idf.c")) + tuple(
    "heap/" + n for n in (*native_edits(), "multi_heap_platform.h", "include/multi_heap.h",
                          "include/esp_heap_caps.h", "tlsf/tlsf.h", "tlsf/tlsf_common.h", "tlsf/tlsf_block_functions.h"))


def upstream(name):
    return ("https://raw.githubusercontent.com/espressif/tlsf/" + TLSF_COMMIT + "/" + name.removeprefix("heap/tlsf/")
            if name.startswith("heap/tlsf/") else UPSTREAM + name)


def source_path(folder, name):
    return folder / ("original-native" if name in {"heap/" + n for n in native_edits()} else "native-source") / name


def provenance(folder):
    pin_path = folder / "official-tlsf-pin.json"
    if pin_path.exists():
        pin = json.loads(pin_path.read_text())
    else:
        with urlopen(TLSF_PIN, timeout=60) as response:
            pin = json.load(response)
    if pin["sha"] != TLSF_COMMIT or pin["submodule_git_url"] != "../../espressif/tlsf.git":
        raise ValueError("Official IDF TLSF submodule pin differs")
    pin_path.write_text(json.dumps(pin, indent=2) + "\n")
    rows = []
    for name in NATIVE:
        with urlopen(upstream(name), timeout=60) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        if digest != sha(source_path(folder, name)):
            raise ValueError("Native source differs from pinned official ESP-IDF: " + name)
        rows.append({"path": name, "url": upstream(name), "sha256": digest})
    (folder / "official-native-source.json").write_text(json.dumps(rows, indent=2) + "\n")


def reachable_call8(folder, source, image):
    """Decode reachable instructions at their own PCs instead of through dead padding."""
    import shlex
    import subprocess
    compiler = shlex.split(json.loads((folder / "compile_commands.json").read_text())[0]["command"])[0]
    objdump = compiler.removesuffix("gcc") + "objdump"
    start, end = source["st_value"], source["st_value"] + source["st_size"]
    pending, visited, result = [start], set(), []
    while pending:
        pc = pending.pop()
        if pc in visited or pc == end:
            continue
        if not start <= pc < end or len(visited) > 4096:
            raise ValueError("Native caller control flow escapes its function")
        visited.add(pc)
        text = subprocess.check_output([objdump, "-d", "--start-address=" + hex(pc),
            "--stop-address=" + hex(min(end, pc + 3)), str(image)]).decode()
        found = re.search(r"^%x:\s+([0-9a-f]+)\s+(\S+)\s*(.*)$" % pc, text, re.M)
        if not found:
            raise ValueError("Cannot decode reachable native caller")
        word, op, args = found.groups()
        noreturn = op.startswith('call') and any('<' + name + '>' in args for name in (
            '__assert_func', 'abort', 'esp_system_abort', 'panic_abort'))
        args = args.split(" <")[0]
        if op == 'call8':
            result.append((format(pc, 'x'), word, args, 'reachable-control-flow'))
        if op.startswith('ret') or op in ('jx', 'break') or noreturn:
            continue
        if op in ('.byte', 'ill'):
            raise ValueError("Undecodable reachable native instruction")
        if op == 'j' or op.startswith(('b', 'loop')):
            pending.append(int(args.split(', ')[-1], 16))
        if op != 'j':
            pending.append(pc + len(word) // 2)
    return result


def calls(folder, required=None, require_iram=True, supplemental="", elf_name="application.elf", disassembly_name="disassembly.txt"):
    defaults = [("multi_heap_register_impl", "bench_heap_register"),
        ("multi_heap_internal_unlock", "bench_heap_check"),
        ("tlsf_malloc", "bench_prepare_used"), ("tlsf_memalign_offs", "bench_prepare_used"),
        ("bench_prepare_used", "bench_tlsf_delta"), ("tlsf_free", "bench_tlsf_delta"),
        ("tlsf_realloc", "bench_tlsf_delta"), ("tlsf_realloc", "tlsf_malloc"),
        ("prvAddNewTaskToReadyList", "bench_life_create"), ("vTaskDelete", "bench_life_request"),
        ("prvDeleteTCB", "__wrap_vPortTCBPreDeleteHook"),
        ("prvIdleTask", "prvDeleteTCB"), ("prvDeleteTCB", "vPortFree"), ("vPortFree", "heap_caps_free"),
        ("__wrap_vPortTCBPreDeleteHook", "vPortTCBPreDeleteHook"),
        ("main_task", "__wrap_app_main"), ("__wrap_app_main", "app_main"),
        ("manager", "__wrap_vTaskDelay"), ("__wrap_vTaskDelay", "vTaskDelay"),
        ("manager", "xTaskCreatePinnedToCore"), ("app_main", "xTaskCreatePinnedToCore"),
        ("worker", "vTaskDelete")]
    required = defaults if required is None else required
    instructions = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+call8\s+([0-9a-f]+) <([^>]+)>$",
                              (folder / disassembly_name).read_text()+"\n"+supplemental, re.M)
    result = []
    with (folder / elf_name).open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        for caller, callee in required:
            source = max(symbols.get_symbol_by_name(caller) or [], key=lambda s: s["st_size"], default=None)
            target = symbols.get_symbol_by_name(callee)
            if source is None or not source["st_size"] or not target:
                raise ValueError("Missing native event/lifecycle symbol: " + caller + " -> " + callee)
            section = elf.get_section(source["st_shndx"])
            matches = []
            selected = instructions
            required_count = (3 if (caller, callee) in (('heap_caps_init', 'bench_boundary_sample'),
                ('soc_get_available_memory_regions', 'bench_boundary_sample')) else
                2 if (caller, callee) == ('prvDeleteTCB', 'vPortFree') else 1)
            if (folder / 'build.json').exists() and json.loads((folder / 'build.json').read_text()).get('compiler_boundary_inline_guards') and sum(
                    source['st_value'] <= int(address, 16) < source['st_value'] + source['st_size'] and
                    int(destination, 16) == target[0]['st_value'] for address, _, destination, _ in selected) < required_count:
                selected = reachable_call8(folder, source, folder / elf_name)
            for address, encoded, destination, _ in selected:
                pc, value, dest = int(address, 16), int(encoded, 16), int(destination, 16)
                if not source["st_value"] <= pc < source["st_value"] + source["st_size"] or dest != target[0]["st_value"]:
                    continue
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                pos = pc - section["sh_addr"]
                if value & 0x3f != 0x25 or (pc & ~3) + 4 + 4 * offset != dest or \
                        section.data()[pos:pos + 3] != value.to_bytes(3, "little"):
                    raise ValueError("Native lifecycle call instruction/target differs")
                matches.append(hex(pc))
            if not matches:
                raise ValueError("Native lifecycle call absent: " + caller + " -> " + callee)
            if (caller, callee) == ("prvDeleteTCB", "vPortFree") and len(matches) != 2:
                raise ValueError("Native dynamic stack and TCB free paths incomplete")
            result.append({"caller": caller, "callee": callee, "instructions": matches})
        if require_iram:
            helper = symbols.get_symbol_by_name("bench_prepare_used")[0]
            if not 0x40080000 <= helper["st_value"] < 0x400C0000:
                raise ValueError("Native TLSF observer helper is not in IRAM")
    return result


def build(folder, verify_upstream=False):
    manifest = json.loads((folder / "build.json").read_text())
    if manifest["status"] != "build_pass_not_measured" or manifest["board_resets"] or manifest["ranking_eligible"]:
        raise ValueError("Source-only build incorrectly qualified")
    if any(not (folder / n).resolve().is_relative_to(folder.resolve()) or sha(folder / n) != v
           for n, v in manifest["files"].items()):
        raise ValueError("Built source/image manifest differs")
    for path in OBSERVER.rglob("*"):
        if path.is_file():
            expected = path.read_bytes()
            if manifest.get("ordinary_irq_stack_coverage"):
                from build_esp32_freertos_stack_coverage import EXTENSION, EXTRA, extended_source
                if path.relative_to(OBSERVER).as_posix() == "census.c":
                    expected = extended_source(path.read_text(),EXTENSION.read_text()).encode()
                elif path.relative_to(OBSERVER).as_posix() == "CMakeLists.txt":
                    expected += EXTRA.encode()
            if (folder / "observer" / path.relative_to(OBSERVER)).read_bytes() != expected:
                raise ValueError("Unreviewed observer source")
    for name in ("series.c", "small_whetstone.c", "small_whetstone.h", "ph_esp_timer.h", "ph_us_schedule.h", "config"):
        if (folder / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("Original workload/schedule/configuration changed: " + name)
    expected = (REFERENCE / "FreeRTOSConfig.h").read_bytes()
    if (folder / "reference-FreeRTOSConfig.h").read_bytes() != expected or \
            (folder / "FreeRTOSConfig.h").read_bytes() != expected + b'\n#include "bench_task_trace.h"\n':
        raise ValueError("Native scheduler change exceeds declared trace hooks")
    for name, edits in native_edits().items():
        if (folder / "native-source/heap" / name).read_bytes() != patched((folder / "original-native/heap" / name).read_bytes(), edits):
            raise ValueError("Allocator changes exceed declared native event points")
    if verify_upstream:
        provenance(folder)
    rows = json.loads((folder / "official-native-source.json").read_text())
    pin = json.loads((folder / "official-tlsf-pin.json").read_text())
    if pin["sha"] != TLSF_COMMIT or pin["submodule_git_url"] != "../../espressif/tlsf.git":
        raise ValueError("Official TLSF submodule provenance differs")
    if len(rows) != len(NATIVE) or {r["path"] for r in rows} != set(NATIVE) or any(
            r["url"] != upstream(r["path"]) or r["sha256"] != sha(source_path(folder, r["path"])) for r in rows):
        raise ValueError("Official native source coverage/provenance differs")
    commands = json.loads((folder / "compile_commands.json").read_text())
    for name in ("tasks.c", "multi_heap.c", "tlsf.c", "census.c", "series.c"):
        matching = [r for r in commands if Path(r["file"]).name == name]
        if len(matching) != 1 or [a for a in shlex.split(matching[0]["command"]) if a.startswith("-O")] != ["-Os"]:
            raise ValueError("Native component compilation/optimization differs: " + name)
    if "13.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("Compiler profile differs")
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    footprint = static_footprint(folder / "application.elf")
    with (folder / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        irq = elf.get_section_by_name(".symtab").get_symbol_by_name("port_IntStack")[0]
        section = elf.get_section(irq["st_shndx"])
        reserved = int(re.search(r"^CONFIG_FREERTOS_ISR_STACKSIZE=(\d+)$", (folder / "config").read_text(), re.M)[1])
        if irq["st_size"] != reserved or section.name != ".dram0.data":
            raise ValueError("Native interrupt stack reservation differs from actual ELF SRAM")
        irq_stack = {"address":irq["st_value"], "reserved_bytes":reserved, "already_in_static_sram":True,
                     "live_use_peak_measured":False}
    return {"audit": "pass", "official_native_files_checked": len(rows), "machine_calls": calls(folder),
        "original_workload_unchanged": True, "static_sram_bytes": footprint["static_sram_bytes"],
        "ram_sections": footprint["ram_sections"], "clock_mhz": 240, "cores": 1, "tick_hz": 1000,
        "optimization": "-Os", "ranking_eligible": False, "whole_live_ram_peak_bytes": None,
        "interrupt_stack":irq_stack}


SAMPLE = re.compile(r"FREERTOS_RAM phase=(\S+) occupied=(\d+) peak=(\d+) invalid=(\d+) register=(\d+) alloc=(\d+) free=(\d+) resize=(\d+) align=(\d+)")


def observations(lines, phases):
    samples = [dict(zip(("phase", "occupied", "peak", "invalid", "register", "alloc", "free", "resize", "align"),
                       (m[1], *map(int, m.groups()[1:])))) for line in lines if (m := SAMPLE.fullmatch(line))]
    if [r["phase"] for r in samples] != phases or any(
            r["invalid"] or not 0 < r["occupied"] <= r["peak"] or not 0 < r["register"] <= 16 for r in samples) or any(
            b[k] < a[k] for a, b in zip(samples, samples[1:]) for k in ("peak", "register", "alloc", "free", "resize", "align")):
        raise ValueError("Native heap phase order, event ledger or oracle differs")
    if lines.count("FREERTOS_RAM END") != 1 or sum(line.startswith("FREERTOS_RAM BEGIN ") for line in lines) != 1 or \
            "FREERTOS_RAM BEGIN clock_mhz=240 cores=1 tick_hz=1000 window=heap-register-through-original-controller-delay" not in lines or \
            any(re.search(r"panic|abort|Guru Meditation|Exception|watchdog|ASSERT|FATAL|invalid-command", s, re.I) for s in lines):
        raise ValueError("Native allocation capture incomplete or contains an error")
    return samples


def validation(folder):
    lines = [r["line"] for r in read_raw_capture(folder, 1)]
    if sum(s.startswith("rst:0x") for s in lines) != 1 or any(s.startswith("HARTSTONE PH ") for s in lines):
        raise ValueError("Allocator validation must be a separate reset, not a workload score")
    samples = observations(lines, ["validation-base", "validation-moved", "validation-shrink", "validation-grow",
                                   "validation-aligned", "validation-freed"])
    values = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM validation=PASS base=(\d+) final=(\d+) required_overlap_peak=(\d+) observed_peak=(\d+)", s))]
    if len(values) != 1:
        raise ValueError("Native allocator self-validation did not pass")
    before, after, required, maximum = values[0]
    if before != after or before != samples[0]["occupied"] or after != samples[-1]["occupied"] or \
            not before < required <= maximum or maximum != samples[-1]["peak"] or \
            not samples[1]["occupied"] > samples[2]["occupied"] < samples[3]["occupied"] < samples[4]["occupied"] or \
            samples[-1]["resize"] < 2 or not samples[-1]["align"]:
        raise ValueError("Moving/in-place/aligned/failed allocation validation does not reconcile")
    return {"audit": "pass", "samples": samples, "base_final_bytes": before,
        "required_moving_realloc_overlap_peak_bytes": required, "observed_peak_bytes": maximum,
        "independent_workload_resets": 0}


def lifetimes(lines, samples, worker_count, sections):
    summaries = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM tasks created=(\d+) requested=(\d+) cleanup=(\d+) retired=(\d+) active=(\d+) peak_active=(\d+) retired_max_used=(\d+) invalid=(\d+)", s))]
    roles = [(m[1], *map(int, m.groups()[1:])) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM role=(worker|controller|main|system) created=(\d+) requested=(\d+) retired=(\d+) active=(\d+)", s))]
    live = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM live tcb=(\d+) stack=(\d+) span=(\d+) tcb_bytes=(\d+) kind=(\d+) role=(\d+) stack_heap=(\d+) tcb_heap=(\d+) stack_block=(\d+) tcb_block=(\d+) spare=(\d+)", s))]
    pools = [tuple(map(int, m.groups())) for s in lines if (m := re.fullmatch(
        r"FREERTOS_RAM pool start=(\d+) bytes=(\d+) occupied=(\d+) metadata=(\d+) native_bias=(\d+) checks=(\d+)", s))]
    if len(summaries) != 1 or [r[0] for r in roles] != ["worker", "controller", "main", "system"]:
        raise ValueError("Native task lifetime role coverage differs")
    made, requested, cleanup, retired, active, maximum, stack_used, bad = summaries[0]
    expected = sum(5 + s for s in range(worker_count - 4))
    if bad or made != retired + active or requested != cleanup or cleanup != retired or \
            len(live) != active or len({r[0] for r in live}) != active or not 0 < active <= maximum <= 128 or not stack_used or \
            roles[0][1:] != (expected, expected, expected, 0) or roles[1][1:] != (1, 0, 0, 1) or roles[2][1:] != (1, 1, 1, 0) or \
            any(sum(r[i] for r in roles) != value for i, value in enumerate((made, requested, retired, active), 1)):
        raise ValueError("Worker/main retirement or original retained-controller ownership differs")
    if len(pools) != samples[-1]["register"] or sum(p[2] for p in pools) != samples[-1]["occupied"] or any(
            not 0 < metadata <= value <= size or bias > metadata or not checks for _, size, value, metadata, bias, checks in pools):
        raise ValueError("Native pool metadata, counters or final occupancy differs")
    regions = [(start, size) for start, size, *_ in pools]
    region_accounting(sections, regions, False)
    intervals = []
    for tcb, stack, span, tcb_bytes, kind, role, stack_heap, tcb_heap, stack_block, tcb_block, spare in live:
        if kind > 2 or role not in (1, 3) or not 0 <= spare <= span or not span or not tcb_bytes or \
                stack_heap not in (0, 1) or tcb_heap not in (0, 1) or kind == 0 and not stack_heap or kind < 2 and not tcb_heap:
            raise ValueError("Live task ownership/high-water bound differs")
        for pointer, requested_bytes, is_heap, block in ((stack, span, stack_heap, stack_block), (tcb, tcb_bytes, tcb_heap, tcb_block)):
            if is_heap:
                if block < requested_bytes + 4 or not any(a <= pointer - 4 < pointer + block - 4 <= a + size for a, size in regions):
                    raise ValueError("Live task block escapes native heap")
                intervals.append((pointer - 4, pointer + block - 4))
            else:
                if block or not any(int(s["address"], 16) <= pointer < pointer + requested_bytes <= int(s["address"], 16) + s["bytes"] for s in sections):
                    raise ValueError("Non-heap task buffer lacks ELF SRAM ownership")
                intervals.append((pointer, pointer + requested_bytes))
    ordered = sorted(intervals)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("Live task storage overlaps")
    return {"created": made, "delete_requested": requested, "native_cleanup": cleanup, "retired": retired,
        "active": active, "peak_active": maximum, "retired_max_used_bytes": stack_used,
        "roles": {name: dict(zip(("created", "delete_requested", "retired", "active"), values)) for name, *values in roles},
        "live_records": [list(r) for r in live], "pool_records": [list(r) for r in pools], "worker_lifetimes": expected,
        "all_workload_workers_released": True, "original_controller_retained": True,
        "stack_blocks_already_in_heap_or_static": True, "high_waters_not_summed": True}


def audit(directory, source):
    campaign = envelope(directory)
    if campaign["kind"] != "freertos-ram" or campaign["independent_resets"] != 3 or campaign["board_mac"] != "34:98:7a:a2:85:28":
        raise ValueError("Wrong board or incomplete native FreeRTOS lifecycle campaign")
    proof = build(source)
    for path in (directory / "build").iterdir():
        if sha(path) != sha(source / path.name):
            raise ValueError("Measured image differs from source-qualified build")
    verified(directory / "captures", directory / "build", campaign["board_mac"])
    separate_validation = validation(directory / "validation")
    captures = independent_captures(directory / "captures")
    runs = []
    for index, rows in enumerate(captures, 1):
        verified(directory / "captures", directory / "build", campaign["board_mac"], logs=("verify-run%d.log" % index,))
        original = series(directory / "captures" / ("reset%d.jsonl" % index), "FreeRTOS", 4, high_resolution=True)
        if original["completion"] != "FIRST_LOSS_REACHED":
            raise ValueError("Original PH4 workload did not reach first loss")
        lines = [r["line"] for r in rows]
        samples = observations(lines, ["application-entry", "application-return", "series-end", "controller-delayed"])
        phase_at = [i for i,s in enumerate(lines) if SAMPLE.fullmatch(s)]
        terminal_at = [i for i,s in enumerate(lines) if s.startswith("HARTSTONE PH SERIES status=FIRST_LOSS ")]
        boot_at = lines.index("HARTSTONE PH SERIES boot target=ESP32 os=FreeRTOS experiment=4")
        first_trial = next(i for i,s in enumerate(lines) if s.startswith("HARTSTONE PH TRIAL "))
        if len(terminal_at) != 1 or not phase_at[0] < boot_at < phase_at[1] < first_trial < terminal_at[0] < phase_at[2] < phase_at[3] or \
                not 0.8 <= rows[phase_at[3]]["elapsed_s"] - rows[phase_at[2]]["elapsed_s"] <= 2.5:
            raise ValueError("Original controller post-terminal delay boundary differs")
        count = original["first_loss_step"] + 5
        ledger = lifetimes(lines, samples, count, proof["ram_sections"])
        runs.append({"original_ph4": original, "samples": samples, "tasks": ledger,
            "allocated_heap_peak_bytes": samples[-1]["peak"],
            "observed_software_allocation_bytes": proof["static_sram_bytes"] + samples[-1]["peak"],
            "ranking_eligible": False})
    return {"audit": "pass", "os": "FreeRTOS", "independent_resets": 3, "build": proof,
        "validation": separate_validation, "runs": runs, "original_flash_restored": True,
        "scope": "heap registration through original PH4 controller first post-terminal delay; all worker/native-main retirement and retained system/controller allocation",
        "whole_live_ram_peak_bytes": None, "full_live_ram_ranking_eligible": False,
        "ranking_eligible": False, "energy_measured": False, "external_independent_replication": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_upstream:
        provenance(args.build)
    result = audit(args.capture, args.build) if args.capture else build(args.build)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
