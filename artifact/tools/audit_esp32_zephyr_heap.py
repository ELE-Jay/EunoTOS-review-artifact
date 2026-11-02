#!/usr/bin/env python3
"""Audit original Zephyr 100-by-10-byte heap means on four native OS ports."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import statistics
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from audit_esp32_iperf_original import ANSI
from audit_esp32_resources import audit_elf_image
from audit_esp32_riot_original import check_manifest, digest, UPSTREAM as RIOT_UPSTREAM
from audit_esp32_zephyr_latency_alios import UPSTREAM as ALIOS_UPSTREAM, hardware_tick_divisors
from audit_esp32_zephyr_latency_freertos import ROOT, REFERENCE
from audit_esp32_zephyr_original import UPSTREAM as ZEPHYR_UPSTREAM, LATENCY

PORT = ROOT / "firmware/bsp/esp32/zephyr_latency_heap"
SHARED = ROOT / "firmware/bsp/esp32/zephyr_latency_freertos/include"
TAGS = ("heap.malloc.immediate", "heap.free.immediate")
LABELS = {"freertos": "FreeRTOS", "nuttx": "NuttX", "riot": "RIOT", "alios": "AliOS-Rhino"}
SOURCES = {
    "freertos": ("components/freertos/heap_idf.c", "components/heap/heap_caps.c", "components/heap/heap_caps_base.c",
                  "components/heap/multi_heap.c", "components/heap/tlsf/tlsf.c"),
    "nuttx": ("mm/umm_heap/umm_malloc.c", "mm/umm_heap/umm_free.c", "mm/mm_heap/mm_malloc.c",
              "mm/mm_heap/mm_free.c", "mm/mm_heap/mm.h", "mm/umm_heap/umm_heap.h"),
    "riot": ("cpu/esp_common/syscalls.c", "sys/newlib_syscalls_default/syscalls.c", "core/lib/rmutex.c", "core/mutex.c"),
    "alios": ("kernel/rhino/k_mm.c", "kernel/rhino/k_mm_blk.c", "kernel/rhino/include/k_mm.h",
              "kernel/rhino/include/k_default_config.h", "platform/arch/xtensa/lx6/xtensa_init.c",
              "platform/arch/xtensa/lx6/include/frxt/xtensa_rtos.h"),
}
UPSTREAM = {"freertos": "https://raw.githubusercontent.com/espressif/esp-idf/v5.2.5/",
            "nuttx": "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/",
            "riot": RIOT_UPSTREAM, "alios": ALIOS_UPSTREAM}


def native_source_url(os, name):
    if os == "freertos" and name == "components/heap/tlsf/tlsf.c":
        return "https://raw.githubusercontent.com/espressif/tlsf/d2e28f872472ffc6a704faae65ddee1f24e2dfba/tlsf.c"
    return UPSTREAM[os] + name


def heap_operation_evidence(directory, os, disassembly):
    body = re.search(r"^[0-9a-f]+ <heap_malloc_free>:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
    if body is None:
        raise ValueError("original heap body not linked")
    branch = re.search(r"\bbnez(?:\.n)?\s+a10,\s+([0-9a-f]+) <heap_malloc_free\+0x[0-9a-f]+>", body[1])
    if branch is None:
        raise ValueError("original allocation success branch missing")
    row_pattern = r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$"
    rows = re.findall(row_pattern, body[1], re.M)
    supplement = None
    if os != "freertos":
        path = directory / "heap-success-branch.txt"
        decoded = re.findall(row_pattern, path.read_text(), re.M)
        if not decoded or decoded[0][0] != branch[1] or not re.fullmatch(
                r"bne\s+a\d+,\s*a\d+,\s*[0-9a-f]+ <heap_malloc_free\+0xd>", decoded[-1][2]):
            raise ValueError("supplement is not the original success branch/loop backedge")
        for previous, current in zip(decoded, decoded[1:]):
            if int(previous[0], 16) + len(previous[1]) // 2 != int(current[0], 16):
                raise ValueError("success branch instruction coverage incomplete")
        rows = [row for row in rows if int(row[0], 16) < int(branch[1], 16)] + decoded
        supplement = {"path": path.name, "sha256": digest(path), "elf_sha256": digest(directory / "application.elf"),
                      "instruction_bytes_checked": len(decoded), "reason": "linear Xtensa objdump alignment loss before actual success branch"}
    relevant = [(address, encoding, instruction) for address, encoding, instruction in rows if
                re.match(r"rsr(?:\.ccount\s+\w+|\s+\w+,\s*ccount)$", instruction) or
                re.fullmatch(r"call8\s+[0-9a-f]+ <k_(?:malloc|free)>", instruction)]
    if ["clock" if instruction.startswith("rsr") else instruction.split("<")[1][:-1]
            for _, _, instruction in relevant] != ["clock", "k_malloc", "clock", "clock", "k_free", "clock"]:
        raise ValueError("original four timestamps/allocate/free timing order differs")
    with (directory / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        original = symbols.get_symbol_by_name("heap_malloc_free")[0]
        start, end = original["st_value"], original["st_value"] + original["st_size"]
        section = elf.get_section(original["st_shndx"])
        data, base = section.data(), section["sh_addr"]
        for address, encoding, instruction in (decoded if supplement else []) + relevant:
            address, value = int(address, 16), int(encoding, 16)
            encoded = bytes.fromhex(encoding)[::-1]
            if not start <= address < end or address + len(encoded) > end or data[address - base:address - base + len(encoded)] != encoded:
                raise ValueError("original operation disassembly bytes differ from frozen ELF")
            if instruction.startswith("rsr") and value & 0xffff0f != 0x03ea00:
                raise ValueError("timestamp label is not an encoded CCOUNT read")
            if match := re.fullmatch(r"call8\s+([0-9a-f]+) <(k_malloc|k_free)>", instruction):
                offset = value >> 6
                if offset & (1 << 17):
                    offset -= 1 << 18
                target = symbols.get_symbol_by_name(match[2])[0]["st_value"]
                if value & 0x3f != 0x25 or (address & ~3) + 4 + 4 * offset != target or int(match[1], 16) != target:
                    raise ValueError("original allocator call label differs from encoded target")
    return supplement


def capture(directory, index, os):
    rows = [json.loads(line) for line in (directory / f"reset{index}.jsonl").read_text().splitlines()]
    raw, position = (directory / f"reset{index}.raw").read_bytes(), 0
    for row in rows:
        chunk = raw[position:position + row["raw_bytes"]]
        if row["raw_bytes"] <= 0 or hashlib.sha256(chunk).hexdigest() != row["raw_sha256"] or \
                chunk.decode("utf-8", errors="replace").rstrip("\r\n") != row["line"]:
            raise ValueError("raw UART byte/record binding differs")
        position += row["raw_bytes"]
    if position != len(raw) or not rows:
        raise ValueError("raw UART coverage incomplete")
    lines = [ANSI.sub("", row["line"]).strip() for row in rows]
    times = [datetime.fromisoformat(row["utc"]) for row in rows]
    elapsed = [row["elapsed_s"] for row in rows]
    if any(t.utcoffset() is None for t in times) or any(b < a for a, b in zip(times, times[1:])) or \
            any(not math.isfinite(t) or t < 0 for t in elapsed) or any(b < a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("native capture chronology differs")
    tick = "native-tickless" if os == "riot" else "1"
    begin = f"HEAP PORT BEGIN {LABELS[os]} Zephyr-3.7.0-subset count=100 bytes=10 clock=240 cores=1 tick={tick}"
    if lines.count(begin) != 1 or lines.count("HEAP PORT END") != 1 or lines[-1] != "HEAP PORT END" or \
            sum("rst:0x" in line for line in lines) != 1 or any(re.search(
                r"HEAP PORT FAIL|FAILED|Guru Meditation|panic|assert failed|Brownout|watchdog", line, re.I) for line in lines):
        raise ValueError("native reset/profile/completion differs")
    if os == "freertos":
        elf_sha = digest(directory / "application.elf")
        boot = sum("2nd stage bootloader" in line for line in lines) == 1 and \
            sum("main_task: Calling app_main()" in line for line in lines) == 1 and \
            sum("cpu freq: 240000000 Hz" in line for line in lines) == 1 and \
            any("ELF file SHA256:  " + elf_sha[:9] + "..." in line for line in lines)
    elif os == "nuttx":
        boot = lines.count("NuttShell (NSH) NuttX-12.2.1") == 1 and \
            lines.count("HEAP NATIVE VERSION NuttX 12.2.1") == 1 and \
            sum("2nd stage bootloader" in line for line in lines) == 1
    elif os == "riot":
        boot = lines.count("Single core mode") == 1 and lines.count("Pro cpu up.") == 1 and \
            lines.count("main(): This is RIOT! (Version: 2024.10-devel)") == 1
    else:
        boot = lines.count("Welcome to AliOS Things") == 1 and lines.count("bootload image") == 1 and \
            lines.count("HEAP NATIVE TICK divisor=240000000") == 1
    if not boot:
        raise ValueError("native version/clock/boot binding differs")
    pending, values = None, {}
    for line in lines:
        if match := re.fullmatch(r"HEAP ORIGINAL INPUT numerator=(\d+) count=(\d+)", line):
            if pending is not None:
                raise ValueError("unbound original heap mean input")
            pending = {"numerator": int(match[1]), "count": int(match[2])}
        elif match := LATENCY.fullmatch(line):
            tag, _, cycles, ns = match.groups()
            if pending is None or tag not in TAGS or tag in values or pending["count"] != 100 or \
                    not 0 < pending["numerator"] < 2 ** 32 or int(cycles) != pending["numerator"] // 100 or \
                    int(ns) != pending["numerator"] * 1000 // 240 // 100:
                raise ValueError("original heap count/mean formula differs")
            values[tag] = {"mean_ns": int(ns), "mean_cycles": int(cycles), "original_input": pending}
            pending = None
    if pending is not None or tuple(values) != TAGS:
        raise ValueError("original heap cases incomplete or reordered")
    return {"start_utc": times[0].isoformat(), "end_utc": times[-1].isoformat(), "metrics": values,
            "uart_sha256": digest(directory / f"reset{index}.jsonl"), "raw_sha256": digest(directory / f"reset{index}.raw")}


def audit(directory, os, verify_upstream=False):
    if os not in LABELS:
        raise ValueError("unsupported native heap profile")
    for name in ("image.sha256", "capture.sha256"):
        check_manifest(directory, name)
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "image.sha256").read_text().splitlines()}
    if not {"application.elf", "application.bin", "application.map", "config", "compiler.txt", "build.log",
            "bootloader.bin", "partitions.bin", "port.c", "include/zephyr/kernel.h", "disassembly.txt",
            "source/heap_malloc_free.c", "source/utils.h", *("native-source/" + name for name in SOURCES[os])} <= covered:
        raise ValueError("native source/build/image coverage incomplete")
    covered = {line.split(maxsplit=1)[1].lstrip("*").removeprefix("./") for line in
               (directory / "capture.sha256").read_text().splitlines()}
    if not {"image.sha256", "flash.log", "runner.sh", "capture_esp32_uart.py", *(
            f"reset{i}.{ext}" for i in (1, 2, 3) for ext in ("jsonl", "raw"))} <= covered:
        raise ValueError("native acquisition coverage incomplete")
    originals = {row["path"]: row for row in json.loads((REFERENCE / "official-source.json").read_text())}
    for name in ("heap_malloc_free.c", "utils.h"):
        proof = originals["src/" + name]
        if proof["url"] != ZEPHYR_UPSTREAM + "latency_measure/src/" + name or \
                digest(directory / "source" / name) != proof["sha256"] or \
                (directory / "source" / name).read_bytes() != (REFERENCE / "source/src" / name).read_bytes():
            raise ValueError("original heap body/statistics changed")
    for name in ("port.c", "include/zephyr/kernel.h"):
        if (directory / name).read_bytes() != (PORT / name).read_bytes():
            raise ValueError("native heap adapter differs from inspected source")
    for path in (PORT / os).rglob("*"):
        if path.is_file() and path.read_bytes() != (directory / "build-files" / path.relative_to(PORT / os)).read_bytes():
            raise ValueError("native application build files changed")
    for name in ("timing/timing.h", "sys/printk.h", "timestamp.h", "app_memory/app_memdomain.h"):
        if (directory / "include/zephyr" / name).read_bytes() != (SHARED / "zephyr" / name).read_bytes():
            raise ValueError("shared timing/format contract changed")
    proof_path = directory / "official-native-source.json"
    if verify_upstream:
        records = []
        for name in SOURCES[os]:
            with urlopen(native_source_url(os, name), timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if digest(directory / "native-source" / name) != sha:
                raise ValueError(("native allocator source differs from official revision", name))
            records.append({"path": name, "url": native_source_url(os, name), "sha256": sha})
        proof_path.write_text(json.dumps(records, indent=2) + "\n")
    proof = json.loads(proof_path.read_text())
    if len(proof) != len(SOURCES[os]) or {row["path"] for row in proof} != set(SOURCES[os]) or any(
            row["url"] != native_source_url(os, row["path"]) or row["sha256"] != digest(directory / "native-source" / row["path"])
            for row in proof):
        raise ValueError("native allocator provenance differs")
    config, compiler = (directory / "config").read_text(), (directory / "compiler.txt").read_text()
    version = {"freertos": "13.2.0", "nuttx": "13.2.0", "riot": "12.2.0", "alios": "5.2.0"}[os]
    if version not in compiler:
        raise ValueError("native compiler profile differs")
    commands = []
    if os == "freertos":
        commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
        if not {"CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_FREERTOS_HZ=1", "CONFIG_FREERTOS_UNICORE=y",
                "CONFIG_ESP_INT_WDT_TIMEOUT_MS=3000", "CONFIG_HEAP_POISONING_DISABLED=y"} <= set(config.splitlines()):
            raise ValueError("native core/clock/tick/heap profile differs")
    else:
        log = (directory / "build.log").read_text().replace("\\\n", " ")
        commands = [shlex.split(line) for line in log.splitlines() if "xtensa-esp32-elf-gcc" in line and " -c " in line]
    app_suffix = {"freertos": "app-freertos/", "riot": "app-riot/",
                  "nuttx": "examples/zephyr_heap/", "alios": "app/example/zephyr_heap/"}[os]
    for name in ("heap_malloc_free.c", "port.c", *(name for name in SOURCES[os] if name.endswith(".c"))):
        selected = []
        for args in commands:
            if Path(args[0]).name != "xtensa-esp32-elf-gcc":
                continue
            sources = [arg for arg in args if not arg.startswith("-") and arg.endswith(".c")]
            if name in ("port.c", "heap_malloc_free.c"):
                matches = any(arg.endswith(app_suffix + name) for arg in sources)
                if os == "nuttx":
                    matches = name in sources and any("apps.examples.zephyr_heap.o" in arg for arg in args)
            else:
                matches = any(arg.endswith("/" + name) or arg == name or name.endswith("/" + arg)
                              for arg in sources)
                if os == "freertos" and name == "components/freertos/heap_idf.c":
                    matches = any(arg.endswith("/tm-cooperative-no-timeslicing/freertos/heap_idf.c") for arg in sources)
            if matches:
                selected.append(args)
        if len(selected) != 1 or [arg for arg in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"]:
            raise ValueError(("original/native allocator source compilation differs", name))
        if name in ("port.c", "heap_malloc_free.c") and "-DHEAP_OS_" + os.upper() not in selected[0]:
            raise ValueError("native adapter branch not actually compiled")
        if os == "alios" and "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0]:
            raise ValueError("native allocator C tick override missing")
    if os == "nuttx":
        required = {"CONFIG_BUILD_FLAT=y", "CONFIG_EXAMPLES_ZEPHYR_HEAP=y", "CONFIG_USEC_PER_TICK=1000000",
                    "CONFIG_RR_INTERVAL=0", "CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ=240", "CONFIG_MM_DEFAULT_MANAGER=y",
                    "CONFIG_MM_HEAP_MEMPOOL_THRESHOLD=0"}
        if not required <= set(config.splitlines()) or {"CONFIG_SMP=y", "CONFIG_SCHED_TICKLESS=y", "CONFIG_MM_KERNEL_HEAP=y"} & \
                set(config.splitlines()) or 'CONFIG_VERSION_STRING="12.2.1"' not in (directory / "version-metadata").read_text():
            raise ValueError("native flat/default general heap/version/timer profile differs")
    if os == "riot":
        for name, value in (("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240", 1), ("CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE", 1),
                            ("MODULE_NEWLIB_NANO", 1), ("THREAD_PRIORITY_MAIN", 10)):
            if not re.search(r"^#define " + name + " " + str(value) + "$", config, re.M):
                raise ValueError("native tickless/Newlib-nano profile differs")
        if "MODULE_SCHED_ROUND_ROBIN" in config or "MODULE_ESP_IDF_HEAP" in config:
            raise ValueError("native allocator/scheduler changed")
        library = json.loads((directory / "official-native-library.json").read_text())
        vendor = json.loads((ROOT / "artifacts/reports/esp32-support-audit-v1/toolchain-vendor.json").read_text())
        release = next(row for row in next(row for row in vendor["tools"] if row["name"] == "xtensa-esp32-elf")["versions"]
                       if row["name"] == "esp-12.2.0_20230208")["linux-amd64"]
        if library["audit"] != "pass" or library["archive_sha256"] != release["sha256"] or \
                library["library_sha256"] != digest(directory / "libg_nano.a") or \
                library["member"] != "xtensa-esp32-elf/xtensa-esp32-elf/lib/libg_nano.a" or \
                library["library_bytes"] != (directory / "libg_nano.a").stat().st_size:
            raise ValueError("precompiled native allocator differs from vendor payload")
        mapped = (directory / "application.map").read_text()
        for member in ("lib_a-malloc.o", "lib_a-nano-mallocr.o", "lib_a-nano-freer.o"):
            if (directory / "libc-path.txt").read_text().strip() + "(" + member + ")" not in mapped:
                raise ValueError("captured native library not used by actual link")
    divisors = None
    if os == "alios":
        if not {'AOS_BUILD_BOARD="esp32bench"', 'AOS_BUILD_APP="zephyr_heap"', 'AOS_APP_ZEPHYR_HEAP=y'} <= set(config.splitlines()):
            raise ValueError("native application selection differs")
        for name in ("portasm.S", "xtensa_vectors.S"):
            selected = [args for args in commands if any(arg.endswith("/" + name) for arg in args)]
            if len(selected) != 1 or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in selected[0]:
                raise ValueError("native assembler tick override missing")
        divisors = hardware_tick_divisors(directory)
        board = (directory / "k_config.h").read_text()
        for name, value in (("RHINO_CONFIG_MM_BLK", 1), ("RHINO_CONFIG_MM_TLF", 1),
                            ("RHINO_CONFIG_MM_DEBUG", 1), ("RHINO_CONFIG_MM_REGION_MUTEX", 0)):
            if not re.search(r"^#define " + name + r"\s+" + str(value) + "$", board, re.M) or any(
                    arg.startswith("-D" + name) for args in commands for arg in args):
                raise ValueError("native Rhino allocator/debug/critical-section configuration differs")
    audit_elf_image(directory / "application.elf", directory / "application.bin")
    with (directory / "application.elf").open("rb") as stream:
        symbols = {symbol.name: symbol for symbol in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
        for name in ("heap_malloc_free", "k_malloc", "k_free", "timing_cycles_to_ns_avg"):
            if name not in symbols or symbols[name]["st_shndx"] == "SHN_UNDEF" or not symbols[name]["st_size"]:
                raise ValueError("original/native heap entry not linked")
    disassembly = (directory / "disassembly.txt").read_text()
    branch_evidence = heap_operation_evidence(directory, os, disassembly)
    if os == "alios":
        body = re.search(r"^[0-9a-f]+ <k_mm_alloc>:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
        if not body or not re.search(r"\bcall8\s+[^<]*<krhino_mblk_alloc>", body[1]):
            raise ValueError("configured native small-block allocation path not compiled")
    for name, target in zip(("k_malloc", "k_free"), {"freertos": ("pvPortMalloc", "vPortFree"),
            "nuttx": ("malloc", "free"), "riot": ("malloc", "free"), "alios": ("krhino_mm_alloc", "krhino_mm_free")}[os]):
        body = re.search(r"^[0-9a-f]+ <" + name + r">:\n(.*?)(?=\n\n|\Z)", disassembly, re.M | re.S)
        if not body or not re.search(r"\bcall\w*\s+[^<]*<" + target + r">", body[1]):
            raise ValueError("timed wrapper does not call the actual native allocator")
    native = {"freertos": ("pvPortMalloc", "vPortFree"), "nuttx": ("malloc", "free", "mm_malloc", "mm_free"),
              "riot": ("malloc", "free", "_malloc_r", "_free_r"), "alios": ("krhino_mm_alloc", "krhino_mm_free")}[os]
    for name in native:
        if not re.search(r"\bcall\w*\s+[^<]*<" + name + r">", disassembly):
            raise ValueError(("native allocator API not called", name))
    flash = (directory / "flash.log").read_text()
    installed = [(int(size), int(address, 16)) for size, address in re.findall(r"Wrote (\d+) bytes .* at (0x\w+)", flash)]
    if "84:1f:e8:8f:55:dc" not in flash or flash.count("Hash of data verified.") != 3 or installed != [
            ((directory / name).stat().st_size, address) for name, address in
            (("bootloader.bin", 0x1000), ("partitions.bin", 0x8000), ("application.bin", 0x10000))]:
        raise ValueError("installed native image/board binding differs")
    captures = [capture(directory, i, os) for i in (1, 2, 3)]
    if any(a["end_utc"] >= b["start_utc"] for a, b in zip(captures, captures[1:])):
        raise ValueError("independent heap boots overlap")
    metrics = {tag: {"means_ns": (values := [row["metrics"][tag]["mean_ns"] for row in captures]),
                     "median_of_three_means_ns": statistics.median(values)} for tag in TAGS}
    return {"audit": "pass", "benchmark": "Zephyr 3.7.0 latency_measure original heap subset", "os": LABELS[os],
            "metric_count": 2, "resets": 3, "original_iterations": 100, "allocation_bytes": 10,
            "metrics": metrics, "captures": captures, "clock_mhz": 240, "cores": 1, "compiler": version,
            "tick_hz": None if os == "riot" else 1, "hardware_tick_divisors": divisors,
            "heap_branch_evidence": branch_evidence,
            "rhino_allocator_profile": {"small_blocks": True, "heap_debug": True, "region_mutex": False}
                if os == "alios" else None,
            "allocator": {"freertos": "ESP-IDF internal 8-bit capability heap / multi-heap TLSF",
                          "nuttx": "native flat user/default general heap",
                          "riot": "native Newlib-nano general heap / RIOT locking and sbrk",
                          "alios": "native Rhino general heap, configured small-block fast path retained"}[os],
            "original_source_files": 2, "native_source_files": len(SOURCES[os]), "ranking_eligible": False,
            "unmodified_official_native_suite": False,
            "boundary": "original 100 immediate 10-byte allocate/free pairs and arithmetic means; native allocator/adapter costs included; standalone startup heap state, not fragmented/concurrent heap, lifecycle peak or cross-OS allocator rank"}


def render_table(results):
    lines = ["| Original Zephyr heap subset / OS | Allocate means, ns (three boots) | Free means, ns (three boots) |",
             "| --- | --- | --- |"]
    for result in results:
        values = [" / ".join(map(str, result["metrics"][tag]["means_ns"])) for tag in TAGS]
        lines.append(f"| Original heap port / {result['os']} | {values[0]} | {values[1]} |")
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
