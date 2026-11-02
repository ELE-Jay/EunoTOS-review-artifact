#!/usr/bin/env python3
"""Build an isolated native-heap/task lifecycle observer around unchanged PH4."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def native_edits():
    return {
        "multi_heap.c": [
            ("multi_heap_handle_t multi_heap_register_impl(void *start_ptr, size_t size)",
             "extern void bench_heap_register(void *, void *, uintptr_t, size_t, size_t);\n"
             "extern void bench_heap_check(void *, size_t);\n\n"
             "multi_heap_handle_t multi_heap_register_impl(void *start_ptr, size_t size)"),
            ("    result->minimum_free_bytes = result->free_bytes;\n    return result;",
             "    result->minimum_free_bytes = result->free_bytes;\n"
             "    bench_heap_register(result, result->heap_data, (uintptr_t)start_ptr, size + sizeof(heap_t), result->free_bytes);\n"
             "    return result;"),
            ("void multi_heap_internal_unlock(multi_heap_handle_t heap)\n{\n    MULTI_HEAP_UNLOCK(heap->lock);",
             "void multi_heap_internal_unlock(multi_heap_handle_t heap)\n{\n"
             "    bench_heap_check(heap, heap->free_bytes);\n    MULTI_HEAP_UNLOCK(heap->lock);")],
        "tlsf/tlsf.c": [
            ("void* tlsf_malloc(tlsf_t tlsf, size_t size)",
             '#include "tlsf-observer.inc"\n\nvoid* tlsf_malloc(tlsf_t tlsf, size_t size)'),
            ("return block_prepare_used(control, block, adjust);",
             "return bench_prepare_used(control, block, adjust, 1);"),
            ("return block_prepare_used(control, block, adjust);",
             "return bench_prepare_used(control, block, adjust, 4);"),
            ('tlsf_assert(!block_is_free(block) && "block already marked as free");\n\t\tblock_mark_as_free(block);',
             'tlsf_assert(!block_is_free(block) && "block already marked as free");\n'
             '\t\tbench_tlsf_delta(tlsf, ptr, -(ptrdiff_t)(block_size(block) + block_header_overhead), 2);\n'
             '\t\tblock_mark_as_free(block);'),
            ("block_trim_used(control, block, adjust);\n\t\t\tp = ptr;",
             "block_trim_used(control, block, adjust);\n\t\t\tp = ptr;\n"
             "\t\t\tbench_tlsf_delta(tlsf, p, (ptrdiff_t)block_size(block) - (ptrdiff_t)cursize, 3);")],
    }


def patched(original, edits):
    text = original.replace(b"\r\n", b"\n").decode("utf-8")
    for index, (before, after) in enumerate(edits):
        # The first and second identical preparation returns are malloc/alignment.
        expected = 2 if before == "return block_prepare_used(control, block, adjust);" and index == 1 else 1
        if text.count(before) != expected:
            raise ValueError("Native allocator event anchor differs: " + before)
        text = text.replace(before, after, 1)
    return text.encode("utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root, work, output, observer):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite build/evidence")
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    freertos, heap, component = (work / n for n in ("freertos", "heap", "freertos_lifetimes"))
    shutil.copytree(root / "tm-cooperative-no-timeslicing/freertos", freertos, symlinks=True)
    shutil.copytree(root / "esp-idf-v5.2.5/components/heap", heap, symlinks=True)
    shutil.copytree(observer, component)
    reference = root / "downloads/hartstone-native-us-fifo-v1/freertos/ph4"
    config_path = freertos / "config/include/freertos/FreeRTOSConfig.h"
    if config_path.read_bytes() != (reference / "FreeRTOSConfig.h").read_bytes():
        raise ValueError("Native no-timeslicing profile differs from original reference")
    config_path.write_bytes(config_path.read_bytes() + b'\n#include "bench_task_trace.h"\n')
    shutil.copyfile(observer / "bench_task_trace.h", config_path.parent / "bench_task_trace.h")
    for name, edits in native_edits().items():
        path = heap / name
        original = output / "original-native/heap" / name
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, original)
        path.write_bytes(patched(path.read_bytes(), edits))
    shutil.copyfile(observer / "tlsf-observer.inc", heap / "tlsf/tlsf-observer.inc")
    for name in ("series.c", "small_whetstone.c", "small_whetstone.h", "ph_esp_timer.h"):
        source = root / "hartstone_freertos/main" / name
        if source.read_bytes() != (reference / name).read_bytes():
            raise ValueError("Original PH4 workload changed: " + name)
        shutil.copyfile(source, output / name)
    shutil.copyfile(root / "hartstone_common/ph_us_schedule.h", output / "ph_us_schedule.h")
    if (output / "ph_us_schedule.h").read_bytes() != (reference / "ph_us_schedule.h").read_bytes():
        raise ValueError("Original release schedule changed")
    shutil.copyfile(reference / "config", output / "config")
    shutil.copyfile(reference / "FreeRTOSConfig.h", output / "reference-FreeRTOSConfig.h")
    shutil.copyfile(config_path, output / "FreeRTOSConfig.h")
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env = dict(os.environ, IDF_PATH=str(root / "esp-idf-v5.2.5"), IDF_TOOLS_PATH=str(root / "idf-tools"),
        IDF_PYTHON_ENV_PATH=str(root / "idf-python-env"),
        ESP_ROM_ELF_DIR=str(root / "idf-tools/tools/esp-rom-elfs/20230320"),
        PATH=str(gcc) + ":" + str(root / "idf-python-env/bin") + ":" + str(root / "bin") + ":" + os.environ["PATH"])
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    build_dir = work / "build"
    def run(args, name):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    run([cmake, "-G", "Ninja", "-S", str(component / "app"), "-B", str(build_dir), "-DPH_EXPERIMENT=4",
         "-DPH_HIGH_RES=ON", "-DSDKCONFIG=" + str(output / "config"),
         "-DPYTHON=" + str(root / "idf-python-env/bin/python"),
         "-DEXTRA_COMPONENT_DIRS=" + ";".join(map(str, (root / "hartstone_freertos/main", freertos, heap, component))),
         "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log")
    run([cmake, "--build", str(build_dir), "--parallel", "2"], "build.log")
    if (output / "config").read_bytes() != (reference / "config").read_bytes():
        raise ValueError("Observer changed original sdkconfig")
    for source, name in (("iotosbench_esp32_hartstone.elf", "application.elf"),
                         ("iotosbench_esp32_hartstone.bin", "application.bin"),
                         ("iotosbench_esp32_hartstone.map", "application.map"),
                         ("bootloader/bootloader.bin", "bootloader.bin"),
                         ("partition_table/partition-table.bin", "partitions.bin"),
                         ("compile_commands.json", "compile_commands.json")):
        shutil.copyfile(build_dir / source, output / name)
    shutil.copytree(observer, output / "observer")
    for name in ("FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/portable/xtensa/port.c",
                 "FreeRTOS-Kernel/portable/xtensa/include/freertos/portmacro.h", "heap_idf.c"):
        destination = output / "native-source/freertos" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(freertos / name, destination)
    for name in (*native_edits(), "multi_heap_platform.h", "include/multi_heap.h", "include/esp_heap_caps.h",
                 "tlsf/tlsf.h", "tlsf/tlsf_common.h", "tlsf/tlsf_block_functions.h"):
        destination = output / "native-source/heap" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(heap / name, destination)
    shutil.copyfile(__file__, output / "build-script.py")
    for tool, args, name in (("gcc", ["--version"], "compiler.txt"),
                             ("objdump", ["-d", str(output / "application.elf")], "disassembly.txt"),
                             ("nm", ["-S", str(output / "application.elf")], "symbols.txt")):
        run([str(gcc / ("xtensa-esp32-elf-" + tool)), *args], name)
    report = {"status":"build_pass_not_measured", "board_resets":0, "ranking_eligible":False,
        "os":"FreeRTOS", "benchmark":"original SEI-derived PH4", "clock_mhz":240, "cores":1, "tick_hz":1000,
        "scope":"native heap registration through first original post-terminal controller delay; allocation peak and task block lifetimes, not simultaneous live stack use",
        "changes":"native allocator commit/register/unlock observations and original FreeRTOS traceTASK_CREATE/DELETE hooks; original workload and scheduler configuration retained",
        "native_tlsf_line_endings":"LF normalized in observed copy; pinned original bytes retained",
        "files":{p.relative_to(output).as_posix():digest(p) for p in output.rglob("*") if p.is_file()}}
    (output / "build.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("status","board_resets","ranking_eligible")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    args = parser.parse_args()
    build(args.root,args.workspace,args.output,args.observer)
