#!/usr/bin/env python3
"""Observe native allocation events around the frozen original TM message test."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_esp32_freertos_ram_lifetimes import digest, native_edits, patched

BASE = "tm-freertos-native-aligned-v1/message_processing"
TICK_TRACE = b'''\n#ifndef __ASSEMBLER__
void bench_live_tick(unsigned, void *, void *);
#define traceTASK_INCREMENT_TICK(tick) do { \\
    _Static_assert(__builtin_offsetof(TCB_t, pxTopOfStack) == 0, "Native TCB SP offset"); \\
    bench_live_tick((tick), pxCurrentTCBs[0], (void *)pxCurrentTCBs[0]->pxTopOfStack); \\
} while (0)
#endif
'''
BOUNDARY_TRACE = b'''\n#ifndef __ASSEMBLER__
void bench_boundary_switched(void);
#define traceTASK_SWITCHED_IN() do { \\
    _Static_assert(__builtin_offsetof(TCB_t, pxTopOfStack) == 0, "Native TCB SP offset"); \\
    bench_boundary_switched(); \\
} while (0)
#endif
'''
BOUNDARY_CMAKE = '''
foreach(name main freertos heap)
    idf_component_get_property(lib ${name} COMPONENT_LIB)
    target_compile_options(${lib} PRIVATE $<$<COMPILE_LANGUAGE:C>:-finstrument-functions>)
endforeach()
'''


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Observer anchor differs: " + before)
    return text.replace(before, after)


def observer_source(original, tail, irq_extension=None, startup_extension=None, tick_extension=None, lifecycle_extension=None, compact=False, handoff_extension=None, peak_extension=None, boot_readback_extension=None, step_extension=None, boundary_extension=None, boundary_fast_pruning=False, native_extension=None, boundary_inline_guards=False, single_threshold_guards=False):
    text = original[:original.index("void __real_app_main(void);")]
    text = replace_once(text, "static unsigned terminal, complete;", "static unsigned sleeps, complete;")
    text = replace_once(text, "struct walk_totals {", """/* Preallocated evidence; never allocate recursively from an allocator hook. */
static struct { uint32_t kind, pool, pointer; int32_t delta; } trace[1024];
static unsigned trace_count;
static void record(unsigned kind, unsigned pool, void *pointer, int32_t delta)
{
    if (trace_count == 1024) { invalid++; return; }
    trace[trace_count].kind = kind;
    trace[trace_count].pool = pool;
    trace[trace_count].pointer = (uintptr_t)pointer;
    trace[trace_count++].delta = delta;
}

struct walk_totals {""")
    text = replace_once(text, "        events[0]++;", "        events[0]++;\n        record(0, i, (void *)start, pools[i].metadata);")
    text = replace_once(text, "        events[kind]++;", "        events[kind]++;\n        record(kind, i, pointer, delta);")
    text = replace_once(text, 'strcmp(name, "ph")', 'strcmp(name, "tm")')
    text = replace_once(text, "            created++;", "            record(5, tasks[i].role, tcb, tcb_bytes);\n            record(6, tasks[i].role, stack, span);\n            created++;")
    text = replace_once(text, "        requested++;", "        requested++;\n        record(7, tasks[i].role, tcb, 0);")
    text = replace_once(text, "        cleanups++;", "        cleanups++;\n        record(8, tasks[i].role, tcb, 0);")
    if irq_extension is not None:
        text = replace_once(text, "static unsigned sleeps, complete;",
            "static unsigned sleeps, complete;\nstatic void bench_irq_stack_report(void);")
        text = replace_once(text, '    puts("FREERTOS_RAM END");',
            '    bench_irq_stack_report();\n    puts("FREERTOS_RAM END");')
        tail = replace_once(tail, '        if (trace_count != count) invalid++;',
            '        if (trace_count != count) invalid++;\n        bench_irq_stack_report();')
    if startup_extension is not None:
        if irq_extension is None:
            raise ValueError("Startup coverage requires the frozen IRQ observer")
        text=replace_once(text,"static void bench_irq_stack_report(void);",
            "static void bench_irq_stack_report(void);\nstatic void bench_startup_stack_report(void);")
        text=replace_once(text,"    bench_irq_stack_report();","    bench_startup_stack_report();\n    bench_irq_stack_report();")
        tail=replace_once(tail,"        bench_irq_stack_report();",
            "        bench_startup_stack_report();\n        bench_irq_stack_report();")
    if handoff_extension is not None:
        if startup_extension is None:
            raise ValueError("Heap handoff requires startup-stack coverage")
        startup_extension = handoff_extension + "\n" + replace_once(startup_extension,
            "    __real_heap_caps_enable_nonos_stack_heaps();", "    bench_startup_heap_handoff();")
        startup_extension = replace_once(startup_extension,
            "static void bench_startup_stack_report(void)\n{",
            "static void bench_startup_stack_report(void)\n{\n    bench_startup_heap_report();")
    if boot_readback_extension is not None:
        if startup_extension is None:
            raise ValueError("Boot readback requires application startup coverage")
        startup_extension = boot_readback_extension + "\n" + replace_once(startup_extension,
            "static void bench_startup_stack_report(void)\n{",
            "static void bench_startup_stack_report(void)\n{\n    bench_boot_handoff_report();")
    if tick_extension is not None:
        if startup_extension is None:
            raise ValueError("Tick snapshots require the complete startup observer")
        text = replace_once(text, "static unsigned sleeps, complete;",
            "static unsigned sleeps, complete;\nstatic volatile unsigned bench_live_enabled;\nstatic void bench_live_report(void);")
        tail = replace_once(tail, "    if (++sleeps == 4 && !complete) {",
            "    if (!sleeps) bench_live_enabled = 1;\n    if (++sleeps == 4 && !complete) {\n        bench_live_enabled = 0;")
        tail = replace_once(tail, "        task_report();", "        task_report();\n        bench_live_report();")
    if lifecycle_extension is not None:
        text = replace_once(text, "static void validate(void)",
            "static void bench_validate_task_lifetimes(void);\n\nstatic __attribute__((noinline)) void validate(void)")
        boundary = ('    bench_startup_stack_report();' if startup_extension is not None else
            '    bench_irq_stack_report();' if irq_extension is not None else '    puts("FREERTOS_RAM END");')
        text = replace_once(text, boundary, '    bench_validate_task_lifetimes();\n' + boundary)
    text = text + tail + "".join("\n" + extension for extension in
        (irq_extension, startup_extension, tick_extension, lifecycle_extension) if extension is not None)
    if compact:
        # Same complete evidence, smaller bounded buffers for this frozen workload.
        boundary = text.index("static void bench_validate_task_lifetimes(void);" if lifecycle_extension is not None else "static void validate(void)")
        text = text[:boundary].replace("128", "16") + text[boundary:]
        text = text.replace("trace[1024]", "trace[128]").replace("trace_count == 1024", "trace_count == 128")
        text = text.replace("capacity=1024", "capacity=128")
    if peak_extension is not None:
        if not compact or startup_extension is None:
            raise ValueError("Allocation-peak contexts require compact startup coverage")
        text = replace_once(text, "static void record(", "static __attribute__((noinline)) void record(")
        text = replace_once(text, "static unsigned trace_count;", "static unsigned trace_count;\nstatic void bench_peak_context(void);\nstatic void bench_peak_report(void);")
        text = replace_once(text, "    trace[trace_count++].delta = delta;", "    trace[trace_count++].delta = delta;\n    bench_peak_context();")
        text = text.replace("    bench_startup_stack_report();", "    bench_peak_report();\n    bench_startup_stack_report();")
        text += "\n" + peak_extension
    if step_extension is not None:
        from measure_esp32_message_steps import step_source
        text = step_source(text, step_extension)
    if boundary_extension is not None:
        from measure_esp32_message_boundaries import boundary_source
        text = boundary_source(text, boundary_extension, boundary_fast_pruning)
    if native_extension is not None:
        from measure_esp32_native_sp import observer_source as native_source
        text = native_source(text, native_extension)
    if boundary_inline_guards:
        from guard_esp32_boundary_calls import observer_source as guarded_source
        text = guarded_source(text)
    if single_threshold_guards:
        from guard_esp32_sp_threshold import observer_source as threshold_source
        text = threshold_source(text)
    return text


def build(root, work, output, observer, tail, irq_coverage=False, startup_coverage=False, tick_stacks=False, lifecycle_validation=False, compact=False, startup_handoff=False, peak_context=False, boot_readback_state=None, step_stacks=False, boundary_stacks=False, boundary_header_exclusion=False, boundary_fast_pruning=False, native_sp=False, boundary_inline_guards=False, stack_entry_guards=False, single_threshold_guards=False):
    if work.exists() or output.exists():
        raise ValueError("Refusing to overwrite builds or measured evidence")
    if startup_coverage and not irq_coverage:
        raise ValueError("Startup coverage requires IRQ coverage")
    if tick_stacks and not startup_coverage:
        raise ValueError("Tick snapshots require startup coverage")
    if startup_handoff and not startup_coverage:
        raise ValueError("Heap handoff requires startup coverage")
    if startup_handoff and not lifecycle_validation:
        raise ValueError("Heap handoff requires the complete separate validation trace")
    if peak_context and (not compact or not startup_handoff):
        raise ValueError("Allocation-peak contexts require compact native startup handoff")
    if boot_readback_state is not None and (not startup_coverage or type(boot_readback_state) is not int or
            boot_readback_state % 4 or not 0x3fff0000 <= boot_readback_state <= 0x3fffffd8):
        raise ValueError("Boot readback requires a bounded paired-ELF state address")
    if step_stacks and (not compact or not startup_handoff or not peak_context or boot_readback_state is None):
        raise ValueError("Continuous stack trace requires the complete compact boot-handoff observer")
    if boundary_stacks and (step_stacks or tick_stacks or not compact or not startup_handoff or boot_readback_state is None):
        raise ValueError("Boundary observer requires compact boot-handoff coverage without other periodic probes")
    if boundary_header_exclusion and not boundary_stacks:
        raise ValueError("Header filtering requires the compiler-boundary observer")
    if boundary_fast_pruning and not boundary_stacks:
        raise ValueError("Fast depth pruning requires compiler-boundary observations")
    if boundary_inline_guards and (not boundary_fast_pruning or not native_sp):
        raise ValueError("Inline guards require the combined fast-boundary/native-SP observer")
    if stack_entry_guards and not boundary_inline_guards:
        raise ValueError("Entry guards require the existing combined native observer")
    if single_threshold_guards and not stack_entry_guards:
        raise ValueError("Single threshold requires actual stack-entry guards")
    if native_sp and (step_stacks or tick_stacks or not compact or not startup_handoff or boot_readback_state is None):
        raise ValueError("Native assembly observations require compact boot-handoff coverage without other SP probes")
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    reference = root / "downloads" / BASE
    freertos, heap, component = (work / n for n in ("freertos", "heap", "freertos_lifetimes"))
    shutil.copytree(root / "tm-cooperative-no-timeslicing/freertos", freertos, symlinks=True)
    shutil.copytree(root / "esp-idf-v5.2.5/components/heap", heap, symlinks=True)
    shutil.copytree(observer, component)
    shutil.copytree(observer, output / "original-observer")
    shutil.copyfile(tail, output / "message-tail.c")
    extension = None
    if irq_coverage:
        extension = (observer.parent / "freertos_stack_coverage/stack-coverage.inc").read_text()
        (output / "stack-coverage.inc").write_text(extension)
    startup=None
    if startup_coverage:
        folder=observer.parent/"freertos_startup_stack"
        startup=(folder/"startup-stack.inc").read_text()
        shutil.copyfile(folder/"startup-stack.inc",output/"startup-stack.inc")
        shutil.copyfile(folder/"startup-entry.S",component/"startup-entry.S")
    handoff = None
    if startup_handoff:
        handoff = (observer.parent / "freertos_startup_stack/heap-handoff.inc").read_text()
        (output / "heap-handoff.inc").write_text(handoff)
    tick = None
    if tick_stacks:
        tick = (observer.parent / "freertos_tick_stacks.inc").read_text()
        (output / "tick-stacks.inc").write_text(tick)
    lifecycle = None
    if lifecycle_validation:
        lifecycle = (observer.parent / "freertos_task_lifecycle_validation.inc").read_text()
        (output / "task-lifecycle-validation.inc").write_text(lifecycle)
    peak = None
    if peak_context:
        peak = (observer.parent / "freertos_peak_context.inc").read_text()
        (output / "peak-context.inc").write_text(peak)
    readback = None
    if boot_readback_state is not None:
        folder = observer.parent / "freertos_startup_stack"
        readback = (folder / "boot-readback.inc").read_text()
        shutil.copyfile(folder / "boot-readback.inc", output / "boot-readback.inc")
        shutil.copyfile(folder / "boot-readback-entry.S", component / "boot-readback-entry.S")
    step = None
    if step_stacks:
        folder = observer.parent / "continuous_step_stacks"
        step = (folder / "step-stacks.inc").read_text()
        shutil.copytree(folder, output / "continuous-step-source")
        shutil.copyfile(root / "esp-idf-v5.2.5/components/xtensa/xtensa_context.S", output / "continuous-step-source/native-context.S")
        for name in ("step-entry.S", "step-state.h"):
            shutil.copyfile(folder / name, component / name)
    boundary = None
    if boundary_stacks:
        boundary = (observer.parent / "function_boundary_stacks/boundary-stacks.inc").read_text()
        (output / "boundary-stacks.inc").write_text(boundary)
    native = None
    if native_sp:
        from measure_esp32_native_sp import EXTENSION, PORTASM, patch_portasm
        native = (EXTENSION / "native-stacks.inc").read_text()
        (output / "native-stacks.inc").write_text(native)
        port = freertos / PORTASM
        shutil.copyfile(port, output / "native-portasm-original.S")
        port.write_text(patch_portasm(port.read_text()))
        for name in ("native-entry.S", "native-state.h"):
            shutil.copyfile(EXTENSION / name, component / name)
        if single_threshold_guards:
            from guard_esp32_sp_threshold import native_source
            target = component / 'native-entry.S'
            target.write_text(native_source(target.read_text()))
    (component / "census.c").write_text(observer_source((observer / "census.c").read_text(), tail.read_text(), extension,startup,tick,lifecycle,compact,handoff,peak,readback,step,boundary,boundary_fast_pruning,native,boundary_inline_guards,single_threshold_guards))
    cmake_file = component / "CMakeLists.txt"
    cmake_file.write_text(replace_once(cmake_file.read_text(), "app_main fputs vTaskDelay vPortTCBPreDeleteHook",
        "app_main tm_thread_sleep vTaskDelay vPortTCBPreDeleteHook") +
        ('\nidf_build_set_property(LINK_OPTIONS "-Wl,--wrap=xPortStartScheduler" APPEND)\n' if irq_coverage else ""))
    if startup_coverage:
        cmake_file.write_text(replace_once(cmake_file.read_text(),'SRCS "census.c"','SRCS "census.c" "startup-entry.S"')+
            '\nidf_build_set_property(LINK_OPTIONS "-Wl,--wrap=heap_caps_enable_nonos_stack_heaps" APPEND)\n'
            'idf_build_set_property(LINK_OPTIONS "-Wl,-e,bench_startup_entry" APPEND)\n')
    if boot_readback_state is not None:
        cmake_file.write_text(replace_once(cmake_file.read_text(), '"startup-entry.S"',
            '"startup-entry.S" "boot-readback-entry.S"').replace('"-Wl,-e,bench_startup_entry"',
            '"-Wl,-e,bench_boot_handoff_entry"') +
            '\ntarget_compile_definitions(${COMPONENT_LIB} PRIVATE BENCH_BOOT_STATE_ADDRESS=' + hex(boot_readback_state) + ')\n')
    if step_stacks:
        cmake_file.write_text(replace_once(cmake_file.read_text(), 'SRCS "census.c"', 'SRCS "census.c" "step-entry.S"') +
            '\nidf_build_set_property(LINK_OPTIONS "-Wl,-u,bench_step_debug_handler" APPEND)\n')
    if boundary_fast_pruning:
        shutil.copyfile(observer.parent / "function_boundary_stacks/boundary-fast-entry.S", component / "boundary-fast-entry.S")
        cmake_file.write_text(replace_once(cmake_file.read_text(), 'SRCS "census.c"', 'SRCS "census.c" "boundary-fast-entry.S"'))
    if native_sp:
        cmake_file.write_text(replace_once(cmake_file.read_text(), 'SRCS "census.c"', 'SRCS "census.c" "native-entry.S"'))
    launcher = ''
    if boundary_inline_guards:
        script = Path(__file__).with_name('guard_esp32_boundary_calls.py')
        shutil.copyfile(script, output / script.name)
        if stack_entry_guards:
            from guard_esp32_stack_entries import DYNAMIC, dynamic_source
            for name in DYNAMIC:
                source = heap / name
                saved = output / 'dynamic-stack-sources' / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, saved.with_suffix(saved.suffix + '.original'))
                source.write_text(dynamic_source(name, source.read_text()))
                shutil.copyfile(source, saved)
            script = Path(__file__).with_name('guard_esp32_stack_entries.py')
            shutil.copyfile(script, output / script.name)
            shutil.copyfile(Path(__file__).with_name('inspect_esp32_stack_entry_coverage.py'), output / 'inspect_esp32_stack_entry_coverage.py')
        if single_threshold_guards:
            script = Path(__file__).with_name('guard_esp32_sp_threshold.py')
            shutil.copyfile(script, output / script.name)
        launcher = ('\nforeach(name main freertos heap)\n'
            '    idf_component_get_property(lib ${name} COMPONENT_LIB)\n'
            '    set_property(TARGET ${lib} PROPERTY C_COMPILER_LAUNCHER "' + str(root / 'reproduction-audit-runtime/bin/python') +
            ';' + str(script) + ';--evidence;' + str(output / 'inline-assembly') + '")\nendforeach()\n')
    (component / "app/CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.16)\nset(COMPONENTS main freertos_lifetimes)\n'
        'include($ENV{IDF_PATH}/tools/cmake/project.cmake)\nproject(iotosbench_tm)\n' + launcher +
        ('' if stack_entry_guards else
            BOUNDARY_CMAKE.replace('-finstrument-functions>', '-finstrument-functions;-finstrument-functions-exclude-file-list=.h>')
            if boundary_header_exclusion else BOUNDARY_CMAKE if boundary_stacks else ''))
    main = component / "app/main"
    main.mkdir()
    for name in ("main.c", "port.c", "test.c", "tm_override.h", "CMakeLists.txt"):
        shutil.copyfile(reference / name, main / name)
    original_test = root / "threadx-6.2.1_rel/utility/benchmarks/thread_metric/tm_message_processing_test.c"
    if original_test.read_bytes() != (reference / original_test.name).read_bytes():
        raise ValueError("Original Thread-Metric test changed")
    shutil.copyfile(original_test, output / original_test.name)
    config = freertos / "config/include/freertos/FreeRTOSConfig.h"
    if config.read_bytes() != (reference / "FreeRTOSConfig.h").read_bytes():
        raise ValueError("No-timeslicing kernel configuration differs")
    config.write_bytes(config.read_bytes() + b'\n#include "bench_task_trace.h"\n')
    shutil.copyfile(observer / "bench_task_trace.h", config.parent / "bench_task_trace.h")
    if tick_stacks:
        trace = config.parent / "bench_task_trace.h"
        trace.write_bytes(trace.read_bytes() + TICK_TRACE)
    if boundary_stacks:
        trace = config.parent / "bench_task_trace.h"
        trace.write_bytes(trace.read_bytes() + BOUNDARY_TRACE)
    if native_sp and not boundary_stacks:
        from measure_esp32_native_sp import NATIVE_TRACE
        trace = config.parent / "bench_task_trace.h"
        trace.write_bytes(trace.read_bytes() + NATIVE_TRACE)
    for name, edits in native_edits().items():
        path = heap / name
        original = output / "original-native/heap" / name
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, original)
        path.write_bytes(patched(path.read_bytes(), edits))
    shutil.copyfile(observer / "tlsf-observer.inc", heap / "tlsf/tlsf-observer.inc")
    shutil.copyfile(reference / "config", output / "config")
    gcc = root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env = dict(os.environ, IDF_PATH=str(root / "esp-idf-v5.2.5"), IDF_TOOLS_PATH=str(root / "idf-tools"),
        IDF_PYTHON_ENV_PATH=str(root / "idf-python-env"), ESP_ROM_ELF_DIR=str(root / "idf-tools/tools/esp-rom-elfs/20230320"),
        PATH=str(gcc)+":"+str(root / "idf-python-env/bin")+":"+str(root / "bin")+":"+os.environ["PATH"])
    cmake = str(root / "idf-tools/tools/cmake/3.30.2/bin/cmake")
    def run(args, name):
        with (output / name).open("x") as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    directory = work / "build"
    run([cmake, "-G", "Ninja", "-S", str(component / "app"), "-B", str(directory),
         "-DTM_TEST=message_processing", "-DTM_IRQ_FROM_CPU2=OFF", "-DSDKCONFIG="+str(output / "config"),
         "-DPYTHON="+str(root / "idf-python-env/bin/python"),
         "-DEXTRA_COMPONENT_DIRS="+";".join(map(str, (freertos, heap, component))),
         "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure.log")
    run([cmake, "--build", str(directory), "--parallel", "2"], "build.log")
    if (output / "config").read_bytes() != (reference / "config").read_bytes():
        raise ValueError("Observer changed original 100-Hz configuration")
    for source, name in (("iotosbench_tm.elf", "application.elf"), ("iotosbench_tm.bin", "application.bin"),
                         ("iotosbench_tm.map", "application.map"), ("bootloader/bootloader.bin", "bootloader.bin"),
                         ("partition_table/partition-table.bin", "partitions.bin"), ("compile_commands.json", "compile_commands.json")):
        shutil.copyfile(directory / source, output / name)
    shutil.copytree(component, output / "observer")
    for name in ("FreeRTOS-Kernel/tasks.c", "FreeRTOS-Kernel/queue.c", "FreeRTOS-Kernel/portable/xtensa/port.c", "heap_idf.c",
                 "config/include/freertos/FreeRTOSConfig.h") + (("FreeRTOS-Kernel/portable/xtensa/portasm.S",) if irq_coverage else ()):
        destination = output / "native-source/freertos" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(freertos / name, destination)
    if tick_stacks or boundary_stacks or native_sp:
        shutil.copyfile(config.parent / "bench_task_trace.h", output / "native-source/freertos/config/include/freertos/bench_task_trace.h")
    for name in native_edits():
        destination = output / "native-source/heap" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(heap / name, destination)
    if startup_coverage:
        for name in ("components/esp_system/port/cpu_start.c","components/heap/port/esp32/memory_layout.c",
                     "components/freertos/app_startup.c","components/esp_system/startup.c"):
            destination=output/"native-startup"/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/"esp-idf-v5.2.5"/name,destination)
    shutil.copyfile(__file__, output / "build-script.py")
    shutil.copyfile(Path(__file__).with_name("build_esp32_freertos_ram_lifetimes.py"), output / "native-patch-builder.py")
    for tool, args, name in (("gcc", ["--version"], "compiler.txt"), ("objdump", ["-d", str(output / "application.elf")], "disassembly.txt"),
                             ("nm", ["-S", str(output / "application.elf")], "symbols.txt")):
        run([str(gcc / ("xtensa-esp32-elf-"+tool)), *args], name)
    report = {"status":"build_pass_not_measured", "reference":BASE, "os":"FreeRTOS", "clock_mhz":240, "tick_hz":100,
        "cores":1, "workload":"unchanged original Thread-Metric message processing", "trace_capacity":128 if compact else 1024,
        "scope":("explicit validation command runs finite task lifetimes; original benchmark path remains linked and unchanged"
            if lifecycle_validation else "native heap registration through third original report; retained original tasks are not deleted"),
        "ranking_eligible":False, "full_live_ram_measured":False,
        "baseline_elf_sha256":digest(reference / "iotosbench_tm.elf"),
        **({"message_ordinary_irq_stack_coverage":True} if irq_coverage else {}),
        **({"application_startup_stack_coverage":True} if startup_coverage else {}),
        **({"native_tick_stack_snapshots":True} if tick_stacks else {}),
        **({"task_lifecycle_validation":True} if lifecycle_validation else {}),
        **({"compact_observer":True, "task_capacity":16} if compact else {}),
        **({"startup_heap_handoff":True} if startup_handoff else {}),
        **({"allocation_peak_context":True} if peak_context else {}),
        **({"continuous_instruction_stack_trace":True} if step_stacks else {}),
        **({"compiler_boundary_stack_trace":True} if boundary_stacks else {}),
        **({"compiler_boundary_header_exclusion":True} if boundary_header_exclusion else {}),
        **({"compiler_boundary_fast_pruning":True} if boundary_fast_pruning else {}),
        **({"compiler_boundary_inline_guards":True} if boundary_inline_guards else {}),
        **({"compiler_stack_entry_guards":True} if stack_entry_guards else {}),
        **({"single_threshold_guards":True} if single_threshold_guards else {}),
        **({"native_assembly_sp_trace":True} if native_sp else {}),
        **({"boot_readback_state_address":boot_readback_state} if boot_readback_state is not None else {}),
        "files":{p.relative_to(output).as_posix():digest(p) for p in output.rglob("*") if p.is_file()}}
    (output / "build.json").write_text(json.dumps(report, indent=2)+"\n")
    print("Original-message lifecycle observer built; no board measurement yet", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    for option in ("workspace", "output", "observer", "tail"):
        parser.add_argument("--"+option, type=Path, required=True)
    parser.add_argument("--irq-coverage", action="store_true")
    parser.add_argument("--startup-coverage", action="store_true")
    parser.add_argument("--startup-handoff", action="store_true")
    parser.add_argument("--tick-stacks", action="store_true")
    parser.add_argument("--lifecycle-validation", action="store_true")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--peak-context", action="store_true")
    parser.add_argument("--boot-readback-state", type=lambda s: int(s, 0))
    args = parser.parse_args()
    build(args.root, args.workspace, args.output, args.observer, args.tail, args.irq_coverage,args.startup_coverage,args.tick_stacks,args.lifecycle_validation,args.compact,args.startup_handoff,args.peak_context,args.boot_readback_state)
