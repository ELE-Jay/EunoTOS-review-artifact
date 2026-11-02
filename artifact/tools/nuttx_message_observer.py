"""Reuse the audited PH4 native hooks around the unchanged original TM task."""
from pathlib import Path

BASE = "tm-nuttx-native-aligned-v1/message_processing"
TICK_NATIVE = ('arch/xtensa/src/esp32/esp32_timerisr.c',
    'arch/xtensa/src/common/xtensa_irqdispatch.c', 'arch/xtensa/include/irq.h',
    'include/nuttx/sched.h', 'sched/sched/sched_processtimer.c')
COMPACT_CAPACITIES = {'events':128,'stack_events':32,'stack_slots':16,'identities':128,'live_blocks':64}


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Native observer anchor missing/ambiguous: " + old)
    return text.replace(old, new, 1)


def compact_sources(files):
    """Reduce storage limits only; keep native hooks, payloads and overflow checks."""
    files = dict(files)
    for name in ('base-census.inc','census.c'):
        text = files[name]
        text = text.replace('stacks[128]','stacks[16]').replace('block_bytes[128]','block_bytes[16]')
        text = text.replace(' < 128',' < 16').replace(' == 128',' == 16')
        files[name] = text
    text = files['nuttx_message_trace.h']
    for old,new in (('message_events[1024]','message_events[128]'),
                    ('message_count == 1024','message_count == 128'),
                    ('message_stacks[128]','message_stacks[32]'),
                    ('message_stack_count == 128','message_stack_count == 32')):
        text = replace_once(text,old,new)
    files['nuttx_message_trace.h'] = text
    text = files['nuttx_message_identity.h']
    for old,new in (('message_identities[256]','message_identities[128]'),
                    ('message_live[256]','message_live[64]'),
                    ('if (i == 256 || !message_count)','if (i == 128 || !message_count)'),
                    ('if (i == 256) { message_overflow++; break; }','if (i == 64) { message_overflow++; break; }')):
        text = replace_once(text,old,new)
    files['nuttx_message_identity.h'] = text
    return files


def sources(observer, identities=False, startup=False, tick=False, control=False, lifecycle=False, compact=False):
    if compact and (not identities or not startup or tick):
        raise ValueError('Compact observer requires startup/identities without periodic stack sampling')
    observer = Path(observer)
    marker = "int __real_hartstone_main(int argc, char **argv);"
    base, _ = (observer / "nuttx_heap_events/census.c").read_text().split(marker, 1)
    base = replace_once(base, "static struct mm_heap_s *target;", '#include "nuttx_message_trace.h"\nstatic struct mm_heap_s *target;')
    base = replace_once(base, "    current = peak = sizeof(*heap);", "    current = peak = sizeof(*heap);\n    message_event(0, current, current, peak);")
    base = replace_once(base, "    events[kind]++;", "    events[kind]++;\n    message_event(kind, delta, current, peak);\n    oracle_requested = 1;")
    stacks, _ = (observer / "nuttx_stack_lifetimes.c").read_text().split(marker, 1)
    stacks = replace_once(stacks, "            owned_creates++;", "            owned_creates++;\n            message_stack(1, tcb, stacks[i].allocation, stacks[i].bytes, block_bytes[i]);")
    stacks = replace_once(stacks, "            stack_blocks -= block_bytes[i];", "            message_stack(2, tcb, stacks[i].allocation, stacks[i].bytes, block_bytes[i]);\n            stack_blocks -= block_bytes[i];")
    # Retain the already audited allocator self-test, outside the TM workload.
    old = (observer / "nuttx_heap_events/census.c").read_text()
    validation = old.split('    if (argc == 2 && strcmp(argv[1], "--validate-observer") == 0) {', 1)[1].split('    printf("RAM_EVENTS BEGIN', 1)[0]
    validation = replace_once(validation, '        puts("RAM_EVENTS END");', '        message_dump();\n        puts("NUTTX_MESSAGE_RAM VALIDATION END");')
    tail = (observer / "nuttx_message_tail.c").read_text()
    tail = replace_once(tail, "/* ORIGINAL_ALLOCATOR_VALIDATION */", validation)
    result = {"base-census.inc":base, "census.c":stacks+tail,
              "nuttx_message_trace.h":(observer / "nuttx_message_trace.h").read_text()}
    if lifecycle:
        if not identities:
            raise ValueError("Task lifecycle validation requires allocation-address history")
        name = "nuttx_task_lifecycle_validation.inc"
        result[name] = (observer / name).read_text()
        result["census.c"] = replace_once(result["census.c"], "static unsigned message_reports;",
            '#include "' + name + '"\n\nstatic unsigned message_reports;')
        result["census.c"] = replace_once(result["census.c"], '        message_dump();',
            '        bench_n_validate_task_lifetimes();\n        report("validation-lifecycles");\n        message_dump();')
    if identities:
        result["base-census.inc"] = replace_once(base, '#include "nuttx_message_trace.h"',
            '#include "nuttx_message_trace.h"\n#include "nuttx_message_identity.h"')
        result["census.c"] = replace_once(result["census.c"], "static void message_dump(void)\n{",
            "static void message_dump(void)\n{\n    message_identity_dump(target);")
        result["nuttx_message_identity.h"] = (observer / "nuttx_message_identity.h").read_text()
    if startup:
        if not identities:
            raise ValueError("Startup observation extends the frozen allocation-identity image")
        result["startup-stack.inc"]=(observer/"nuttx_startup_stack/startup-stack.inc").read_text()
        result["startup-entry.S"]=(observer/"nuttx_startup_stack/startup-entry.S").read_text()
        result["census.c"]=replace_once(result["census.c"],"static unsigned message_reports;",
            '#include "startup-stack.inc"\n\nstatic unsigned message_reports;')
        result["census.c"]=replace_once(result["census.c"],"static void message_dump(void)\n{",
            "static void message_dump(void)\n{\n    message_startup_report();")
    if tick:
        if not startup:
            raise ValueError("Tick snapshots require the original address/startup observer")
        result['nuttx_tick_stacks.inc']=(observer/'nuttx_tick_stacks.inc').read_text()
        result['census.c']=replace_once(result['census.c'], 'static unsigned message_reports;',
            '#include "nuttx_tick_stacks.inc"\n\nstatic unsigned message_reports;')
        result['census.c']=replace_once(result['census.c'],
            '    if (++message_reports == 4) message_finish();',
            '    if (++message_reports == 1) bench_n_live_enabled = 1;\n'
            '    if (message_reports == 4) {\n        bench_n_live_enabled = 0;\n'
            '        bench_n_live_report();\n        message_finish();\n    }')
    if control:
        if not tick:
            raise ValueError("Same-image control requires native tick snapshots")
        result['nuttx_tick_control.inc']=(observer/'nuttx_tick_control.inc').read_text()
        result['census.c']=replace_once(result['census.c'], '#include "nuttx_tick_stacks.inc"',
            '#include "nuttx_tick_control.inc"\n#include "nuttx_tick_stacks.inc"')
        result['census.c']=replace_once(result['census.c'],
            '    if (++message_reports == 1) bench_n_live_enabled = 1;',
            '    if (++message_reports == 1) {\n        bench_n_live_enabled = bench_n_tick_requested;\n'
            '        bench_n_tick_window = 1;\n    }')
        result['census.c']=replace_once(result['census.c'], '        bench_n_live_enabled = 0;',
            '        bench_n_tick_window = 0;\n        bench_n_live_enabled = 0;')
        result['census.c']=replace_once(result['census.c'], '        bench_n_live_report();',
            '        bench_n_live_report();\n        bench_n_tick_cost_report();')
        result['census.c']=replace_once(result['census.c'], '    setvbuf(stdout, NULL, _IONBF, 0);',
            '    setvbuf(stdout, NULL, _IONBF, 0);\n    bench_n_tick_setup(argc, argv);')
        result['nuttx_tick_stacks.inc']=replace_once(result['nuttx_tick_stacks.inc'],
            '    if (bench_n_live_enabled) {',
            '    uint32_t begin = bench_n_tick_window ? bench_n_tick_ccount() : 0;\n'
            '    if (bench_n_live_enabled) {')
        result['nuttx_tick_stacks.inc']=replace_once(result['nuttx_tick_stacks.inc'],
            '    __real_nxsched_process_timer();',
            '    if (bench_n_tick_window) {\n        uint32_t cycles = bench_n_tick_ccount() - begin;\n'
            '        bench_n_tick_calls++;\n        bench_n_tick_cycles += cycles;\n'
            '        if (cycles > bench_n_tick_max) bench_n_tick_max = cycles;\n    }\n'
            '    __real_nxsched_process_timer();')
    return compact_sources(result) if compact else result


def makefile(original,startup=False):
    result=replace_once(original, "CSRCS    += port.c test.c", "CSRCS    += port.c test.c census.c\nCFLAGS += -I. -I$(TOPDIR)/mm/mm_heap -I$(TOPDIR)/arch/xtensa/src/esp32")
    return replace_once(result,"include $(APPDIR)/Application.mk",
        "ASRCS += startup-entry.S\n\ninclude $(APPDIR)/Application.mk") if startup else result
