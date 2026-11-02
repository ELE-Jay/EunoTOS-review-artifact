#!/usr/bin/env python3
"""Audit unchanged RIOT message iterations on Rhino, retaining native queue and SDK boundaries."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import shutil
from urllib.request import urlopen
from elftools.elf.elffile import ELFFile

from build_esp32_riot_msg_alios import NATIVE, LIBRARIES
from collect_esp32_riot_msg_alios_control import FUNCTIONS, NORETURN, collector_source
from audit_esp32_riot_original import UPSTREAM as RIOT_UPSTREAM, check_manifest
from audit_esp32_rhealstone_alios import UPSTREAM
from audit_esp32_riot_native_message import HEADER_URL, HEADER_SHA, GCC_SOURCE
from audit_esp32_alios_tm import check_native_port
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_resources import audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture, read_control_rows
from audit_esp32_zephyr_syskernel_sema import literal_word
from audit_esp32_zephyr_isr import rhino_vector_dispatch, irq_archive_member
from audit_esp32_zephyr_latency_alios import hardware_tick_divisors
from audit_esp32_iperf_original import ANSI
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "firmware/bsp/esp32/riot_msg_pingpong"
REFERENCE = ROOT / "artifacts/reports/riot-flags-alios-v1"
BEGIN = ("RIOT MSG PORT BEGIN AliOS-Rhino original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
    "controller=10 peer=9 stack=3584 timer=ISR channel=2 resolution_us=1 message_bytes=8 queue_slots=1 logical_sender=0")
FINAL = "RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 buffered_peak=0 free_bytes=8 min_free_bytes=8 waiters=1 alarm_count=1 isr=1"


def sources(folder):
    names = {"source/" + n: RIOT_UPSTREAM + "tests/bench/msg_pingpong/" + n for n in ("main.c", "README.md")}
    names.update({"original-semantics/" + n: RIOT_UPSTREAM + n for n in ("core/msg.c", "core/include/msg.h", "core/include/sched.h")})
    names.update({"native-source/" + n: UPSTREAM + n for n in NATIVE})
    names.update({"native-libraries/" + Path(n).name: UPSTREAM + n for n in LIBRARIES})
    names["rhino-portasm-pinned.S"] = UPSTREAM + "platform/arch/xtensa/lx6/portasm.S"
    names["compiler-stdatomic.h"] = HEADER_URL
    names.update({"licenses/" + n: GCC_SOURCE + n for n in ("COPYING3", "COPYING.RUNTIME")})
    return [{"path": p, "url": u, "sha256": sha(folder / p)} for p, u in sorted(names.items())]


def provenance(folder):
    (folder / "licenses").mkdir(exist_ok=True)
    for name in ("COPYING3", "COPYING.RUNTIME"):
        shutil.copyfile(ROOT / "artifacts/reports/esp32-riot-native-message-v3/licenses" / name, folder / "licenses" / name)
    known = set()
    for p in (ROOT / "artifacts/reports").rglob("official-*.json"):
        data = json.loads(p.read_text())
        if isinstance(data, list):
            known.update((r["url"], r["sha256"]) for r in data if isinstance(r, dict) and {"url", "sha256"} <= r.keys())
    proof = sources(folder)
    for row in proof:
        if (row["url"], row["sha256"]) not in known:
            with urlopen(row["url"], timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("Fixed original/native/compiler input differs: " + row["path"])
    (folder / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")


def build(folder, verify_upstream=False):
    metadata = json.loads((folder / "build.json").read_text())
    if metadata["status"] != "build_pass_not_measured" or metadata["board_resets"] or metadata["ranking_eligible"]:
        raise ValueError("Build-only original message candidate misqualified")
    if any(not (folder / n).resolve().is_relative_to(folder.resolve()) or sha(folder / n) != v for n, v in metadata["files"].items()):
        raise ValueError("Source/image manifest differs")
    for name in ("main.c", "README.md"):
        if (folder / "source" / name).read_bytes() != (ROOT / "artifacts/reports/riot-original-v1/msg_pingpong/source" / name).read_bytes():
            raise ValueError("Original RIOT message program changed")
    files = [(p.relative_to(PORT / "alios"), p) for p in (PORT / "alios").rglob("*") if p.is_file()]
    files += [(Path("include") / n, PORT / "include" / n) for n in ("msg.h", "xtimer.h")]
    files += [(Path("include") / n, PORT.parent / "riot_yield_pingpong/include" / n) for n in ("clk.h", "macros/units.h")]
    files += [(Path("build-script.py"), ROOT / "tools/build_esp32_riot_msg_alios.py")]
    if any((folder / n).read_bytes() != p.read_bytes() for n, p in files):
        raise ValueError("Current message adapter/build recipe differs")
    for name in ("sdkconfig.h", "k_config.h", "rhino-port-pinned.c", "rhino-portasm-pinned.S", "rhino-vectors-pinned.S"):
        if (folder / name).read_bytes() != (REFERENCE / name).read_bytes():
            raise ValueError("Native scheduler/board profile changed: " + name)
    if (folder / "reference-config").read_bytes() != (REFERENCE / "config").read_bytes():
        raise ValueError("Reference configuration differs")
    old, new = [dict(re.findall(r"^(\w+)=(.*)$", p.read_text(), re.M)) for p in (REFERENCE / "config", folder / "config")]
    if {k: (old.get(k), new.get(k)) for k in old.keys() | new.keys() if old.get(k) != new.get(k)} != {
            "AOS_APP_RIOT_FLAGS": ("y", None), "AOS_APP_RIOT_MSG": (None, "y"), "AOS_BUILD_APP": ('"riot_flags"', '"riot_msg"')}:
        raise ValueError("Configuration differs beyond the selected original application")
    if sha(folder / "compiler-stdatomic.h") != HEADER_SHA or "13.2.0" not in (folder / "compiler.txt").read_text() or \
            re.findall(r"\S*stdatomic\.h", (folder / "original-dependencies.d").read_text()) != ["app/example/riot_msg/native-compiler-headers/stdatomic.h"]:
        raise ValueError("Actual original atomic header route/compiler differs")
    if verify_upstream:
        provenance(folder)
    if json.loads((folder / "official-source.json").read_text()) != sources(folder):
        raise ValueError("Fixed source/library/compiler proof differs")
    compatibility = folder / "compiler-compatibility"
    abi = json.loads((compatibility / "abi.json").read_text())
    wrapper = "xtensa-esp32-elf-gcc-legacy-newlib.sh"
    if abi["abi_size_checks"] != "pass" or abi["board_resets"] or abi["ranking_eligible"] or \
            (compatibility / wrapper).read_bytes() != (ROOT / "firmware/bsp/esp32/alios_board" / wrapper).read_bytes():
        raise ValueError("Legacy SDK compiler compatibility route differs")
    sizes = []
    for row in abi["probes"]:
        path = compatibility / (row["compiler"] + ".o")
        if sha(path) != row["object_sha256"]:
            raise ValueError("ABI probe object changed")
        with path.open("rb") as stream:
            value = {s.name: s["st_size"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols() if s.name.startswith("abi_")}
        if value != row["sizes"]:
            raise ValueError("Actual compiled ABI probe differs")
        sizes.append(value)
    if sizes != [{"abi_time": 4, "abi_stat": 60, "abi_jmpbuf": 68, "abi_file": 104, "abi_reent": 240}] * 2:
        raise ValueError("Legacy C ABI sizes differ")
    if any(sha(compatibility / "legacy-headers" / n) != v for n, v in abi["legacy_header_sha256"].items()) or \
            any(sha(folder / "native-libraries" / Path(n).name) != v for n, v in abi["sdk_library_sha256"].items()):
        raise ValueError("Pinned SDK headers/libraries changed")
    commands = [shlex.split(s) for s in (folder / "build.log").read_text().splitlines() if " -c " in s and "xtensa-esp32-elf-gcc" in s]
    required = {n for n in NATIVE if n.endswith(".c")} | {"app/example/riot_msg/port.c", "app/example/riot_msg/original.c",
        "platform/arch/xtensa/lx6/port.c", "platform/arch/xtensa/lx6/portasm.S", "platform/arch/xtensa/lx6/xtensa_vectors.S"}
    for args in commands:
        if "iotos-rhino-gcc13-legacy-tools" not in args[0] or "-DRHINO_CONFIG_TICKS_PER_SECOND=1" not in args or \
                any(a.endswith(".c") for a in args) and [a for a in args if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"]:
            raise ValueError("Actual compiler/tick/optimization differs")
    for n in required:
        selected = [args for args in commands if n in args]
        if len(selected) != 1 or any(a.startswith(("-DTEST_DURATION", "-Dmsg_send", "-Dmsg_receive")) for a in selected[0]) or \
                (n.endswith("original.c") and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("Original/native compilation incomplete or overridden: " + n)
    image_manifest = "".join(v + "  " + n + "\n" for n, v in sorted(metadata["files"].items()))
    if (folder / "image.sha256").read_text() != image_manifest:
        raise ValueError("Derived image manifest differs")
    check_manifest(folder, "msg-control.sha256")
    if {s.split(maxsplit=1)[1] for s in (folder / "msg-control.sha256").read_text().splitlines()} != {
            "application.elf", "image.sha256", "msg-control-flow.txt", "executed-msg-control.py"}:
        raise ValueError("Control supplement does not bind its complete input/output set")
    if (folder / "executed-msg-control.py").read_text() != collector_source((ROOT / "tools/collect_esp32_rhealstone_irq_control.py").read_text()):
        raise ValueError("Control decoder recipe differs")
    with (folder / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        control = read_control_rows((folder / "msg-control-flow.txt").read_text(), "RIOT MSG CONTROL", elf, symbols, set(FUNCTIONS), noreturn=NORETURN)
        layouts = set()
        for cu in elf.get_dwarf_info().iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_typedef" or not die.attributes.get("DW_AT_name") or die.attributes["DW_AT_name"].value != b"kbuf_queue_t":
                    continue
                body = die.get_DIE_from_attribute("DW_AT_type")
                members = {m.attributes["DW_AT_name"].value.decode(): m for m in body.iter_children() if m.tag == "DW_TAG_member"}
                if {n: members[n].attributes["DW_AT_data_member_location"].value for n in
                        ("ringbuf", "cur_num", "peak_num", "min_free_buf_size")} != {
                        "ringbuf": 28, "cur_num": 60, "peak_num": 64, "min_free_buf_size": 68}:
                    raise ValueError("Compiled native buffered-peak layout differs")
                ring = members["ringbuf"].get_DIE_from_attribute("DW_AT_type")
                while ring.tag in ("DW_TAG_typedef", "DW_TAG_const_type"):
                    ring = ring.get_DIE_from_attribute("DW_AT_type")
                free = [m.attributes["DW_AT_data_member_location"].value for m in ring.iter_children()
                        if m.tag == "DW_TAG_member" and m.attributes["DW_AT_name"].value == b"freesize"]
                if free != [16]:
                    raise ValueError("Native ring-buffer free-space field differs from the measured 44-byte offset")
                layouts.add(body.attributes["DW_AT_byte_size"].value)
        if layouts != {84} or symbols.get_symbol_by_name("messages")[0]["st_size"] != 84:
            raise ValueError("Native queue type/object layout is not fully witnessed")
        stack = symbols.get_symbol_by_name("_stack")[0]
        aligned = ((stack["st_value"] + 3584) & ~15) - ((stack["st_value"] + 15) & ~15)
        if stack["st_size"] != 3584 or not 3554 <= aligned <= 3584 or symbols.get_symbol_by_name("message_storage")[0]["st_size"] != 8:
            raise ValueError("Original stack or native single-slot storage changed")
        literal_bindings = (("riot_original_main", "_second_thread"), ("riot_original_main", "_timer_callback"),
            ("thread_create", "messages"), ("msg_send", "messages"), ("msg_receive", "messages"),
            ("xtimer_set", "alarm_expired"), ("alarm_expired", "stop_argument"), ("alarm_expired", "stop_callback"),
            ("krhino_buf_queue_send", "memcpy"))
        for caller, target in literal_bindings:
            if not any(literal_word(elf, row, int(m[1])) == symbols.get_symbol_by_name(target)[0]["st_value"]
                       for row in control[caller].values() if (m := re.search(r"l32r\s+a(\d+),", row))):
                raise ValueError("Actual object/callback/copy literal differs: " + caller + " -> " + target)
        patterns = {"msg_send": (r"movi\.n\s+a12, 8$",), "msg_receive": (r"movi\.n\s+a12, -1$", r"movi\s+a13, -1$"),
            "krhino_buf_queue_send": (r"s32i\s+a8, a7, 64$", r"s32i\.n\s+a8, a7, 60$", r"callx8\s+a8$"),
            "alarm_expired": (r"l32i\.n\s+a10, a9, 0$", r"callx8\s+a8$"),
            "controller_entry": (r"l32i\s+a10, a2, 64$", r"bnez",)}
        for name, patterns_for_body in patterns.items():
            if any(not any(re.search(p, r) for r in control[name].values()) for p in patterns_for_body):
                raise ValueError("Original/native size, wait or monotone buffered-peak operand differs: " + name)
    machine = calls(folder, required=[("riot_original_main", "thread_create"), ("riot_original_main", "xtimer_set"),
        ("riot_original_main", "msg_send"), ("_second_thread", "msg_receive"),
        ("thread_create", "krhino_fix_buf_queue_create"), ("thread_create", "krhino_task_create"),
        ("msg_send", "krhino_buf_queue_send"), ("msg_receive", "krhino_buf_queue_recv"),
        ("krhino_buf_queue_send", "ringbuf_push"), ("krhino_buf_queue_send", "pend_task_wakeup"),
        ("krhino_buf_queue_send", "core_sched"), ("krhino_buf_queue_recv", "pend_to_blk_obj"),
        ("controller_entry", "riot_original_main"), ("controller_entry", "krhino_task_del"),
        ("controller_entry", "krhino_buf_queue_del"), ("controller_entry", "esp_intr_free"),
        ("xtimer_set", "timer_init"), ("xtimer_set", "timer_set_alarm_value"), ("xtimer_set", "timer_isr_register"),
        ("xtimer_set", "timer_start"), ("espos_isr_enter", "krhino_intrpt_enter"), ("espos_isr_exit", "krhino_intrpt_exit")],
        require_iram=False, supplemental="\n".join(row for rows in control.values() for row in rows.values()))
    for row in machine:
        row["instructions"] = sorted(set(row["instructions"]))
    profile = check_native_port(folder, allow_nested=True, gcc13_noop=True)
    if profile.startswith("historical"):
        raise ValueError("Unsafe historical context port selected")
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    mapping, link = (folder / "application.map").read_text(), (folder / "link.opts").read_text()
    for library, member, names in (("libdriver.a", "timer.o", tuple(n for n in FUNCTIONS if n.startswith("timer_"))),
                                  ("libesp32.a", "intr_alloc.o", ("esp_intr_alloc_intrstatus", "esp_intr_free"))):
        if "platform/mcu/esp32/lib/" + library not in link:
            raise ValueError("Pinned SDK archive link absent")
        with io.BytesIO(irq_archive_member(folder / "native-libraries" / library, member.encode())) as stream:
            native = ELFFile(stream)
            for name in names:
                if native.get_section_by_name(".text." + name) is None or not re.search(r"\.text\." + name +
                        r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+.*" + re.escape(library + "(" + member + ")"), mapping):
                    raise ValueError("Pinned native SDK member linkage absent: " + name)
    return {"audit": "pass", "os": "AliOS-Rhino", "build_manifest_sha256": sha(folder / "build.json"),
        "original_test_body_unchanged": True, "original_duration_us": 1000000,
        "clock_mhz": 240, "cores": 1, "tick_hz": 1, "compiler": "GCC13 / GCC5 headers / pinned SDK libc", "optimization": "Os",
        "official_inputs_checked": len(sources(folder)), "source_compiled_units": len(commands), "machine_calls": machine,
        "branch_aware_functions_checked": len(FUNCTIONS), "native_port": profile, "aligned_peer_storage_bytes": aligned,
        "native_vector": rhino_vector_dispatch(folder, allow_literal_annotation=True), "tick_divisors": hardware_tick_divisors(folder),
        "board_resets": 0, "ranking_eligible": False, "message_bytes": 8, "queue_slots": 1,
        "boundary": "Original one-way message iteration count, not RTT or isolated API latency. Higher-priority sole receiver; "
            "native full-queue send is an error, not a general blocking RIOT API. Monotone native buffered peak is checked after the window. "
            "Original opaque payload is not checked. SDK/background and native object boundaries retained."}


def capture(folder, index, aligned):
    rows = read_raw_capture(folder, index)
    lines = [ANSI.sub("", r["line"]).strip() for r in rows]
    stack = "RIOT MSG NATIVE STACK nominal=3584 aligned=" + str(aligned)
    required = ("load image", "Welcome to AliOS Things", BEGIN, "main starting", FINAL, stack, "RIOT MSG PORT END")
    if sum(s.startswith("rst:0x") for s in lines) != 1 or any(lines.count(s) != 1 for s in required) or lines[-1] != required[-1] or \
            any(re.search(r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation|Exception", s, re.I) for s in lines):
        raise ValueError("Rhino original message reset/profile/queue/completion differs")
    found = [(i, json.loads(s)) for i, s in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', s)]
    timers = [(i, re.fullmatch(r"RIOT MSG NATIVE TIMER counter_us=(\d+) alarm_count=1 irq_released=1", s))
              for i, s in enumerate(lines) if s.startswith("RIOT MSG NATIVE TIMER")]
    retired = [(i, re.fullmatch(r"RIOT MSG PORT RETIRE tasks_before=(\d+) tasks_after=(\d+) queues_before=(\d+) queues_after=(\d+)", s))
               for i, s in enumerate(lines) if s.startswith("RIOT MSG PORT RETIRE")]
    if len(found) != 1 or len(timers) != 1 or not timers[0][1] or len(retired) != 1 or not retired[0][1]:
        raise ValueError("Original count or native timer/retirement absent")
    i, result = found[0]; j, timer = timers[0]; k, retire = retired[0]
    order = (lines.index(BEGIN), lines.index("main starting"), i, lines.index(FINAL), lines.index(stack), j, k, len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= result["result"] <= 0xffffffff or result["ticks"] != 240000000 // result["result"] or \
            not 1000000 <= int(timer[1]) <= 0xffffffff or int(retire[1]) < 2 or retire[1] != retire[2] or retire[3] != retire[4] or \
            rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Original formula/window or native resource retirement differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": result["result"], "original_ticks": result["ticks"],
        "tasks_before": int(retire[1]), "tasks_after": int(retire[2]), "queues_before": int(retire[3]), "queues_after": int(retire[4]),
        "buffered_peak": 0, "direct_copy_only_witnessed_by_native_peak": True, "timer_counter_us": int(timer[1]),
        "uart_sha256": sha(folder / ("reset%d.jsonl" % index)), "raw_sha256": sha(folder / ("reset%d.raw" % index))}


def audit(folder, source):
    metadata = envelope(folder)
    if metadata["kind"] != "riot-msg-alios" or metadata["board_mac"] != "34:98:7a:a2:85:28" or metadata["independent_resets"] != 3:
        raise ValueError("Wrong original Rhino message campaign")
    proof = build(source)
    if any(sha(p) != sha(source / p.name) for p in (folder / "build").iterdir()):
        raise ValueError("Collected Rhino original/native image differs")
    verified(folder / "captures", folder / "build", metadata["board_mac"])
    independent_captures(folder / "captures")
    runs = []
    for index in (1, 2, 3):
        verified(folder / "captures", folder / "build", metadata["board_mac"], logs=("verify-run%d.log" % index,))
        runs.append(capture(folder / "captures", index, proof["aligned_peer_storage_bytes"]))
    return {"audit": "pass", "os": "AliOS-Rhino", "build": proof, "runs": runs,
        "original_counts": [r["original_count"] for r in runs], "independent_resets": 3,
        "original_flash_restored": True, "ranking_eligible": False, "energy_measured": False,
        "payload_correctness_validated": False, "external_independent_replication": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.capture, args.build) if args.capture else build(args.build, args.verify_upstream)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
