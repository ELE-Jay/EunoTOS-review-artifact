#!/usr/bin/env python3
"""Bind the unchanged one-second RIOT program to native NuttX MQ and board evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from elftools.elf.elffile import ELFFile
from build_esp32_riot_msg_nuttx import NATIVE
from audit_esp32_riot_original import UPSTREAM as RIOT_UPSTREAM
from audit_esp32_riot_yield_nuttx import UPSTREAM
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_zephyr_thread import read_raw_capture
from audit_esp32_resources import audit_elf_image
from audit_esp32_iperf_original import ANSI
from audit_esp32_zephyr_syskernel_sema import literal_word
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "firmware/bsp/esp32/riot_msg_pingpong"
REFERENCE = ROOT / "artifacts/reports/riot-yield-nuttx-v1/config"
BEGIN = ("RIOT MSG PORT BEGIN NuttX original=dd06b372 duration_us=1000000 clock=240 cores=1 tick=1 "
    "controller=150 peer=151 stack=3584 timer=ISR channel=2 resolution_us=1 message_bytes=8 queue_slots=1 logical_sender=0")


def sources(folder):
    names = {"source/" + n: RIOT_UPSTREAM + "tests/bench/msg_pingpong/" + n for n in ("main.c", "README.md")}
    names.update({"original-semantics/" + n: RIOT_UPSTREAM + n
                  for n in ("core/msg.c", "core/include/msg.h", "core/include/sched.h")})
    names.update({"native-source/" + n: UPSTREAM + n for n in NATIVE})
    return [{"path": n, "url": u, "sha256": sha(folder / n)} for n, u in sorted(names.items())]


def provenance(folder):
    known = set()
    for p in (ROOT / "artifacts/reports").rglob("official-*.json"):
        data = json.loads(p.read_text())
        if isinstance(data, list):
            known.update((r["url"], r["sha256"]) for r in data
                         if isinstance(r, dict) and {"url", "sha256"} <= r.keys())
    proof = sources(folder)
    for row in proof:
        if (row["url"], row["sha256"]) not in known:
            with urlopen(row["url"], timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest() != row["sha256"]:
                    raise ValueError("Native/original source differs from fixed upstream: " + row["path"])
    (folder / "official-source.json").write_text(json.dumps(proof, indent=2) + "\n")


def build(folder, verify_upstream=False):
    metadata = json.loads((folder / "build.json").read_text())
    if metadata["status"] != "build_pass_not_measured" or metadata["board_resets"] or metadata["ranking_eligible"]:
        raise ValueError("Unmeasured message build misqualified")
    for n, v in metadata["files"].items():
        if not (folder / n).resolve().is_relative_to(folder.resolve()) or sha(folder / n) != v:
            raise ValueError("Native message build/source manifest differs: " + n)
    for n in ("main.c", "README.md"):
        if (folder / "source" / n).read_bytes() != (ROOT / "artifacts/reports/riot-original-v1/msg_pingpong/source" / n).read_bytes():
            raise ValueError("Original RIOT message program changed")
    files = [(p.relative_to(PORT / "nuttx"), p) for p in (PORT / "nuttx").rglob("*") if p.is_file()]
    files += [(Path("include") / n, PORT / "include" / n) for n in ("msg.h", "xtimer.h")]
    files += [(Path("include") / n, PORT.parent / "riot_yield_pingpong/include" / n)
              for n in ("clk.h", "macros/units.h")]
    files += [(Path("build-script.py"), ROOT / "tools/build_esp32_riot_msg_nuttx.py"), (Path("reference-config"), REFERENCE)]
    if any((folder / n).read_bytes() != p.read_bytes() for n, p in files):
        raise ValueError("Current native message adapter/recipe/reference differs")
    baseline, actual = [dict(re.findall(r"^(CONFIG_\w+)=(.*)$", p.read_text(), re.M))
                        for p in (REFERENCE, folder / "config")]
    changes = {k: (baseline.get(k), actual.get(k)) for k in baseline.keys() | actual.keys()
               if k != "CONFIG_BASE_DEFCONFIG" and baseline.get(k) != actual.get(k)}
    if changes != {"CONFIG_EXAMPLES_RIOT_YIELD": ("y", None), "CONFIG_EXAMPLES_RIOT_MSG": (None, "y")} or \
            actual.get("CONFIG_USEC_PER_TICK") != "1000000" or actual.get("CONFIG_RR_INTERVAL") != "0" or \
            actual.get("CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ") != "240" or actual.get("CONFIG_SMP") == "y" or \
            actual.get("CONFIG_CANCELLATION_POINTS") == "y" or actual.get("CONFIG_STACK_COLORATION") != "y" or \
            "13.2.0" not in (folder / "compiler.txt").read_text():
        raise ValueError("NuttX profile differs beyond the selected builtin app")
    if verify_upstream:
        provenance(folder)
    if json.loads((folder / "official-source.json").read_text()) != sources(folder):
        raise ValueError("Fixed original/native source proof differs")
    commands = [shlex.split(s) for s in (folder / "build.log").read_text().splitlines()
                if s.startswith("xtensa-esp32-elf-gcc -c ")]
    for name in ("original.c", "port.c", *(n for n in NATIVE if n.endswith(".c"))):
        if name in ("original.c", "port.c"):
            file, scope = name, "/apps/examples/riot_msg/"
        elif name.startswith("libs/libc/"):
            file, scope = name[10:], "/nuttx/libs/libc"
        elif name.startswith(("sched/", "fs/")):
            prefix, file = name.split("/", 1)
            scope = "/nuttx/" + prefix
        else:
            file, scope = name.replace("arch/xtensa/src/esp32/", "chip/").replace("arch/xtensa/src/", ""), "/nuttx/arch/xtensa/src"
        selected = [args for args in commands if file in args and any(scope in a for a in args)]
        if len(selected) != 1 or [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", a)][-1:] != ["-Os"] or \
                any(a.startswith(("-DTEST_DURATION", "-Dmsg_send", "-Dmsg_receive")) for a in selected[0]) or \
                (name == "original.c" and "-Dmain=riot_original_main" not in selected[0]):
            raise ValueError("Actual original/native compiler invocation differs: " + name)
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    machine = calls(folder, required=[("riot_original_main", "thread_create"), ("riot_original_main", "xtimer_set"),
        ("riot_original_main", "msg_send"), ("_second_thread", "msg_receive"),
        ("thread_create", "mq_open"), ("thread_create", "pthread_create"), ("thread_create", "pthread_attr_setstack"),
        ("msg_send", "mq_send"), ("msg_receive", "mq_receive"),
        ("mq_send", "nxmq_send"), ("mq_receive", "nxmq_receive"),
        ("file_mq_send", "nxmq_do_send"), ("file_mq_receive", "nxmq_do_receive"),
        ("xtimer_set", "esp32_oneshot_initialize"), ("xtimer_set", "esp32_oneshot_start"),
        ("riot_msg_main", "riot_original_main"), ("riot_msg_main", "pthread_cancel"),
        ("riot_msg_main", "pthread_join"), ("riot_msg_main", "mq_getattr"),
        ("riot_msg_main", "mq_close"), ("riot_msg_main", "mq_unlink"),
        ("riot_msg_main", "esp32_oneshot_cancel")], require_iram=False)
    with (folder / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if len(symbols.get_symbol_by_name("_stack") or []) != 1 or symbols.get_symbol_by_name("_stack")[0]["st_size"] != 3584:
            raise ValueError("Original peer stack storage changed")
        copy_sites = []
        instructions = [(int(m[1], 16), m[2], m[3]) for m in re.finditer(
            r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+(.+)$", (folder / "disassembly.txt").read_text(), re.M)]
        for name in ("nxmq_do_send", "nxmq_do_receive"):
            function = symbols.get_symbol_by_name(name)[0]
            section = elf.get_section(function["st_shndx"])
            body = [(pc, word, text) for pc, word, text in instructions
                    if function["st_value"] <= pc < function["st_value"] + function["st_size"]]
            sites = []
            for pc, word, text in body:
                if not text.startswith("l32r\ta8,"):
                    continue
                row = "%x: %s %s" % (pc, word, text)
                if literal_word(elf, row, 8) != symbols.get_symbol_by_name("memcpy")[0]["st_value"]:
                    continue
                pair = next((r for r in body if r[0] == pc + 3), None)
                if pair is None or pair[1] != "0008e0" or pair[2] != "callx8\ta8":
                    raise ValueError("Native copy literal is not followed by its actual indirect call")
                for address, encoded in ((pc, word), (pc + 3, pair[1])):
                    start = address - section["sh_addr"]
                    if section.data()[start:start + 3] != int(encoded, 16).to_bytes(3, "little"):
                        raise ValueError("Native copy instruction differs from actual ELF bytes")
                sites.append(hex(pc + 3))
            if len(sites) != (2 if name == "nxmq_do_send" else 1):
                raise ValueError("Native send/receive copy site absent or ambiguous")
            copy_sites.append({"caller": name, "callee": "ROM memcpy", "payload_instruction": sites[0],
                               "optional_notification_metadata_instructions": sites[1:]})
    return {"audit": "pass", "os": "NuttX", "build_manifest_sha256": sha(folder / "build.json"),
        "original_test_body_unchanged": True, "original_duration_us": 1000000, "clock_mhz": 240, "cores": 1,
        "tick_hz": 1, "compiler": "GCC 13.2.0", "optimization": "Os", "message_bytes": 8, "queue_slots": 1,
        "native_controller_priority": 150, "native_peer_priority": 151, "official_source_files_checked": len(sources(folder)),
        "machine_calls": machine, "native_copy_sites": copy_sites, "ranking_eligible": False, "board_resets": 0,
        "boundary": "Whole original send-and-higher-priority-receiver iteration, not round trip or isolated API latency. "
            "Native POSIX MQ uses internal message storage and two copy sites; not RIOT's unbuffered rendezvous or Zephyr's direct-copy path. "
            "Original opaque uninitialized user fields are not payload-integrity evidence. Native asynchronous cancellation and unlink occur after output."}


def capture(folder, index):
    rows = read_raw_capture(folder, index)
    lines = [ANSI.sub("", r["line"]).strip() for r in rows]
    final = "RIOT MSG NATIVE FINAL peer_blocked=1 queued=0 alarm_count=1 isr=1"
    required = ("NuttShell (NSH) NuttX-12.2.1", "RIOT MSG NATIVE VERSION NuttX 12.2.1", BEGIN,
        "main starting", final, "RIOT MSG NATIVE TIMER channel_reserved_until_reset=1", "RIOT MSG PORT END")
    if sum(s.startswith("rst:0x") for s in lines) != 1 or any(lines.count(s) != 1 for s in required) or \
            lines[-1] != required[-1] or any(re.search(r"PORT FAIL|FAILED|panic|assert failed|watchdog|Brownout|Guru Meditation", s, re.I) for s in lines):
        raise ValueError("NuttX original message boot/profile/completion differs")
    found = [(i, json.loads(s)) for i, s in enumerate(lines) if re.fullmatch(r'\{ "result" : \d+, "ticks" : \d+ }', s)]
    retired = [(i, re.fullmatch(r"RIOT MSG PORT RETIRE before=(\d+) after=(\d+)", s))
               for i, s in enumerate(lines) if s.startswith("RIOT MSG PORT RETIRE")]
    if len(found) != 1 or len(retired) != 1 or retired[0][1] is None:
        raise ValueError("Original count or native retirement missing")
    i, value = found[0]
    j, r = retired[0]
    order = (lines.index(BEGIN), lines.index("main starting"), i, lines.index(final), j, lines.index(required[-2]), len(lines) - 1)
    if tuple(sorted(order)) != order or not 1 <= value["result"] <= 0xffffffff or \
            value["ticks"] != 240000000 // value["result"] or int(r[1]) < 2 or r[1] != r[2] or \
            rows[i]["elapsed_s"] - rows[lines.index("main starting")]["elapsed_s"] < 0.95:
        raise ValueError("Original formula/window or native task registry differs")
    return {"start_utc": rows[0]["utc"], "end_utc": rows[-1]["utc"], "original_count": value["result"],
        "original_ticks": value["ticks"], "registry_before": int(r[1]), "registry_after": int(r[2]),
        "final_peer_blocked": True, "final_queued_messages": 0, "native_alarm_count": 1, "native_alarm_isr_context": True,
        "uart_sha256": sha(folder / ("reset%d.jsonl" % index)), "raw_sha256": sha(folder / ("reset%d.raw" % index))}


def audit(folder, source):
    metadata = envelope(folder)
    if metadata["kind"] != "riot-msg-nuttx" or metadata["board_mac"] != "34:98:7a:a2:85:28" or metadata["independent_resets"] != 3:
        raise ValueError("Wrong original NuttX message campaign")
    proof = build(source)
    for p in (folder / "build").iterdir():
        if sha(p) != sha(source / p.name):
            raise ValueError("Collected original/native image differs")
    verified(folder / "captures", folder / "build", metadata["board_mac"])
    independent_captures(folder / "captures")
    runs = []
    for index in (1, 2, 3):
        verified(folder / "captures", folder / "build", metadata["board_mac"], logs=("verify-run%d.log" % index,))
        runs.append(capture(folder / "captures", index))
    return {"audit": "pass", "os": "NuttX", "build": proof, "runs": runs,
        "original_counts": [r["original_count"] for r in runs], "independent_resets": 3,
        "original_flash_restored": True, "ranking_eligible": False, "energy_measured": False,
        "payload_correctness_validated": False, "external_independent_replication": False}


def audit_prewrite_failure(folder):
    metadata = json.loads((folder / "campaign.json").read_text())
    if metadata["kind"] != "riot-msg-nuttx" or metadata["status"] != "incomplete" or \
            metadata["original_flash_restored"] or metadata["ranking_eligible"] or metadata["old_cohort_modified"]:
        raise ValueError("Not an incomplete prewrite backup campaign")
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*")
              if p.is_file() and p.name not in ("campaign.json", "audit.json")}
    if set(metadata["files"]) != actual or any(not (folder / n).resolve().is_relative_to(folder.resolve()) or
            sha(folder / n) != v for n, v in metadata["files"].items()):
        raise ValueError("Prewrite failure evidence changed")
    backup = (folder / "backup.log").read_text()
    identity = (folder / "identity-before.log").read_text()
    if "Corrupt data, expected" not in backup or "Changing baud rate to 460800" not in backup or \
            set(re.findall(r"^MAC: ([0-9a-f:]+)$", identity, re.M)) != {metadata["board_mac"]} or \
            (folder / "captures").exists() or any(folder.glob("restore*.log")) or \
            "board.backup()" not in (folder / "runner.py").read_text():
        raise ValueError("Expected backup-only serial failure not witnessed")
    return {"audit": "pass", "result": "prewrite_backup_transfer_failure", "independent_resets": 0,
        "benchmark_measured": False, "firmware_write_started": False, "original_flash_restored": False,
        "ranking_eligible": False, "retry_change": "115200 baud and verified 256-KiB segments before any write"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--failure", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit_prewrite_failure(args.failure) if args.failure else audit(args.capture, args.build) if args.capture else build(args.build, args.verify_upstream)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
