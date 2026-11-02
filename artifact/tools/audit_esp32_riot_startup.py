#!/usr/bin/env python3
"""Verify a bounded startup diagnostic and a distinct legacy-newlib candidate."""
import argparse
import json
from pathlib import Path
import statistics
from elftools.elf.elffile import ELFFile

from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_resources import audit_elf_image
from audit_esp32_tm_alignment import EVIDENCE, MARKER
from audit_esp32_tm_basic import audit as original
from audit_esp32_tm_reboots import require_self_check
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]


def build(folder, diagnostic):
    report = json.loads((folder / "build.json").read_text())
    if diagnostic:
        if report["returncode"] or not report["diagnostic_only"] or report["ranking_eligible"]:
            raise ValueError("Not a build-only startup diagnostic")
        images, sources = report["images"], report["source"]
        for name, digest in sources.items():
            if sha(folder / "source" / name) != digest:
                raise ValueError("Startup probe source changed")
        if (folder / "source/startup_probe.c").read_bytes() != (ROOT / "firmware/bsp/esp32/riot_startup_probe/startup_probe.c").read_bytes():
            raise ValueError("Unreviewed startup markers")
    else:
        case = report.get("case", "message_processing")
        if report["status"] != "PASS_BUILD_ONLY" or report["build_returncode"] or "13.2.0" not in report["compiler"] or \
                not any(a.endswith("gcc13-legacy-newlib.sh") for a in report["command"]):
            raise ValueError("Wrong GCC13/native legacy-newlib build")
        if sha(folder / "build.log") != report["build_log_sha256"]:
            raise ValueError("Compiler evidence changed")
        for name, digest in report["source_sha256"].items():
            if name.startswith("artifact:"):
                path = (folder / name.removeprefix("artifact:")).resolve()
                if not path.is_relative_to(folder.resolve()):
                    raise ValueError("Build source escapes artifact directory")
            elif name == "threadx-6.2.1_rel/utility/benchmarks/thread_metric/tm_" + case + "_test.c":
                path = ROOT / "artifacts/source_snapshots/thread-metric-6.2.1-rel" / Path(name).name
            elif name.startswith("downloads/tm-alignment-v1/riot-gcc13-legacy-newlib/message_processing/"):
                path = folder / name.split("message_processing/", 1)[1]
            else:
                path = EVIDENCE / "source-evidence" / name
            if sha(path) != digest:
                raise ValueError("Original/native source changed: " + name)
        baseline = EVIDENCE / "riot-gcc12/message_processing/source"
        for name in ("main.c", "port.c", "test.c", "tm_override.h", "riot_tm_baseline.inc", "Makefile"):
            if (folder / "source" / name).read_bytes() != (baseline / name).read_bytes():
                raise ValueError("Compiler control changed the original adapter/profile")
        images = report["image_sha256"]
        with (folder / "application.elf").open("rb") as stream:
            names = {s.name for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols() if s["st_shndx"] != "SHN_UNDEF"}
        if (case == "message_processing" and not {"xQueueGenericCreate", "xQueueGenericSend", "xQueueGenericReceive"} <= names) or any(n.startswith("tm_legacy_mailbox_") for n in names):
            raise ValueError("Official copy queue was not linked")
        compatibility = folder / "compiler-compatibility"
        abi = json.loads((compatibility / "abi.json").read_text())
        wrapper = compatibility / "gcc13-legacy-newlib.sh"
        if abi["abi_size_checks"] != "pass" or abi["board_resets"] or abi["ranking_eligible"] or \
                sha(wrapper) != abi["wrapper_sha256"] or wrapper.read_bytes() != (
                    ROOT / "firmware/bsp/esp32/riot_startup_probe/gcc13-legacy-newlib.sh").read_bytes() or \
                (compatibility / "riot_newlib_abi_probe.c").read_bytes() != (
                    ROOT / "firmware/bsp/esp32/riot_startup_probe/newlib_abi_probe.c").read_bytes():
            raise ValueError("RIOT native C ABI route/probe differs")
        for name, digest in abi["legacy_header_sha256"].items():
            if sha(compatibility / "legacy-headers" / name) != digest:
                raise ValueError("Retained RIOT newlib header changed")
        expected = {"abi_time": 8, "abi_stat": 88, "abi_jmpbuf": 68, "abi_file": 104, "abi_reent": 240}
        if [row["compiler"] for row in abi["probes"]] != ["gcc12", "gcc13-legacy-newlib"]:
            raise ValueError("RIOT ABI compiler comparison missing")
        for row in abi["probes"]:
            obj = compatibility / (row["compiler"] + ".o")
            if sha(obj) != row["object_sha256"]:
                raise ValueError("RIOT public C ABI object changed")
            with obj.open("rb") as stream:
                sizes = {s.name:s["st_size"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols() if s.name.startswith("abi_")}
            if sizes != expected or sizes != row["sizes"]:
                raise ValueError("RIOT public C ABI sizes differ")
    for name, digest in images.items():
        if sha(folder / name) != digest:
            raise ValueError("Native candidate image changed")
    audit_elf_image(folder / "application.elf", folder / "application.bin")
    return {"audit": "pass", "images": images, "diagnostic": diagnostic, "ranking_eligible": False,
            "public_c_abi_sizes": expected if not diagnostic else None}


def audit(folder, source, diagnostic):
    campaign = envelope(folder, allow_incomplete=not diagnostic)
    proof = build(source, diagnostic)
    if campaign["board_mac"] != "34:98:7a:a2:85:28" or campaign["kind"] != ("startup" if diagnostic else "message"):
        raise ValueError("Wrong candidate board or acquisition kind")
    for name, digest in proof["images"].items():
        if sha(folder / "build" / name) != digest:
            raise ValueError("Captured candidate differs from built image")
    if campaign["status"] == "incomplete":
        verified(folder / "captures", folder / "build", campaign["board_mac"],
                 logs=("identity.log", "flash.log", "verify-before.log", "verify-run1.log"))
    else:
        verified(folder / "captures", folder / "build", campaign["board_mac"])
    indices = (1,) if diagnostic or campaign["status"] == "incomplete" else (1, 2, 3)
    rows = independent_captures(folder / "captures", indices)
    if diagnostic:
        markers = [r["line"] for r in rows[0] if r["line"].startswith("STARTUP_PROBE ")]
        if not markers or markers[-1] != "STARTUP_PROBE enter syscalls_init" or "STARTUP_PROBE leave syscalls_init" in markers:
            raise ValueError("Declared startup stage not established")
        return {"audit": "pass", "attempted_resets": 1, "last_stage": markers[-1], "markers": markers,
                "diagnostic_only": True, "ranking_eligible": False, "root_cause": "subcall within syscalls_init not yet established"}
    values = []
    for index, capture in enumerate(rows, 1):
        if campaign["status"] == "incomplete":
            return {"audit": "pass", "attempted_resets": 1, "status": "startup_or_original_test_incomplete",
                    "last_uart_line": capture[-1]["line"], "ranking_eligible": False}
        lines = [r["line"] for r in capture]
        if lines.count(MARKER) != 1 or lines.count("Thread-Metric conditions cpu_hz=240000000 cores=1 timer=tickless scheduler=priority-fifo") != 1:
            raise ValueError("Native copy queue/tickless profile differs")
        require_self_check(capture, "queue")
        values.append(original(folder / "captures" / ("reset%d.jsonl" % index), "RIOT", "message_processing")["original_window_totals"][0])
    return {"audit": "pass", "independent_resets": 3, "case": "message_processing", "values": values,
            "median": statistics.median(values), "unit": "count/30s", "compiler": "GCC13.2 with GCC12 newlib",
            "public_c_abi_sizes": proof["public_c_abi_sizes"],
            "kernel_tick": "native tickless", "ranking_eligible": False, "energy_measured": False,
            "boundary": "native tickless is retained; not admitted to the 100 Hz cohort"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    result = audit(args.campaign, args.source, args.diagnostic) if args.campaign else build(args.source, args.diagnostic)
    if args.campaign:
        (args.campaign / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
