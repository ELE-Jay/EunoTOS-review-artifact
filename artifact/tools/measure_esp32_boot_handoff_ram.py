#!/usr/bin/env python3
"""Pair the existing boot observer with a stackless application-entry readback."""
import argparse
import json
from pathlib import Path
import re
import shutil
import sys

from build_esp32_tm_ram_lifetimes import build as build_application
from measure_esp32_bootloader_ram import observations as boot_observations
from run_esp32_followup import read_raw_capture, sha

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("source", "entry_sp", "low", "paint_end", "painted", "verified", "app_sp", "spare", "touched", "invalid", "guard", "stages")
PATTERN = re.compile("FREERTOS_BOOT_HANDOFF " + " ".join(n + r"=(\d+)" for n in FIELDS))


def observations(lines, address):
    found = [PATTERN.fullmatch(s) for s in lines if s.startswith("FREERTOS_BOOT_HANDOFF ")]
    if len(found) != 1 or found[0] is None:
        raise ValueError("Missing, malformed or repeated boot handoff")
    row = dict(zip(FIELDS, map(int, found[0].groups())))
    boot = boot_observations(lines)[-1]
    if any(row[k] != boot[k] for k in ("entry_sp", "low", "paint_end", "painted", "verified", "guard", "stages")) or \
            row["source"] != address or row["invalid"] or row["app_sp"] % 16 or \
            not row["low"] + 64 < row["app_sp"] <= 0x3ffe3f20 or \
            min(row["spare"], row["touched"]) < 0 or row["spare"] + row["touched"] != row["painted"] or \
            row["spare"] % 4 or row["touched"] % 4 or row["touched"] < boot["touched"]:
        raise ValueError("Inherited boot state or cumulative watermark differs")
    return row


def paired_boot(source):
    from audit_esp32_bootloader_ram import build as audit_boot
    from elftools.elf.elffile import ELFFile
    proof = audit_boot(source)
    with (source / "bootloader.elf").open("rb") as stream:
        state = ELFFile(stream).get_section_by_name(".symtab").get_symbol_by_name("bench_boot_state")[0]
        return state["st_value"], proof


def build(root, workspace, output, boot_source):
    address, old_proof = paired_boot(boot_source)
    observer = ROOT / "firmware/bsp/esp32/resource_census/freertos_lifetimes"
    build_application(root, workspace, output, observer, observer.parent / "freertos_message_tail.c",
        irq_coverage=True, startup_coverage=True, lifecycle_validation=True, compact=True,
        startup_handoff=True, peak_context=True, boot_readback_state=address)
    shutil.copytree(boot_source, output / "paired-bootloader")
    shutil.copyfile(boot_source / "bootloader.bin", output / "bootloader.bin")
    shutil.copyfile(__file__, output / "paired-builder.py")
    manifest = json.loads((output / "build.json").read_text())
    manifest.update(paired_bootloader_sha256=old_proof["bootloader_sha256"], application_rebuilt=True)
    manifest["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*")
                         if p.is_file() and p != output / "build.json"}
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return build_proof(output)


def build_proof(source):
    from run_esp32_tm_ram_lifetimes import build_proof as audit_application
    manifest = json.loads((source / "build.json").read_text())
    address, boot = paired_boot(source / "paired-bootloader")
    if manifest.get("boot_readback_state_address") != address or manifest.get("application_rebuilt") is not True or \
            manifest.get("paired_bootloader_sha256") != boot["bootloader_sha256"] or \
            sha(source / "bootloader.bin") != boot["bootloader_sha256"] or \
            (source / "config").read_bytes() != (source / "paired-bootloader/config").read_bytes():
        raise ValueError("Installed bootloader/application pair differs")
    return {"audit": "pass", "application": audit_application(source), "bootloader": boot,
        "readback_state_address": address, "application_binary_unchanged": False,
        "scope": "second-stage marked stack through application entry before repaint; observer included",
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False}


def audit(folder, source):
    from run_esp32_tm_ram_lifetimes import audit as audit_application
    from replay_esp32_bootloader_ram import handoff_row
    from replay_esp32_followup import raw_rows
    proof = build_proof(source)
    application = audit_application(folder, source)
    runs = []
    validation = None
    for directory, index, app in [("validation", 1, application["separate_validation"])] + [
            ("captures", i, app) for i, app in enumerate(application["runs"], 1)]:
        rows = read_raw_capture(folder / directory, index)
        lines = [r["line"] for r in rows]
        row = observations(lines, proof["readback_state_address"])
        separate = [r["line"] for r in raw_rows(folder / directory / ("reset%d.jsonl" % index))]
        if row != handoff_row(separate, proof["readback_state_address"]) or \
                row["app_sp"] != app["application_startup_stack"]["application_entry_sp"] or \
                lines.index(next(s for s in lines if s.startswith("BOOT_RAM phase=1 "))) >= \
                lines.index(next(s for s in lines if s.startswith("TM_RAM BEGIN "))):
            raise ValueError("Independent boot handoff replay differs")
        item = {"handoff": row, "boot_stages": boot_observations(lines),
                "maximum_clock_read_bracket_s": max(r["clock_read_after_s"] - r["clock_read_before_s"] for r in rows)}
        if directory == "validation":
            validation = item
        else:
            runs.append(item)
    return {"audit": "pass", "build": proof, "application": application, "runs": runs,
        "separate_validation_readback": validation, "auditor_code_sha256": sha(Path(__file__)),
        "independent_resets": 5, "original_flash_restored": True, "independent_readback_replay": True,
        "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
        "remaining": ["first-stage ROM", "unpainted active entry guard", "continuous simultaneous live stacks and unmanaged occupancy"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "build-audit", "audit"))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--boot-source", type=Path)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run evidence-dependent work on leon; keep only source code on the Mac")
    if args.mode == "build":
        result = build(args.root, args.workspace, args.output, args.boot_source)
        (args.output / "paired-build-proof.json").write_text(json.dumps(result, indent=2) + "\n")
    else:
        result = audit(args.campaign, args.source) if args.mode == "audit" else build_proof(args.source)
        with args.output.open("x") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("audit", "independent_resets", "whole_live_ram_peak_bytes", "ranking_eligible") if k in result}))
