#!/usr/bin/env python3
"""Independently replay Tenon native memory source, image and guest records."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

from elftools.elf.elffile import ELFFile
from audit_tenonos_tasks import configuration, require
from audit_tenonos_policy_sequence import guest_checks
from tenonos_kvm_reproduce import sha

MAIN = b"int main(int argc __unused, char *argv[] __unused)"
RENAMED = b"int iotos_original_main(int argc __unused, char *argv[] __unused)"
ADDITION = b"\nAPPRHEALSTONEBENCHMARK_SRCS-y += $(APPRHEALSTONEBENCHMARK_BASE)/iotos_memory.c\n"


def observations(text):
    lines = [line.rstrip("\r") for line in text.split("\n") if line.startswith("IOTOS_MEMORY ")]
    expected = ["before-suite", "after-suite", "validation-allocated", "validation-released"]
    rows = []
    for line, phase in zip(lines, expected):
        fields = dict(part.split("=", 1) for part in line.split()[1:])
        require(set(fields) == {"phase", "allocator", "current", "peak"} and fields["phase"] == phase,
                "Unexpected native observation fields")
        rows.append({"phase": phase, "allocator": fields["allocator"],
                     "current": int(fields["current"]), "peak": int(fields["peak"])})
    require(len(lines) == len(rows) == 4 and len({r["allocator"] for r in rows}) == 1 and
            rows[0]["allocator"] in ("tlsf", "buddy"), "Native observation coverage differs")
    require(all(0 < r["current"] <= r["peak"] < 134217728 for r in rows) and
            all(a["peak"] <= b["peak"] for a, b in zip(rows, rows[1:])) and
            rows[2]["current"] >= rows[1]["current"] + 65536 and rows[3]["current"] == rows[1]["current"] and
            len(re.findall(r"(?m)^IOTOS_MEMORY_VALIDATION pass=1\r?$", text)) == 1,
            "Native statistics validation did not pass")
    return rows


def writable_image(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        require(elf["e_machine"] == "EM_AARCH64", "Wrong guest image architecture")
        ranges = sorted((s["p_paddr"], s["p_paddr"] + s["p_memsz"]) for s in elf.iter_segments()
                        if s["p_type"] == "PT_LOAD" and s["p_flags"] & 2 and s["p_memsz"])
    union = []
    for start, end in ranges:
        if union and start <= union[-1][1]:
            union[-1][1] = max(union[-1][1], end)
        else:
            union.append([start, end])
    require(bool(union), "No writable static load segment")
    return {"physical_ranges": union, "bytes": sum(b - a for a, b in union)}


def audit(root, folder):
    plan = json.loads((folder / "protocol.json").read_text())
    campaign = json.loads((folder / "campaign.json").read_text())
    references = json.loads((folder / "references.json").read_text())
    require(plan["id"] == "tenon-rpi4-native-allocator-memory-v1" and campaign["status"] == "complete" and
            campaign["protocol_sha256"] == sha(folder / "protocol.json") and campaign["model_calls"] == 0 and
            campaign["governor_restored"] and campaign["host_after_restore"]["governor"] == campaign["host_initial"]["governor"],
            "Incomplete or changed native-memory campaign")
    require([r["profile"] for r in campaign["completed"]] == plan["profiles"], "Profile coverage differs")
    for name, digest in campaign["source_sha256"].items():
        require(sha(folder / "helpers" / name) == digest, "Frozen helper changed")
    manifest = json.loads((root / "artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark/manifest.json").read_text())
    require(manifest["commit"] == "0b71b8e722acfab4733eb99b07b67fbe8472c31d" and not manifest["truncated"], "Different public test suite")
    original = {r["path"]: r for r in manifest["files"]}
    rows = []
    for completed in campaign["completed"]:
        name = completed["profile"]
        p = folder / name
        reference = next(r for r in references["variants"] if r["id"] == name)
        require(sha(p / "input.config") == reference["config_sha256"], "Reference configuration changed")
        transfer = json.loads((p / "runtime-transfer-check.json").read_text())
        require(transfer["all_equal"] and transfer["remote_returncode"] == 0, "Transfer incomplete")
        for rel, digest in transfer["files"].items():
            file = (p / rel).resolve()
            file.relative_to(p.resolve())
            require(sha(file) == digest, "Returned bytes changed: " + rel)
        source = p / "source/app-rtos-benchmark-memory"
        proof = json.loads((p / "source-proof.json").read_text())
        require(set(proof["original_app_sha256"]) == set(original) and
                set(proof["observer_app_sha256"]) == set(original) | {"iotos_memory.c"}, "Source coverage differs")
        patches = proof["identity"]["rtos_adapter_patch"]["files"]
        require(patches == {"adapter/os/tenonos/rst_isr.c": "738792173125d862712cf17d40640a3f1c3488a761d2ac321cfe537982d1a707",
                            "adapter/os/tenonos/rst_task.c": "71c41a94f0ccdf644b0afb0f266afe072e3048df42816bf2a8893dcece304bed"},
                "Different compatibility adapter")
        for rel in original:
            raw = (source / rel).read_bytes()
            require(sha(source / rel) == proof["observer_app_sha256"][rel], "Observer source changed")
            if rel == "main.c":
                require(raw.count(RENAMED) == 1, "Wrapper entry differs")
                raw = raw.replace(RENAMED, MAIN)
            elif rel == "Makefile.uk":
                require(raw.endswith(ADDITION), "Wrapper source registration differs")
                raw = raw[:-len(ADDITION)]
            require(hashlib.sha256(raw).hexdigest() == proof["original_app_sha256"][rel], "Original test body changed")
            if rel in patches:
                require(hashlib.sha256(raw).hexdigest() == patches[rel], "Patched adapter changed")
            else:
                require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == original[rel]["sha"], "Wrong upstream Git blob")
        require(sha(source / "iotos_memory.c") == sha(folder / "helpers/tenonos_memory_probe.c"), "Compiled memory wrapper differs")
        native = json.loads((p / "native-statistics.json").read_text())
        require(all(sha(p / "source/native-statistics" / n) == h for n, h in native.items()), "Native statistics source differs")
        tlsf = proof["tlsf"]
        if tlsf:
            require(all("-DTLSF_STATISTIC=1" in (p / "source/native-statistics" / n).read_text()
                        for n in ("libtlsf-tlsf.o.cmd", "libtlsf-glue.o.cmd")), "Actual native flag missing")
            baseline = p / "source/native-statistics/tlsf-without-observer-fix.c"
            require(sha(baseline) == plan["tlsf_before_statistics_repair_sha256"], "Native TLSF baseline changed")
            text = (p / "source/native-statistics/tlsf.c").read_bytes()
            additions = (b"#if TLSF_STATISTIC\n    /* Account new-area capacity before free_ex removes its free block. */\n    tlsf->used_size += area_size;\n#endif\n",
                         b"#if TLSF_STATISTIC\n    if (tlsf->used_size > tlsf->max_size)\n        tlsf->max_size = tlsf->used_size;\n#endif\n")
            for addition in additions:
                require(text.count(addition) == 1, "Statistics repair differs")
                text = text.replace(addition, b"")
            require(text == baseline.read_bytes(), "TLSF allocation mechanism changed")
        before, after = configuration(p / "input.config"), configuration(p / "build/.config")
        diff = {k: [before.get(k, "n"), after.get(k, "n")] for k in before.keys() | after.keys()
                if before.get(k, "n") != after.get(k, "n")}
        require(diff == {k.removeprefix("CONFIG_"): v for k, v in proof["config_changes"].items()} and
                set(diff) == ({"UK_APP"} if tlsf else {"UK_APP", "LIBUKALLOC_IFSTATS"}), "Native policy changed")
        build = json.loads((p / "build/build-result.json").read_text())
        require(sha(p / "build/runtime-image") == build["image_sha256"] and sha(p / "build/.config") == build["config_sha256"], "Image/config changed")
        guests, complete = guest_checks(p / "boots", build["image_sha256"])
        require(complete and len(guests) == 3, "Original six outputs incomplete")
        snapshots = [observations((p / ("boots/boot%d.stdout" % i)).read_text()) for i in (1, 2, 3)]
        reported = json.loads((p / "memory-result.json").read_text())
        require(snapshots == reported["snapshots"] and reported["whole_live_ram_peak_bytes"] is None and
                all(r["allocator"] == ("tlsf" if tlsf else "buddy") for values in snapshots for r in values), "Memory summary differs")
        for i in (1, 2, 3):
            cmd = json.loads((p / ("boots/boot%d.json" % i)).read_text())["argv"]
            require(all(cmd[cmd.index(k) + 1] == v for k, v in (("-accel", "kvm"), ("-m", "128M"), ("-smp", "1"))), "Guest envelope differs")
        require(all(completed[s]["governor"] == "performance" and completed[s]["throttled"] == "throttled=0x0" and
                    not completed[s]["qemu_running"] for s in ("host_before", "host_after")), "Host envelope differs")
        peaks = [r[1]["peak"] for r in snapshots]
        recovery = p / "elf-recovery-v5"
        linked = json.loads((recovery / "result.json").read_text())
        returned = json.loads((p / "elf-recovery-v5-transfer.json").read_text())
        require(returned["all_equal"] and returned["remote_returncode"] == 0 and
                all(sha(recovery / n) == h for n, h in returned["files"].items()) and linked["pass"] and
                linked["new_guest_boots"] == 0 and linked["measured_image_sha256"] == build["image_sha256"] and
                sha(recovery / "linked.elf") == linked["linked_elf_sha256"] and
                sha(recovery / "objcopy-image.bin") == linked["objcopy_image_sha256"] == build["image_sha256"],
                "Recovered ELF does not bind to the measured flat image")
        rows.append({"profile": name, "fresh_guests": 3, "native_allocator_peaks_bytes": peaks,
                     "median_native_allocator_peak_bytes": statistics.median(peaks), "snapshots": snapshots,
                     "writable_static_load": writable_image(recovery / "linked.elf"),
                     "statistic": "TLSF pool including native metadata/block headers" if tlsf else "Buddy assigned pages, including malloc compatibility overhead",
                     "image_sha256": build["image_sha256"], "ranking_eligible": False})
    return {"pass": True, "profiles": rows, "fresh_guests": 9, "model_calls": 0,
            "scope": plan["scope"], "whole_live_ram_peak_bytes": None, "ranking_eligible": False,
            "campaign_sha256": sha(folder / "campaign.json"), "auditor_sha256": sha(Path(__file__))}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = audit(Path(__file__).resolve().parents[1], args.folder.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
