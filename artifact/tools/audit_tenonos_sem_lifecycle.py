#!/usr/bin/env python3
"""Bind the original semaphore-lifecycle boundary to retained source and ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from elftools.elf.elffile import ELFFile
from audit_tenonos_memory import audit as memory_audit
from audit_tenonos_tasks import require
from tenonos_kvm_reproduce import sha


def function_bytes(path, name):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        require(elf["e_machine"] == "EM_AARCH64", "Different native architecture")
        symbols = elf.get_section_by_name(".symtab").get_symbol_by_name(name)
        require(symbols is not None and len(symbols) == 1, "Missing or ambiguous lifecycle function")
        symbol = symbols[0]
        section = elf.get_section(symbol["st_shndx"])
        offset = symbol["st_value"] - section["sh_addr"]
        raw = section.data()[offset:offset + symbol["st_size"]]
        return raw, symbol["st_value"]


def audit(root, folder):
    checked = memory_audit(root, folder)
    require(checked == json.loads((folder / "audit.json").read_text()), "Retained native-memory evidence changed")
    manifest_path = root / "artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark/manifest.json"
    inventory = json.loads(manifest_path.read_text())
    entries = {v["path"]: v for v in inventory["files"]}
    rows = []
    for profile in checked["profiles"]:
        p = folder / profile["profile"]
        app = p / "source/app-rtos-benchmark-memory"
        names = ("adapter/os/tenonos/rst_sem.c", "src/rst_semaphore_shuffle.c")
        for name in names:
            raw = (app / name).read_bytes()
            require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == entries[name]["sha"],
                    "Semaphore source differs from the pinned public blob")
        adapter = (app / names[0]).read_text()
        test = (app / names[1]).read_text()
        require(len(re.findall(r"void\s+rst_sem_delete\s*\(rst_sem_id\s+sem\)\s*\{\s*\}", adapter)) == 1 and
                "malloc(sizeof(struct uk_semaphore))" in adapter, "Native create/delete implementation differs")
        require(len(re.findall(r"rst_sem_delete\s*\(", test)) == 1 and re.search(
                r"if\s*\(rst_task1\s*==\s*NULL\)\s*\{[^}]*rst_sem_delete\(rst_sem\);\s*return RST_ERROR;", test),
                "Original delete call is not confined to the reviewed creation-failure branch")
        raw, address = function_bytes(p / "elf-recovery-v5/linked-symbols.elf", "rst_sem_delete")
        require(raw == bytes.fromhex("c0035fd6"), "Actual native delete is not the single AArch64 RET instruction")
        rows.append({"profile": profile["profile"], "delete_function_address": address,
            "delete_machine_bytes": raw.hex(), "source_sha256": {n: sha(app / n) for n in names},
            "measured_runtime_image_sha256": profile["image_sha256"],
            "delete_returns_without_releasing": True, "normal_test_path_requests_delete": False})
    return {"pass": True, "profiles": rows, "upstream_commit": inventory["commit"],
        "memory_audit_sha256": sha(folder / "audit.json"), "inventory_sha256": sha(manifest_path),
        "new_guest_boots": 0, "new_model_calls": 0, "ranking_eligible": False,
        "whole_live_ram_peak_bytes": None,
        "finding": "The compiled public delete wrapper returns without freeing. The original shuffle test requests deletion only on a task-creation-failure path, not normal completion. Normal retained occupancy is therefore not itself evidence of a leak; a separate successful create/delete/reclaim lifecycle cannot be claimed from this suite.",
        "consequence": "Preserve original bodies and measured values. Treat native object-reclamation validation as a separate unresolved capability; do not silently free original retained objects or count malloc/free validation as complete semaphore lifetime evidence."}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path("/home/reviewer/esp32-pilot/audit-workspace"):
        p.error("Audit retained evidence on leon")
    result = audit(root, a.folder.resolve())
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "profiles"}))
