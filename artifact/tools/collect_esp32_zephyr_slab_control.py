#!/usr/bin/env python3
"""Freeze actual entry-driven fixed-block original/native machine paths."""
import os
from pathlib import Path
import re
import subprocess

FUNCTIONS = ("main", "mem_slab_test", "begin_test", "check_result", "TIME_STAMP_DELTA_GET",
             "k_mem_slab_alloc", "k_mem_slab_num_used_get", "k_uptime_delta", "native_slab_mean",
             "memarray_init", "memarray_extend", "memarray_available")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/zephyr-slab-riot-v3"
    objdump = str(root / "xtensa-esp32-elf/bin/xtensa-esp32-elf-objdump")
    image = str(directory / "application.elf")
    for name in ("image.sha256", "capture.sha256"):
        subprocess.check_call(["sha256sum", "-c", name], cwd=str(directory), stdout=subprocess.DEVNULL)
    output, manifest = directory / "slab-control-flow.txt", directory / "slab-control.sha256"
    if output.exists() or manifest.exists():
        raise SystemExit("slab supplement already exists")
    symbols = subprocess.check_output([objdump, "-t", image]).decode()
    chunks = []
    for name in FUNCTIONS:
        found = re.findall(r"^([0-9a-f]+)\s+.*?\s+F\s+\S+\s+([0-9a-f]+)\s+" + name + r"$", symbols, re.M)
        if not found:
            raise SystemExit("original/native slab symbol missing: " + name)
        start, size = max(((int(a, 16), int(n, 16)) for a, n in found), key=lambda row: row[1])
        pending, visited = [start], set()
        while pending:
            entry = pending.pop(0)
            if entry in visited:
                continue
            visited.add(entry)
            if not start <= entry < start + size:
                raise SystemExit("slab branch outside body")
            decoded = subprocess.check_output([objdump, "-d", "--start-address=" + hex(entry),
                "--stop-address=" + hex(start + size), image]).decode()
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", decoded, re.M)
            position, block = entry, []
            for address, encoding, instruction in rows:
                address = int(address, 16)
                if address != position:
                    raise SystemExit("slab instruction coverage incomplete")
                block.append(f"{address:x}: {encoding} {instruction}\n")
                position += len(encoding) // 2
                if re.match(r"ret(?:w)?(?:\.n)?\b", instruction) or re.fullmatch(r"call8\s+[0-9a-f]+ <fail>", instruction):
                    break
                branch = re.match(r"(j|b[\w.]+|loop[\w.]*)\s+.*?([0-9a-f]+) <" + name + r"(?:\+0x[0-9a-f]+)?>$", instruction)
                if branch:
                    pending.append(int(branch[2], 16))
                    if branch[1] != "j":
                        pending.append(position)
                    break
            else:
                raise SystemExit("slab block lacks a terminator")
            chunks.append(f"SLAB CONTROL {name} {entry:x}\n")
            chunks.extend(block)
    output.write_text("".join(chunks))
    subprocess.check_call(["cp", __file__, str(directory / "collect-slab-control.py")])
    with manifest.open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256",
            output.name, "collect-slab-control.py"], cwd=str(directory), stdout=stream)
    print("Frozen original/native slab paths collected; audit pending.")
