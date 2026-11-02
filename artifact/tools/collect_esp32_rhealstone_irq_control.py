#!/usr/bin/env python3
"""Freeze reachable original/native single-IRQ paths from the installed image."""
import os
from pathlib import Path
import re
import subprocess

FUNCTIONS = ("Init", "Task_1", "Isr_handler", "rh_native_priority_scheduler", "rh_install_irq",
             "rh_cause_irq", "rh_clear_irq", "benchmark_timer_initialize", "benchmark_timer_read",
             "rtems_task_create", "rtems_task_start", "rh_end", "rtems_task_exit", "rtems_test_exit", "rh_fail")
NORETURN = ("rtems_task_exit", "rtems_test_exit", "rh_fail")

if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/rhealstone-irq-freertos-v1"
    objdump = str(root / "idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin/xtensa-esp32-elf-objdump")
    image = str(directory / "application.elf")
    for name in ("image.sha256", "capture.sha256"):
        subprocess.check_call(["sha256sum", "-c", name], cwd=str(directory), stdout=subprocess.DEVNULL)
    output = directory / "irq-control-flow.txt"
    manifest = directory / "irq-control.sha256"
    if output.exists() or manifest.exists():
        raise SystemExit("single-IRQ supplement already exists")
    symbols = subprocess.check_output([objdump, "-t", image]).decode()
    chunks = []
    for name in FUNCTIONS:
        found = re.findall(r"^([0-9a-f]+)\s+.*?\s+F\s+\S+\s+([0-9a-f]+)\s+" + name + r"$", symbols, re.M)
        if not found:
            raise SystemExit("original/native IRQ symbol missing: " + name)
        start, size = max(((int(a, 16), int(n, 16)) for a, n in found), key=lambda row: row[1])
        pending, visited = [start], set()
        while pending:
            entry = pending.pop(0)
            if entry in visited:
                continue
            visited.add(entry)
            if not start <= entry < start + size:
                raise SystemExit("IRQ branch outside original/native body")
            decoded = subprocess.check_output([objdump, "-d", "--start-address=" + hex(entry),
                                               "--stop-address=" + hex(start + size), image]).decode()
            rows = re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{2,6})\s+(.+)$", decoded, re.M)
            position, block = entry, []
            for address, encoding, instruction in rows:
                address = int(address, 16)
                if address != position:
                    raise SystemExit("IRQ block instruction coverage incomplete")
                block.append(f"{address:x}: {encoding} {instruction}\n")
                position += len(encoding) // 2
                if re.match(r"call8\s+[0-9a-f]+ <(?:" + "|".join(NORETURN) + r")>$", instruction):
                    break
                if re.match(r"ret(?:w)?(?:\.n)?\b", instruction):
                    break
                branch = re.match(r"(j|b[\w.]+|loop[\w.]*)\s+.*?([0-9a-f]+) <" + name + r"(?:\+0x[0-9a-f]+)?>$", instruction)
                if branch:
                    pending.append(int(branch[2], 16))
                    if branch[1] != "j":
                        pending.append(position)
                    break
            else:
                raise SystemExit("IRQ block lacks a terminator: " + name + " " + hex(entry))
            chunks.append(f"RHEALSTONE IRQ CONTROL {name} {entry:x}\n")
            chunks.extend(block)
    output.write_text("".join(chunks))
    subprocess.check_call(["cp", __file__, str(directory / "collect-irq-control.py")])
    with manifest.open("w") as stream:
        subprocess.check_call(["sha256sum", "application.elf", "image.sha256", "capture.sha256",
                               output.name, "collect-irq-control.py"], cwd=str(directory), stdout=stream)
    print("Frozen single-IRQ original/native supplement collected; audit pending.")
