#!/usr/bin/env python3
"""Record same-header ABI probes and retained SDK library inputs; no board use."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from elftools.elf.elffile import ELFFile
from run_esp32_followup import sha


def prepare(root, workspace, output, probe, wrapper, family="rhino"):
    directory = output / "compiler-compatibility"
    directory.mkdir(exist_ok=False)
    for p in (probe, wrapper):
        shutil.copyfile(p, directory / p.name)
    records = []
    toolchain = root / ("alios-gcc5/xtensa-esp32-elf" if family == "rhino" else "xtensa-esp32-elf")
    current = Path("/dev/shm/iotos-rhino-gcc13-legacy-tools/xtensa-esp32-elf-gcc") if family == "rhino" else root / "audit-workspace/tools/gcc13-legacy-newlib.sh"
    for label, compiler in (("gcc5" if family == "rhino" else "gcc12", toolchain / "bin/xtensa-esp32-elf-gcc"),
            ("gcc13-legacy-newlib", current)):
        obj = directory / (label + ".o")
        config = workspace / "out/config/autoconf.h" if family == "rhino" else output / "config.h"
        args = [str(compiler), "-std=gnu11", "-Os", "-c", "-include", str(config),
                str(directory / probe.name), "-o", str(obj)]
        with (directory / (label + ".log")).open("x") as log:
            subprocess.run(args, cwd=workspace, stdout=log, stderr=subprocess.STDOUT, check=True)
        with obj.open("rb") as stream:
            symbols = ELFFile(stream).get_section_by_name(".symtab")
            sizes = {s.name:s["st_size"] for s in symbols.iter_symbols() if s.name.startswith("abi_")}
        records.append({"compiler": label, "command": args, "sizes": sizes, "object_sha256": sha(obj)})
    if len(records[0]["sizes"]) != 5 or records[0]["sizes"] != records[1]["sizes"]:
        raise ValueError("Legacy SDK public C ABI sizes differ")
    libraries = {}
    names = ("platform/mcu/esp32/libc.a", "platform/mcu/esp32/lib/libnewlib.a", "platform/mcu/esp32/lib/libesp32.a") if family == "rhino" else \
            ("xtensa-esp32-elf/lib/libc.a", "xtensa-esp32-elf/lib/libm.a", "xtensa-esp32-elf/lib/libnosys.a")
    for name in names:
        source = (workspace if family == "rhino" else toolchain) / name
        libraries[name] = sha(source)
    headers = {}
    legacy = toolchain / "xtensa-esp32-elf/include"
    for name in ("stdint.h", "machine/_default_types.h", "sys/reent.h", "stdio.h", "setjmp.h", "sys/stat.h", "time.h"):
        saved = directory / "legacy-headers" / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(legacy / name, saved)
        headers[name] = sha(saved)
    data = {"abi_size_checks": "pass", "probes": records, "sdk_library_sha256": libraries,
            "legacy_header_sha256": headers, "wrapper_sha256": sha(directory / wrapper.name),
            "boundary": "public C type and sizeof compatibility checks, not a proof of all SDK/ROM behavior; actual boot required",
            "board_resets": 0, "ranking_eligible": False}
    (directory / "abi.json").write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--family", choices=("rhino", "riot"), default="rhino")
    for name in ("workspace", "output", "probe", "wrapper"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.root, args.workspace, args.output, args.probe, args.wrapper, args.family)
