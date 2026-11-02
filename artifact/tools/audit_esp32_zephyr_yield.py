#!/usr/bin/env python3
"""Replay unchanged Zephyr preemptive yield cases on native OS adapters."""
import argparse
import json
from pathlib import Path
import hashlib
import re
import shlex
from urllib.request import urlopen
from audit_esp32_zephyr_thread import audit as thread_audit, LABELS, ROOT, YIELD_TAGS, UPSTREAM, check_manifest, digest

COHORTS = (("freertos", "v1"), ("alios", "v1"), ("riot", "v1"), ("nuttx", "v1"))


def audit(directory, os, verify_upstream=False):
    result = thread_audit(directory, os, verify_upstream, yield_subset=True)
    if os in ("freertos", "nuttx"):
        check_manifest(directory, "yield-native.sha256")
        name = "FreeRTOS-Kernel/portable/xtensa/portasm.S" if os == "freertos" else "sched/sched/sched_setpriority.c"
        expected = {"application.elf", "image.sha256", "capture.sha256", "collect-yield-native.sh", "native-yield-source/" + name}
        paths = {line.split(maxsplit=1)[1] for line in (directory / "yield-native.sha256").read_text().splitlines()}
        if paths != expected or (directory / "collect-yield-native.sh").read_bytes() != \
                (ROOT / "tools/collect_esp32_zephyr_yield_native.sh").read_bytes():
            raise ValueError("additional native yield source/image binding differs")
        source = directory / "native-yield-source" / name
        proof = directory / "official-yield-source.json"
        if verify_upstream:
            with urlopen(UPSTREAM[os] + name, timeout=30) as response:
                sha = hashlib.sha256(response.read()).hexdigest()
            if sha != digest(source):
                raise ValueError("native yield implementation differs from fixed official source")
            proof.write_text(json.dumps({"path": name, "url": UPSTREAM[os] + name, "sha256": sha}, indent=2) + "\n")
        if json.loads(proof.read_text()) != {"path": name, "url": UPSTREAM[os] + name, "sha256": digest(source)}:
            raise ValueError("native yield source provenance differs")
        if os == "freertos":
            commands = [shlex.split(row["command"]) for row in json.loads((directory / "compile_commands.json").read_text())]
        else:
            commands = [shlex.split(line) for line in (directory / "build.log").read_text().replace("\\\n", " ").splitlines()
                        if "xtensa-esp32-elf-gcc" in line and " -c " in line]
        commands = [args for args in commands if any(not arg.startswith("-") and
                    (arg.endswith("/" + name) or arg == name or (os == "nuttx" and Path(arg).name == Path(name).name)) for arg in args)
                    and Path(args[0]).name == "xtensa-esp32-elf-gcc"]
        if len(commands) != 1 or [arg for arg in commands[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)][-1:] != ["-Os"] or \
                (os == "nuttx" and "-D__KERNEL__" not in commands[0]):
            raise ValueError("native yield implementation compilation differs")
        result["native_source_files"] += 1
        result["additional_yield_source_sha256"] = digest(source)
    return result


def render_table(results):
    lines = ["| Original Zephyr preemptive yield subset / OS | Original case | Original means, ns (three boots) |",
             "| --- | --- | --- |"]
    for result in results:
        for tag in YIELD_TAGS:
            lines.append(f"| Original yield port / {result['os']} / {tag} | {tag} | " +
                         " / ".join(map(str, result["metrics"][tag]["means_ns"])) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("os", choices=LABELS)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.directory, args.os, args.verify_upstream), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
