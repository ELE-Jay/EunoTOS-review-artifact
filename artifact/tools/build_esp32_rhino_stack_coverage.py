#!/usr/bin/env python3
"""Extend the existing native lifecycle build with deleted/idle/ordinary-IRQ watermarks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import build_esp32_rhino_ram_lifetimes as engine

EXTRA = "\nGLOBAL_LDFLAGS += -Wl,--wrap=krhino_task_dyn_del\n"


def extended_source(original, extension):
    changes = {
        "static unsigned record_count, native_active;": "static unsigned record_count, native_active;\nstatic void bench_stack_begin(void);\nstatic void bench_stack_report(void);",
        "    ready_occupied=occupied;": "    ready_occupied=occupied;\n    bench_stack_begin();",
        '    out("RHINO_RAM END\\n");': '    bench_stack_report();\n    out("RHINO_RAM END\\n");',
    }
    for old, new in changes.items():
        if original.count(old) != 1:
            raise ValueError("Native lifetime extension anchor differs")
        original = original.replace(old, new)
    return original + "\n" + extension


def build(root, workspace, output, observer):
    extension = observer / "stack-coverage.inc"
    original = observer / "census.c"
    recipe = root / "audit-workspace/tools/build_esp32_rhino_ram_lifetimes.py"
    engine.ADDITIONS += EXTRA
    with tempfile.TemporaryDirectory(prefix="rhino-stack-observer-", dir=root) as temporary:
        generated = Path(temporary)
        (generated / "census.c").write_text(extended_source(original.read_text(), extension.read_text()))
        engine.build(root, workspace, output, generated)
    shutil.copyfile(extension, output / "stack-coverage.inc")
    shutil.copyfile(__file__, output / "stack-build-script.py")
    if (output / "build-script.py").read_bytes() != recipe.read_bytes():
        raise ValueError("Underlying build engine differs")
    metadata = json.loads((output / "build.json").read_text())
    metadata["native_stack_coverage"] = True
    metadata["base_observer_sha256"] = hashlib.sha256(original.read_bytes()).hexdigest()
    files = [p for p in output.rglob("*") if p.is_file() and p.name not in ("build.json", "image.sha256")]
    (output / "image.sha256").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " +
        p.relative_to(output).as_posix() + "\n" for p in sorted(files)))
    metadata["files"] = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in output.rglob("*") if p.is_file() and p.name != "build.json"}
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("Native stack coverage extension built; original PH4 unchanged; zero board measurements", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home()/"esp32-pilot")
    for name in ("workspace", "output", "observer"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    build(args.root, args.workspace, args.output, args.observer)
