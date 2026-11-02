#!/usr/bin/env python3
"""Version-compatible replay without changing sealed acquisition sources/data."""
import argparse
import json
from pathlib import Path

from audit_esp32_b1_native_energy import equal_observation
import run_esp32_b1_energy as engine
import run_esp32_b1_kernel_energy as kernel


def audit(folder):
    case = json.loads((folder / "campaign.json").read_text())["case"]
    original = engine.capture_result

    def compatible_result(capture, *args):
        computed = original(capture, *args)
        recorded = json.loads((capture.parent / "energy-result.json").read_text())
        if not equal_observation(computed, recorded):
            raise ValueError("Energy observation changed beyond roundoff or in exact evidence fields")
        return recorded

    engine.capture_result = compatible_result
    try:
        result = engine.audit(folder) if case == "message_processing" else kernel.audit(folder)
    finally:
        engine.capture_result = original
    result["numeric_validation"] = {"relative_float_tolerance":1e-12, "absolute_float_tolerance":1e-18,
        "integer_string_hash_type_and_structure_comparison":"exact", "original_acquisition_sources_unchanged":True}
    result["validator_sha256"] = engine.sha(Path(__file__))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.directory)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("cells", "reuse")}, indent=2))
