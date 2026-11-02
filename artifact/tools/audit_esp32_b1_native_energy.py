#!/usr/bin/env python3
"""Replay frozen native captures across CPython float-summation versions."""
import argparse
import json
import math
from pathlib import Path

import run_esp32_b1_native_energy as native


def equal_observation(computed, recorded):
    if type(computed) is not type(recorded):
        return False
    if isinstance(computed, dict):
        return computed.keys() == recorded.keys() and all(equal_observation(computed[k], recorded[k]) for k in computed)
    if isinstance(computed, list):
        return len(computed) == len(recorded) and all(equal_observation(a, b) for a, b in zip(computed, recorded))
    if isinstance(computed, float):
        return math.isfinite(computed) and math.isfinite(recorded) and math.isclose(computed, recorded, rel_tol=1e-12, abs_tol=1e-18)
    return computed == recorded


def audit(folder):
    original = native.engine.capture_result

    def compatible_result(capture, *args):
        computed = original(capture, *args)
        recorded = json.loads((capture.parent / "energy-result.json").read_text())
        if not equal_observation(computed, recorded):
            raise ValueError("Recorded native observation differs beyond float roundoff or in exact evidence fields")
        # Keep the frozen collector's exact-record check; all fields were validated above.
        return recorded

    native.engine.capture_result = compatible_result
    try:
        result = native.audit(folder)
    finally:
        native.engine.capture_result = original
    result["numeric_validation"] = {"relative_float_tolerance": 1e-12, "absolute_float_tolerance": 1e-18,
                                    "integer_string_hash_and_structure_comparison": "exact",
                                    "reason": "CPython 3.12 improved floating-point sum; frozen 3.11 observations retained"}
    result["validator_sha256"] = native.engine.sha(Path(__file__))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = audit(args.directory)
    (args.directory / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "cells"}, indent=2))
