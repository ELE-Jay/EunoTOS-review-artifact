#!/usr/bin/env python3
"""Reuse the branch-aware decoder for native Rhino's original message and timer paths."""
import hashlib
import json
import os
from pathlib import Path
import re
from collect_esp32_riot_yield_freertos_control import collector_source as base_source

FUNCTIONS = ("riot_original_main", "_second_thread", "_timer_callback", "msg_send", "msg_receive", "thread_create", "peer_entry",
    "xtimer_set", "coreclk", "controller_entry", "application_start", "alarm_expired", "fail", "registry_count",
    "krhino_fix_buf_queue_create", "buf_queue_create", "krhino_buf_queue_send", "krhino_buf_queue_recv",
    "krhino_buf_queue_del", "krhino_task_create", "krhino_task_del", "pend_task_wakeup", "pend_to_blk_obj",
    "pend_state_end_proc", "core_sched", "timer_init", "timer_set_counter_value", "timer_set_alarm_value",
    "timer_isr_register", "timer_enable_intr", "timer_start", "timer_get_counter_value", "timer_pause",
    "timer_disable_intr", "esp_intr_alloc_intrstatus", "esp_intr_free", "espos_isr_enter", "espos_isr_exit")
NORETURN = ("fail", "abort")


def collector_source(source):
    source = base_source(source)
    source = re.sub(r"^FUNCTIONS = .*?\nNORETURN = .*?\n", "FUNCTIONS = " + repr(FUNCTIONS) +
                    "\nNORETURN = " + repr(NORETURN) + "\n", source, count=1, flags=re.M | re.S)
    return source.replace("downloads/riot-yield-freertos-v1", "downloads/riot-msg-alios-v2").replace(
        "yield-control", "msg-control").replace("RIOT YIELD CONTROL", "RIOT MSG CONTROL")


if __name__ == "__main__":
    root = Path(os.environ.get("ESP32_PILOT_ROOT", str(Path.home() / "esp32-pilot")))
    directory = root / "downloads/riot-msg-alios-v2"
    metadata = json.loads((directory / "build.json").read_text())
    for name, value in metadata["files"].items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != value:
            raise ValueError("Changed build before control extraction: " + name)
    manifest = directory / "image.sha256"
    expected = "".join(value + "  " + name + "\n" for name, value in sorted(metadata["files"].items()))
    if manifest.exists() and manifest.read_text() != expected:
        raise ValueError("Existing image manifest differs")
    manifest.write_text(expected)
    script = directory / "collect-msg-control.py"
    if script.exists():
        raise ValueError("Control extraction already exists")
    script.write_text(collector_source(Path(__file__).with_name("collect_esp32_rhealstone_irq_control.py").read_text()))
    exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__", "__file__": str(script)})
