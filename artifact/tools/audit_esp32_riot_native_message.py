#!/usr/bin/env python3
"""Verify native RIOT's unchanged one-second message test, not isolated IPC latency."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
from urllib.request import urlopen

from build_esp32_riot_native_message import NATIVE
from audit_esp32_riot_original import UPSTREAM,capture as original_capture
from audit_esp32_riot_ram_lifetimes import LIBRARY_SHA
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_followup import envelope,independent_captures,verified
from audit_esp32_resources import audit_elf_image
from audit_esp32_zephyr_thread import read_raw_capture
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT/"artifacts/reports/riot-original-v1/msg_pingpong"
HEADER_URL="https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-13.2.0/gcc/ginclude/stdatomic.h"
HEADER_SHA="e6544cb60cf2b30c69d47424f7b04ab18bd2bc97e03a9c852b238f95ed26f3ca"
GCC_SOURCE="https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-13.2.0/"


def sources(folder):
    rows=[("source/"+p.name,UPSTREAM+"tests/bench/msg_pingpong/"+p.name) for p in sorted((REFERENCE/"source").iterdir()) if p.is_file()]
    rows += [("native-source/"+n,UPSTREAM+n) for n in NATIVE]
    rows += [("Makefile.bench_common",UPSTREAM+"tests/bench/Makefile.bench_common"),
             ("Makefile.tests_common",UPSTREAM+"tests/Makefile.tests_common"),("compiler-stdatomic.h",HEADER_URL)]
    rows += [("licenses/"+n,GCC_SOURCE+n) for n in ("COPYING3","COPYING.RUNTIME")]
    return [{"path":p,"url":u,"sha256":sha(folder/p)} for p,u in rows]


def provenance(folder):
    (folder/"licenses").mkdir(exist_ok=True)
    for name in ("COPYING3","COPYING.RUNTIME"):
        path=folder/"licenses"/name
        if not path.exists():
            with urlopen(GCC_SOURCE+name,timeout=60) as response: path.write_bytes(response.read())
    known=set()
    for p in (ROOT/"artifacts/reports").rglob("official-*.json"):
        data=json.loads(p.read_text())
        if isinstance(data,list):
            known.update((r["url"],r["sha256"]) for r in data if isinstance(r,dict) and {"url","sha256"}<=r.keys())
    proof=sources(folder)
    for row in proof:
        if (row["url"],row["sha256"]) not in known:
            with urlopen(row["url"],timeout=60) as response:
                if hashlib.sha256(response.read()).hexdigest()!=row["sha256"]:
                    raise ValueError("Native/original/compiler header differs from fixed upstream: "+row["path"])
    (folder/"official-source.json").write_text(json.dumps(proof,indent=2)+"\n")


def build(folder,verify_upstream=False):
    metadata=json.loads((folder/"build.json").read_text())
    if metadata["status"]!="build_pass_not_measured" or metadata["board_resets"] or metadata["ranking_eligible"]:
        raise ValueError("Unmeasured native original build misqualified")
    for n,v in metadata["files"].items():
        if not (folder/n).resolve().is_relative_to(folder.resolve()) or sha(folder/n)!=v:
            raise ValueError("Native original build/source manifest differs")
    for p in (REFERENCE/"source").iterdir():
        if p.is_file() and (folder/"source"/p.name).read_bytes()!=p.read_bytes():
            raise ValueError("Original message workload changed")
    if (folder/"config").read_bytes()!=(REFERENCE/"config.h").read_bytes() or \
            (folder/"compiler-wrapper.sh").read_bytes()!=(ROOT/"firmware/bsp/esp32/riot_startup_probe/gcc13-legacy-newlib.sh").read_bytes() or \
            (folder/"build-script.py").read_bytes()!=(ROOT/"tools/build_esp32_riot_native_message.py").read_bytes() or \
            sha(folder/"compiler-stdatomic.h")!=HEADER_SHA or "13.2.0" not in (folder/"compiler.txt").read_text():
        raise ValueError("Native original configuration/compiler-header/ABI route changed")
    if verify_upstream: provenance(folder)
    if json.loads((folder/"official-source.json").read_text())!=sources(folder):
        raise ValueError("Pinned original/native/compiler header proof differs")
    library=json.loads((folder/"official-native-library.json").read_text())
    if sha(folder/"libg_nano.a")!=LIBRARY_SHA or library["library_sha256"]!=LIBRARY_SHA or \
            "xtensa-esp-elf/lib/esp32/libg_nano.a(libc_a-mallocr.o)" not in (folder/"application.map").read_text():
        raise ValueError("Actual native Newlib-nano link differs from vendor-pinned library")
    log=re.sub(r"\x1b\[[0-9;]*m","",(folder/"build.log").read_text()).replace("\\\n"," ")
    commands=[shlex.split(l.strip()) for l in log.splitlines() if "gcc13-legacy-newlib.sh" in l and " -c " in l]
    for suffix in ("/tests/bench/msg_pingpong/main.c",*("/"+n for n in NATIVE if n.endswith(".c"))):
        selected=[args for args in commands if any(a.endswith(suffix) for a in args)]
        if len(selected)!=1 or [a for a in selected[0] if re.fullmatch(r"-O(?:[0-3sgz]|fast)",a)]!=["-Os"] or \
                "-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1" not in selected[0] or not any("native-compiler-headers" in a for a in selected[0]) or \
                any(a.startswith(("-DTEST_DURATION","-Dmain=","-Dmsg_send=","-Dmsg_receive=")) for a in selected[0]):
            raise ValueError("Actual original/native compiler selection or one-second budget changed: "+suffix)
    audit_elf_image(folder/"application.elf",folder/"application.bin")
    machine=calls(folder,required=[("main","thread_create"),("main","msg_send"),
        ("_second_thread","msg_receive"),("main","ztimer_set")],require_iram=False)
    return {"audit":"pass","official_source_files_checked":len(sources(folder))-2,"compiler_license_files_checked":2,"machine_calls":machine,
        "original_body_unchanged":True,"native_original_no_adapter":True,"original_duration_us":1000000,
        "compiler":"GCC13 / GCC12 headers / GCC13 native stdatomic / GCC13 Newlib-nano",
        "clock_hz":240000000,"cores":1,"tick_hz":0,"optimization":"-Os","ranking_eligible":False,
        "actual_timer_backend":"native ztimer_xtimer_compat, unchanged from the original board configuration",
        "scope":"whole original synchronous message iteration count in the nominal one-second window, not isolated API latency"}


def capture(folder,index):
    read_raw_capture(folder,index)
    return original_capture(folder/("reset%d.jsonl"%index),"msg_pingpong",set())


def audit(folder,source):
    metadata=envelope(folder)
    if metadata["kind"]!="riot-native-message" or metadata["board_mac"]!="34:98:7a:a2:85:28" or metadata["independent_resets"]!=3:
        raise ValueError("Wrong replacement-board/original native campaign")
    proof=build(source)
    for p in (folder/"build").iterdir():
        if sha(p)!=sha(source/p.name): raise ValueError("Measured native image differs from qualified source")
    verified(folder/"captures",folder/"build",metadata["board_mac"])
    independent_captures(folder/"captures")
    runs=[]
    for index in (1,2,3):
        verified(folder/"captures",folder/"build",metadata["board_mac"],logs=("verify-run%d.log"%index,))
        runs.append(capture(folder/"captures",index))
    values=[r["metrics"]["msg_pingpong"]["original_count"] for r in runs]
    return {"audit":"pass","os":"RIOT","build":proof,"runs":runs,"original_counts":values,
        "independent_resets":3,"original_flash_restored":True,"ranking_eligible":False,"energy_measured":False,
        "external_independent_replication":False,"scope":"replacement-board native tickless original, separate from aligned RTOS adapter profiles"}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build",type=Path)
    parser.add_argument("--capture",type=Path)
    parser.add_argument("--verify-upstream",action="store_true")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    result=audit(args.capture,args.build) if args.capture else build(args.build,args.verify_upstream)
    if args.output: args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
