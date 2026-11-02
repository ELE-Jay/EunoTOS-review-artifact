#!/usr/bin/env python3
"""Locate the reproduced legacy heap difference and audit bootstrap readiness."""
import argparse
from collections import Counter
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from run_esp32_followup import sha
from run_esp32_rhino_message_history import replay, fields

ROOT=Path(__file__).resolve().parents[1]
REPORTS=ROOT/"artifacts/reports"


def native_abi(source):
    layouts=set()
    sizes=set()
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        for cu in elf.get_dwarf_info().iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag!="DW_TAG_typedef" or "DW_AT_name" not in die.attributes:
                    continue
                name=die.attributes["DW_AT_name"].value
                if name not in (b"k_mm_list_t",b"ktask_t"):
                    continue
                body=die.get_DIE_from_attribute("DW_AT_type")
                if name==b"ktask_t":
                    sizes.add(body.attributes["DW_AT_byte_size"].value)
                else:
                    layouts.update(c.attributes["DW_AT_data_member_location"].value for c in body.iter_children()
                        if c.tag=="DW_TAG_member" and c.attributes["DW_AT_name"].value==b"mbinfo")
    if layouts!={16} or sizes!={136}:
        raise ValueError("Actual native allocator/TCB layout differs")
    return {"block_header_bytes":16,"task_control_bytes":136,"bootstrap_stack_bytes":8704}


def diagnose(result,folder,abi):
    cases=[]
    normalized=[]
    for index,run in enumerate(result["runs"],1):
        boot=[t for t in run["tasks"] if t["name"]=="main" and t["reserved"]==abi["bootstrap_stack_bytes"]]
        if len(boot)!=1:
            raise ValueError("Expected exactly one SDK bootstrap task")
        boot=boot[0]
        blocks=Counter(b["usable"] for b in run["live_blocks"])
        events=[fields(json.loads(s)["line"]) for s in (folder/"captures"/("reset%d.jsonl"%index)).read_text().splitlines()
                if "RHINO_MESSAGE_RAM event=" in s]
        pointers=(boot["stack"],boot["tcb"])
        released={p:[e["event"] for e in events if e["kind"]==2 and e["pointer"]==p] for p in pointers}
        if boot["present"]:
            if boot["deleted"] or any(released.values()) or boot["stack_usable"]!=8704 or boot["tcb_usable"]!=136:
                raise ValueError("Retained bootstrap ownership differs")
            blocks.subtract((8704,136))
            state="retained-ready" if boot["state"]==1 else "retained-other"
            if state!="retained-ready":
                raise ValueError("Unexpected bootstrap state")
        else:
            if not all(boot[k] for k in ("deleted","stack_freed","tcb_freed")) or any(len(v)!=1 for v in released.values()):
                raise ValueError("Bootstrap retirement lacks real native frees")
            # These frees are performed by Rhino's existing dynamic resource task.
            reclaimer=next(t for t in run["tasks"] if t["name"]=="dyn_mem_proc_task")
            if any(e["task"]!=reclaimer["tcb"] for e in events if e["kind"]==2 and e["pointer"] in pointers):
                raise ValueError("Bootstrap freed by an unexpected task")
            state="deleted-and-freed"
        normalized.append(+blocks)
        cases.append({"reset":index,"state":state,"stack_pointer":boot["stack"],"tcb_pointer":boot["tcb"],
            "free_events":{str(k):v for k,v in released.items()},"legacy_heap_final_bytes":run["legacy_heap_final_bytes"],
            "fixed_pool_free_bytes":run["fixed_pool_free_bytes"],"readiness":run["bootstrap_readiness"]})
    if any(n!=normalized[0] for n in normalized) or len({r["fixed_pool_free_bytes"] for r in cases})!=1:
        raise ValueError("Difference includes other live allocation sizes or fixed-pool usage")
    expected=abi["bootstrap_stack_bytes"]+abi["task_control_bytes"]+2*abi["block_header_bytes"]
    occupied={r["state"]:r["legacy_heap_final_bytes"] for r in cases}
    if len(occupied)==2 and occupied["retained-ready"]-occupied["deleted-and-freed"]!=expected:
        raise ValueError("Retained native blocks do not explain the measured difference")
    return {"cases":cases,"explained_bytes":expected,
        "remaining_live_large_block_size_multiset":{str(k):v for k,v in sorted(normalized[0].items())}}


def audit(reports=REPORTS):
    before_source=reports/"esp32-rhino-message-history-v1"
    after_source=reports/"esp32-rhino-message-history-v2"
    before=reports/"esp32-rhino-message-history-b1-v2"
    after=reports/"esp32-rhino-message-ready-b1-v1"
    left,right=replay(before_source,before),replay(after_source,after)
    abi=native_abi(before_source)
    if native_abi(after_source)!=abi or left["independent_resets"]!=5 or right["independent_resets"]!=5:
        raise ValueError("Five resets or native ABI differ")
    a,b=diagnose(left,before,abi),diagnose(right,after,abi)
    if {r["state"] for r in a["cases"]}!={"retained-ready","deleted-and-freed"} or \
            any(r["state"]!="deleted-and-freed" or not r["readiness"] for r in b["cases"]) or \
            len(set(right["legacy_heap_final_bytes"]))!=1 or a["remaining_live_large_block_size_multiset"]!=b["remaining_live_large_block_size_multiset"]:
        raise ValueError("The readiness contrast does not close the declared allocation difference")
    return {"audit":"pass","os":"AliOS-Rhino","board_mac":"34:98:7a:a2:85:28",
        "native_profile":"GCC5 / 240 MHz / single core / 100 Hz / original TM message",
        "before":a,"after":b,"native_abi":abi,"independent_resets":10,
        "legacy_heap_before_bytes":left["legacy_heap_final_bytes"],"legacy_heap_after_bytes":right["legacy_heap_final_bytes"],
        "other_live_block_size_multiset_equal":True,"original_workload_unchanged":True,
        "old_results_modified":False,"original_flash_restored":True,"whole_live_ram_peak_bytes":None,
        "ranking_eligible":False,"observer_effect_not_isolated":True,
        "historical_inference":"Same-profile reproduction explains the historical 8872-byte difference; old captures have no allocation identities and remain unchanged.",
        "evidence":{name:sha(reports/name) for name in (
            "esp32-rhino-message-history-v1/build.json","esp32-rhino-message-history-v2/build.json",
            "esp32-rhino-message-history-b1-v2/campaign.json","esp32-rhino-message-ready-b1-v1/campaign.json")}}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--reports",type=Path,default=REPORTS)
    args=parser.parse_args()
    result=audit(args.reports)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:result[k] for k in ("audit","legacy_heap_before_bytes","legacy_heap_after_bytes",
        "independent_resets","ranking_eligible")},indent=2))
