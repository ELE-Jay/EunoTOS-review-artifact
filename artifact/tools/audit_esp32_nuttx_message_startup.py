"""Bind a native idle-stack observation to the installed entry and recolor path."""
import json
from pathlib import Path
import re
import struct

from elftools.elf.elffile import ELFFile
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_freertos_startup_stack import verify_trampoline
from audit_esp32_zephyr_syskernel_sema import literal_word
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]


def build(source,reservations):
    official=json.loads((ROOT/"artifacts/reports/esp32-nuttx-retained-owners-v1/official-stack-source.json").read_text())
    for row in official:
        path=source/("startup-original.c" if row["path"].endswith("esp32_start.c") else "native-source/"+row["path"])
        if sha(path)!=row["sha256"]:
            raise ValueError("Native startup/color source differs from pinned upstream")
    text=(source/"disassembly.txt").read_text()
    from nuttx_message_startup import forward_branches
    for name in ("__wrap_iotosbench_main","__wrap_xtensa_stack_color"):
        anchors,_=forward_branches(source,name)
        for anchor in anchors:
            if (source/("startup-branch-%x.txt"%anchor)).read_text() not in text:
                raise ValueError("Reachable native wrapper branch listing missing")
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbols=elf.get_section_by_name(".symtab")
        state=symbols.get_symbol_by_name("bench_nuttx_startup")[0]
        entry=symbols.get_symbol_by_name("bench_nuttx_startup_entry")[0]
        native=symbols.get_symbol_by_name("__start")[0]
        if entry["st_shndx"]!=native["st_shndx"]:
            raise ValueError("Entry trampoline is not in the native startup code section")
        low,size=reservations["g_idlestack"]
        section=elf.get_section(state["st_shndx"])
        bss=[symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("_sbss","_ebss")]
        a,b=state["st_value"],state["st_value"]+state["st_size"]
        if state["st_size"]!=48 or section.name!=".noinit" or section["sh_type"]!="SHT_NOBITS" or \
                not (b<=low or a>=low+size) or not (b<=bss[0] or a>=bss[1]) or \
                elf["e_entry"]!=entry["st_value"] or struct.unpack_from("<I",(source/"application.bin").read_bytes(),4)[0]!=entry["st_value"]:
            raise ValueError("Native startup entry/state placement differs")
        verify_trampoline(elf,symbols,text,"bench_nuttx_startup_entry",
            [a,low,low+size,0xa5a5a5a5,0x4e425331],"__start")
        body=re.search(r"^[0-9a-f]+ <__start>:\n(.*?)(?=\n\n|\Z)",text,re.M|re.S)
        if body is None:
            raise ValueError("Native startup body missing")
        rows=[]
        code=elf.get_section(native["st_shndx"])
        for address,encoding,instruction in re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.+)$",body[1],re.M):
            if instruction.startswith("call"): break
            pc=int(address,16)
            raw=int(encoding,16).to_bytes(len(encoding)//2,"little")
            at=pc-code["sh_addr"]
            if code.data()[at:at+len(raw)]!=raw:
                raise ValueError("Native pre-switch disassembly differs from ELF")
            rows.append((pc,encoding,instruction))
        code_text="\n".join(r[2] for r in rows)
        if not rows or not re.fullmatch(r"entry\s+a1, 32",rows[0][2]) or not re.search(
                r"s32i(?:\.n)?\s+a1, a(\d+), 24\nor\s+a1, a(\d+), a\2\ns32i(?:\.n)?\s+a1, a\1, 28",code_text):
            raise ValueError("Native entry frame or exact observed SP switch changed")
        values=[literal_word(elf,f"{pc:x}: {encoding} {instruction}",int(re.match(r"l32r\s+a(\d+)",instruction)[1]))
            for pc,encoding,instruction in rows if instruction.startswith("l32r")]
        if a not in values or low+size not in values:
            raise ValueError("Native switch/state literal differs")
    return {"application_startup_stack_coverage":True,"startup_stack_observer":{
        "entry_address":entry["st_value"],"original_entry_address":native["st_value"],
        "state_address":a,"state_bytes":48,"idle_stack_address":low,"idle_reserved_bytes":size,
        "native_inherited_frame_bytes":32,"resolution_bytes":4,"official_sources":official,
        "machine_calls":calls(source,[("up_initial_state","__wrap_xtensa_stack_color"),
            ("__wrap_xtensa_stack_color","xtensa_stack_color"),("message_dump","message_startup_report")],require_iram=False)}}
