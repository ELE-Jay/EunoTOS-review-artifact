"""Observe the native entry/switch and idle watermark before native recoloring."""
import re

NATIVE="arch/xtensa/src/esp32/esp32_start.c"


def instrument(text):
    from nuttx_message_observer import replace_once
    text=replace_once(text,"uint32_t g_idlestack[IDLETHREAD_STACKWORDS]",
        "extern volatile uint32_t bench_nuttx_startup[12];\n\nuint32_t g_idlestack[IDLETHREAD_STACKWORDS]")
    return replace_once(text,'  __asm__ __volatile__("mov sp, %0\\n" : : "r"(sp));',
        '  __asm__ __volatile__("s32i sp, %1, 24\\n"\n'
        '                       "mov sp, %0\\n"\n'
        '                       "s32i sp, %1, 28\\n"\n'
        '                       : : "r"(sp), "r"(bench_nuttx_startup) : "memory");')


def forward_branches(source,name="__wrap_iotosbench_main"):
    from elftools.elf.elffile import ELFFile
    with (source/"application.elf").open("rb") as stream:
        elf=ELFFile(stream)
        symbol=elf.get_section_by_name(".symtab").get_symbol_by_name(name)[0]
        low=symbol["st_value"]
        end=low+symbol["st_size"]
        section=elf.get_section(symbol["st_shndx"])
        targets=set()
        for a,encoded,target in re.findall(r"^([0-9a-f]+):\s+([0-9a-f]{6})\s+j\s+([0-9a-f]+) <"+re.escape(name)+r"\+0x[0-9a-f]+>$",
                (source/"disassembly.txt").read_text(),re.M):
            pc,word,at=int(a,16),int(encoded,16),int(target,16)
            if not low<=pc<at<end: continue
            delta=word>>6
            if delta&(1<<17): delta-=1<<18
            offset=pc-section["sh_addr"]
            if word&63!=6 or pc+4+delta!=at or section.data()[offset:offset+3]!=word.to_bytes(3,"little"):
                raise ValueError("Native forward branch differs from actual ELF")
            targets.add(at)
    return sorted(targets),end


def observations(lines,proof):
    found=[(i,s) for i,s in enumerate(lines) if s.startswith("NUTTX_BOOT_STACK ")]
    if len(found)!=1:
        raise ValueError("Native startup observation missing or repeated")
    at,line=found[0]
    matches=re.fullmatch(r"NUTTX_BOOT_STACK entry_sp=(\d+) before_switch=(\d+) after_switch=(\d+) idle=(\d+) reserved=(\d+) painted=(\d+) verified=(\d+) recolor_sp=(\d+) spare=(\d+) touched=(\d+) recolors=(\d+) frame=(\d+)",line)
    if matches is None:
        raise ValueError("Native startup field shape differs")
    entry,before,after,low,n,paint,verified,sp,spare,touched,count,frame=map(int,matches.groups())
    stack=proof["reservations"]["g_idlestack"]
    if [low,n]!=stack or n!=paint or paint!=verified or verified!=3072 or after!=low+n or \
            not 0x3ffe0000<=before<entry<0x40000000 or entry-before!=frame or frame!=32 or \
            any(s%16 for s in (entry,before,after,sp)) or not low+64<sp<after or \
            spare%4 or touched%4 or not 0<=spare<n or spare+touched!=n or count!=1 or \
            at+1>=len(lines) or not lines[at+1].startswith("TM_N_ID "):
        raise ValueError("Native startup paint/switch/context/watermark differs")
    return {"application_entry_sp":entry,"before_native_switch_sp":before,"after_native_switch_sp":after,
        "inherited_native_frame_bytes":frame,"idle_stack_address":low,"idle_reserved_bytes":n,
        "initial_painted_and_verified_bytes":paint,"before_native_recolor_sp":sp,
        "spare_pattern_bytes":spare,"touched_watermark_bytes":touched,"resolution_bytes":4,
        "observed_before_native_idle_recolor":True,"already_in_static_sram":True,
        "scope":"native idle startup before recolor; observer-inclusive historical writes, not ROM/bootloader or simultaneous-live bytes",
        "full_live_ram_peak_bytes":None}
