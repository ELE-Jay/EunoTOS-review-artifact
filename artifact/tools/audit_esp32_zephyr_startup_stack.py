"""Bind the inherited ROM-stack observation to the unchanged Zephyr loader."""
from pathlib import Path
import re
import struct

from elftools.elf.elffile import ELFFile
from audit_esp32_freertos_startup_stack import verify_trampoline
from audit_esp32_freertos_ram_lifetimes import calls
from audit_esp32_resources import physical_intervals, static_footprint
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "soc/espressif/common/loader.c":"82c10a33e3f4cd841bc4b2ca03ca031ca63d7e56b83022fb6a4b20ddf76cf88f",
    "soc/espressif/esp32/soc.c":"85c256d5d873acbce964b6dcfc720119a2e8c29d18a1c4037e68aefd63ce0334",
    "soc/espressif/esp32/memory.h":"8856352b74926a223f7d616d078517f4579c9b5cfa97db964d01d0993bc64d55",
    "soc/espressif/esp32/default.ld":"700adbc5c57499963cd4cc9b180037089976d5ba38160501ab1f60fffaaaed6e",
    "hal/components/esp_rom/esp32/ld/esp32.rom.ld":"35c1710c1796faf507fb6fcf0d01c3690c61f4289008e5c6f55131e1597ec41c",
}


def build(source):
    import json
    from build_esp32_zephyr_message_lifetimes import startup_observer_sources
    vectors = json.loads((source / 'build.json').read_text()).get('application_startup_vector_coverage',False)
    for name, digest in SOURCES.items():
        if sha(source / "native-startup" / name) != digest:
            raise ValueError("Official fixed startup source differs: " + name)
    folder = ROOT / "firmware/bsp/esp32/resource_census/zephyr_startup_stack"
    for name, content in startup_observer_sources(folder,vectors).items():
        if (source / "observer" / name).read_text() != content:
            raise ValueError("Startup observer source differs")
    with (source / "application.elf").open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        state, entry = [symbols.get_symbol_by_name(n)[0] for n in
            ("bench_z_startup_state", "bench_z_startup_entry")]
        bounds = [symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("_stack_sentry", "__stack")]
        bss = [symbols.get_symbol_by_name(n)[0]["st_value"] for n in ("__bss_start", "__bss_end")]
        section = elf.get_section(state["st_shndx"])
        if bounds != [0x3ffe1320, 0x3ffe3f20] or state["st_size"] != 40 or \
                section["sh_type"] != "SHT_NOBITS" or not section.name.endswith(".noinit") or \
                not (state["st_value"] + 40 <= bss[0] or state["st_value"] >= bss[1]) or \
                elf["e_entry"] != entry["st_value"] or struct.unpack_from("<I",
                    (source / "application.bin").read_bytes(), 4)[0] != entry["st_value"]:
            raise ValueError("ROM window, pre-BSS state or installed entry differs")
        text = (source / "disassembly.txt").read_text()
        verify_trampoline(elf, symbols, text, "bench_z_startup_entry",
            [state["st_value"], *bounds, 0xa5a5a5a5, 0x5a535031], "__start")
        entry_body = re.search(r'^[0-9a-f]+ <bench_z_startup_entry>:\n(.*?)(?=\n\n|\Z)',text,re.M|re.S)[1]
        if vectors and (len(re.findall(r'\brsr\.vecbase\s+a3\b',entry_body)) != 1 or
                not re.search(r'\brsr\.vecbase\s+a3\n[^\n]*\bs32i(?:\.n)?\s+a3, a2, 8\b',entry_body)):
            raise ValueError('Entry vector readback is not bound to the ELF instructions')
        # The original loader ENTRY remains the first stack-changing instruction.
        native = symbols.get_symbol_by_name("__start")[0]
        code = elf.get_section(native["st_shndx"])
        at = native["st_value"] - code["sh_addr"]
        if code.data()[at:at+3] != bytes.fromhex("364100"):
            raise ValueError("Original loader ENTRY32 changed")
    footprint = static_footprint(source / "application.elf")
    boot = physical_intervals(bounds[0], bounds[1] - bounds[0])
    for section in footprint["ram_sections"]:
        for a, b in physical_intervals(int(section["address"], 16), section["bytes"]):
            if any(a < d and c < b for c, d in boot):
                raise ValueError("Static allocated RAM overlaps inherited ROM-stack window")
    return {"application_startup_stack_coverage":True,
        **({'application_startup_vector_coverage':True} if vectors else {}), "startup_stack_observer":{
        "lower_bound":bounds[0], "entry_sp_upper_bound":bounds[1], "state_bytes":40,
        "entry_address":entry["st_value"], "native_entry_address":native["st_value"],
        "unpainted_guard_bytes":64, "resolution_bytes":4,
        "machine_calls":calls(source, [("__start", "bootloader_init"), ("__start", "__esp_platform_start"),
            ("__esp_platform_start", "z_cstart"), ("bg_thread_main", "bench_z_startup_finish"),
            ("__wrap_main", "bench_z_startup_report")], require_iram=False)}}


def observations(lines, proof):
    rows = [(i, m) for i, s in enumerate(lines) if (m := re.fullmatch(
        r"ZEPHYR_BOOT_STACK low=(\d+) entry_sp=(\d+) paint_end=(\d+) painted=(\d+) verified=(\d+) main_sp=(\d+) spare=(\d+) touched=(\d+) guard=(\d+) switches=(\d+)", s))]
    if len(rows) != 1 or sum(s.startswith("ZEPHYR_BOOT_STACK ") for s in lines) != 1:
        raise ValueError("Startup observation absent or duplicated")
    index, match = rows[0]
    low, entry, end, painted, verified, main_sp, spare, touched, guard, count = map(int, match.groups())
    p = proof["startup_stack_observer"]
    main, capacity = proof["reservations"]["z_main_stack"]
    if low != p["lower_bound"] or not low + guard < entry <= p["entry_sp_upper_bound"] or entry % 16 or \
            end != entry - guard or guard != 64 or painted != end - low or painted != verified or \
            painted <= 0 or not 0 <= spare <= painted or spare % 4 or touched % 4 or spare + touched != painted or \
            not main <= main_sp < main + capacity or main_sp % 16 or count != 1 or \
            index + 1 >= len(lines) or not lines[index + 1].startswith("ZEPHYR_RAM BEGIN "):
        raise ValueError("Startup bounds, marker arithmetic, first-main context or report phase differs")
    extra = {}
    if proof.get('application_startup_vector_coverage'):
        vectors = [(i,m) for i,s in enumerate(lines) if (m:=re.fullmatch(
            r'ZEPHYR_BOOT_OWNERSHIP entry_vecbase=(\d+)',s))]
        if len(vectors) != 1 or vectors[0][0] != index-1 or int(vectors[0][1][1]) not in (0x40000000,0x40080000):
            raise ValueError('Startup vector readback absent, misplaced or outside declared boot ABI')
        extra['entry_vector_base'] = int(vectors[0][1][1])
    return {"application_entry_sp":entry, "painted_start":low, "painted_end":end,
        "initial_painted_and_verified_bytes":painted, "first_main_task_sp":main_sp,
        "spare_pattern_bytes":spare, "touched_watermark_bytes":touched,
        "unpainted_guard_bytes":guard, "resolution_bytes":4,
        "observed_before_post_kernel_initialization":True,
        "scope":"inherited ROM-stack window from application entry to first native main context; no before-entry ROM, untouched frames or simultaneous-live peak",
        "full_live_ram_peak_bytes":None, **extra}
