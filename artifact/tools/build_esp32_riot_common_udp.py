#!/usr/bin/env python3
"""Build RIOT's native lwIP/POSIX binding of the frozen original UDP receiver."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_esp32_common_tcp_ports import original_receiver_parts, archive_host_sources, RECEIVER_SHA, SESSION_SHA
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]


def posix_sock_source(text):
    before = '    if (sock && sock->async_cb.gen && mbox_avail(&conn->recvmbox.mbox)) {'
    if text.count(before) != 1:
        raise ValueError('Native lwIP post-receive notification anchor changed')
    # POSIX counts each RCVPLUS; the generic sock re-notification is level based.
    return text.replace(before, '    if (!IS_USED(MODULE_POSIX_SOCKETS) && sock && sock->async_cb.gen && mbox_avail(&conn->recvmbox.mbox)) {')


def adapter_source():
    source = (ROOT / 'firmware/bsp/esp32/zperf_udp_receiver/port.c').read_text()
    anchor = '#ifdef ESP_PLATFORM\n#include <lwip/sockets.h>'
    if source.count(anchor) != 1:
        raise ValueError('Pinned common socket binding anchor changed')
    source = source.replace(anchor, '#if defined(IOTOS_RIOT)\n#include "riot_bindings.h"\n'
                            '#elif defined(ESP_PLATFORM)\n#include <lwip/sockets.h>')
    source = source.replace('#elif defined(ESP_PLATFORM)\nvoid register_',
                            '#elif defined(ESP_PLATFORM) && !defined(IOTOS_RIOT)\nvoid register_')
    before = ('    } else if (status == ZPERF_SESSION_FINISHED) {\n'
              '        printf("ORIGINAL_ZPERF_RX END datagrams=%u lost=%u outorder=%u bytes=%llu receiver_us=%llu jitter_us=%u\\n",')
    after = ('    } else if (status == ZPERF_SESSION_FINISHED) {\n'
             '        if (result->total_len > ULONG_MAX || result->time_in_us > ULONG_MAX) {\n'
             '            native_log("ORIGINAL_ZPERF_RX ERROR counter-display-range");\n'
             '            return;\n        }\n'
             '        printf("ORIGINAL_ZPERF_RX END datagrams=%u lost=%u outorder=%u bytes=%lu receiver_us=%lu jitter_us=%u\\n",')
    if source.count(before) != 1:
        raise ValueError('Original receiver output binding changed')
    source = source.replace(before, after).replace(
        '(unsigned long long)result->total_len,\n            (unsigned long long)result->time_in_us',
        '(unsigned long)result->total_len,\n            (unsigned long)result->time_in_us')
    return source.replace('#define __packed __attribute__((packed))',
                           '#ifndef __packed\n#define __packed __attribute__((packed))\n#endif')


def build(root, work, output, startup_probe=False):
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace') or work.exists() or output.exists():
        raise ValueError('Build on leon in fresh directories; preserve failed candidates')
    riot = root / 'RIOT-2024.10-devel'
    gcc = root / 'idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin'
    base_compiler = ROOT / 'tools/gcc13-legacy-newlib.sh'
    dependencies = root / 'downloads/riot-network-dependencies-v1'
    if shutil.disk_usage(output.parent).free < 150 * 1024 * 1024:
        raise ValueError('Insufficient persistent space for retained build evidence')
    app = work / 'source'
    app.mkdir(parents=True)
    output.mkdir(parents=True)
    maintained = ROOT / 'firmware/bsp/esp32/zperf_udp_receiver_riot'
    for name in ('Makefile', 'main.c', 'riot_bindings.h'):
        shutil.copyfile(maintained / name, app / name)
    if startup_probe:
        shutil.copyfile(maintained / 'startup_probe.c', app / 'startup_probe.c')
        with (app / 'Makefile').open('a') as f:
            f.write('\nLINKFLAGS += ' + ' '.join('-Wl,--wrap=' + name for name in
                ('heap_caps_init', 'heap_caps_match', '__assert_func', 'multi_heap_malloc', 'multi_heap_set_lock', 'tlsf_malloc',
                 'syscalls_init', 'syscalls_init_arch', '__libc_init_array', '__sinit', '__fsetlocking')) + '\n')
    # Keep GCC13 atomic types/macros together, as in the existing native RIOT message port.
    headers = app / 'native-compiler-headers'
    headers.mkdir()
    shutil.copyfile(gcc.parent / 'lib/gcc/xtensa-esp-elf/13.2.0/include/stdatomic.h', headers / 'stdatomic.h')
    (app / 'port.c').write_text(adapter_source())
    for name, text in original_receiver_parts().items():
        (app / name).write_text(text)
    # Preserve RIOT's native -Os profile; only the common receiver body uses -O2.
    compiler = work / 'receiver-cc.sh'
    native_sock = riot / 'pkg/lwip/contrib/sock/lwip_sock.c'
    repaired_sock = work / 'posix-lwip-sock.c'
    repaired_sock.write_text(posix_sock_source(native_sock.read_text()))
    shutil.copyfile(native_sock, output / 'native-sock-original.c')
    shutil.copyfile(repaired_sock, output / 'native-sock-posix-count.c')
    sock_binding = ('arguments=("$@")\nfor i in "${!arguments[@]}"; do\n'
        '  if [[ "${arguments[$i]}" == "' + str(native_sock) + '" ]]; then\n'
        '    arguments[$i]="' + str(repaired_sock) + '"\n'
        '    exec "' + str(base_compiler) + '" "${arguments[@]}" -I"' + str(native_sock.parent) + '"\n'
        '  fi\ndone\n')
    diagnostic_binding = ''
    if startup_probe:
        native_heap = riot / 'build/pkg/esp32_sdk/components/heap/heap_caps_init.c'
        heap_text = native_heap.read_text()
        markers = {
            '    assert(heap_idx == num_heaps);':
                '    ets_printf("COMMON_HEAP regions=%u heaps=%u index=%u table=%p regions_ptr=%p\\n", (unsigned)num_regions, (unsigned)num_heaps, (unsigned)heap_idx, temp_heaps, regions);\n    assert(heap_idx == num_heaps);',
            '        if (heap_caps_match(&temp_heaps[i], MALLOC_CAP_8BIT|MALLOC_CAP_INTERNAL)) {':
                '        ets_printf("COMMON_HEAP match_index=%u heap=%p caps=%x,%x,%x\\n", (unsigned)i, temp_heaps[i].heap, temp_heaps[i].caps[0], temp_heaps[i].caps[1], temp_heaps[i].caps[2]);\n        if (heap_caps_match(&temp_heaps[i], MALLOC_CAP_8BIT|MALLOC_CAP_INTERNAL)) {'}
        for before, after in markers.items():
            if heap_text.count(before) != 1:
                raise ValueError('Native heap diagnostic anchor changed')
            heap_text = heap_text.replace(before, after)
        diagnostic_heap = work / 'heap-startup-probe.c'
        diagnostic_heap.write_text(heap_text)
        shutil.copyfile(native_heap, output / 'native-heap-init.c')
        shutil.copyfile(diagnostic_heap, output / 'diagnostic-heap-init.c')
        diagnostic_binding = ('arguments=("$@")\nfor i in "${!arguments[@]}"; do\n'
            '  if [[ "${arguments[$i]}" == "' + str(native_heap) + '" ]]; then\n'
            '    arguments[$i]="' + str(diagnostic_heap) + '"\n'
            '    exec "' + str(base_compiler) + '" "${arguments[@]}" -I"' + str(native_heap.parent) + '"\n'
            '  fi\ndone\n')
    compiler.write_text('#!/usr/bin/env bash\nset -eu\n' + diagnostic_binding + sock_binding +
        'for argument in "$@"; do\n'
        '  if [[ "$argument" == "' + str(app / 'port.c') + '" ]]; then\n'
        '    exec "' + str(base_compiler) + '" "$@" -O2\n'
        '  fi\n'
        '  if [[ "$argument" == */tlsf.c ]]; then\n'
        '    exec "' + str(base_compiler) + '" "$@" -fno-tree-loop-distribute-patterns\n'
        '  fi\ndone\nexec "' + str(base_compiler) + '" "$@"\n')
    compiler.chmod(0o755)
    env = dict(os.environ, PATH=str(gcc) + ':' + str(root / 'bin') + ':' + os.environ['PATH'],
               PYTHONDONTWRITEBYTECODE='1', PKG_SOURCE_LOCAL_ESP32_SDK_LIB_PHY=str(dependencies / 'sources/esp32_sdk_lib_phy'),
               PKG_SOURCE_LOCAL_ESP32_SDK_LIB_WIFI=str(dependencies / 'sources/esp32_sdk_lib_wifi'),
               PKG_SOURCE_LOCAL_TLSF=str(dependencies / 'native-sources/tlsf'))
    for name in ('CPATH', 'C_INCLUDE_PATH', 'LINKFLAGS'):
        env.pop(name, None)
    command = ['make', '-C', str(app), '-j2', 'QUIET=0', 'RIOTBASE=' + str(riot),
               'CC=' + str(compiler), 'BINDIRBASE=' + str(work / 'bin'), 'FLASH_MODE=dio', 'FLASH_SIZE=4',
               'RIOT_VERSION=2024.10-devel']
    with (output / 'build.log').open('x') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    record = {'status': 'build_pass_not_measured' if result.returncode == 0 else 'build_failed',
        'returncode': result.returncode, 'os': 'RIOT', 'board_resets': 0, 'ranking_eligible': False,
        'startup_diagnostic_only': startup_probe,
        'optimization': {'native': '-Os', 'original_receiver_translation_unit': '-O2'},
        'tlsf_iram_compatibility': 'Disable loop-to-memset folding for TLSF uint32 initialization: ESP32 instruction RAM prohibits byte stores',
        'posix_readiness_fix': 'Keep one RCVPLUS notification per datagram for POSIX counters; suppress the additional generic sock level re-notification after a receive',
        'original_receiver_sha256': RECEIVER_SHA, 'original_session_sha256': SESSION_SHA,
        'compiler': subprocess.check_output([str(gcc / 'xtensa-esp32-elf-gcc'), '--version']).decode().splitlines()[0],
        'command': command, 'adapter_change': 'RIOT native POSIX sockets and select; 10-ms quantized monotonic statistic clock; checked lossless native-width decimal display within fixed-load bounds; original functions unchanged'}
    shutil.copytree(app, output / 'application-source')
    shutil.copyfile(__file__, output / 'builder.py')
    shutil.copyfile(compiler, output / 'receiver-cc.sh')
    shutil.copyfile(riot / 'pkg/lwip/Makefile', output / 'native-lwip-package-Makefile')
    if result.returncode == 0:
        binary = work / 'bin/esp32-wroom-32'
        for src, dst in (('iotos-mainboard-udp.elf', 'application.elf'), ('iotos-mainboard-udp.elf.bin', 'application.bin'),
                         ('iotos-mainboard-udp.map', 'application.map'), ('esp_bootloader/bootloader.bin', 'bootloader.bin'),
                         ('partitions.bin', 'partitions.bin'), ('riotbuild/riotbuild.h', 'config.h')):
            shutil.copyfile(binary / src, output / dst)
        for name, text in original_receiver_parts().items():
            if (output / 'application-source' / name).read_text() != text:
                raise ValueError('Original receiver/session function changed')
        archive_host_sources(root, output)
    record['files'] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    with (output / 'build.json').open('x') as f:
        json.dump(record, f, indent=2)
    print(json.dumps({k:v for k,v in record.items() if k != 'files'}))
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.home() / 'esp32-pilot')
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--startup-probe', action='store_true')
    args = parser.parse_args()
    raise SystemExit(build(args.root, args.workspace, args.output, args.startup_probe))
