#!/usr/bin/env python3
"""Build Rhino's native IPv4 binding of the frozen common original UDP receiver."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_esp32_common_tcp_ports import original_receiver_parts, archive_host_sources, RECEIVER_SHA, SESSION_SHA
from run_esp32_followup import sha

ROOT = Path(__file__).resolve().parents[1]


def adapter_source():
    text = (ROOT / 'firmware/bsp/esp32/zperf_udp_receiver/port.c').read_text()
    before = '#include <sys/socket.h>\n#include <arpa/inet.h>\n#ifdef ESP_PLATFORM'
    if text.count(before) != 1:
        raise ValueError('Pinned socket adapter changed')
    text = text.replace(before, '#if defined(IOTOS_RHINO)\n#include "rhino_bindings.h"\n#else\n'
                        '#include <sys/socket.h>\n#include <arpa/inet.h>\n#endif\n'
                        '#if defined(IOTOS_RHINO)\n#elif defined(ESP_PLATFORM)')
    text = text.replace('#define CONFIG_NET_IPV6 1', '#define CONFIG_NET_IPV6 0')
    text = text.replace('#elif defined(ESP_PLATFORM)\nvoid register_',
                        '#elif defined(ESP_PLATFORM) && !defined(IOTOS_RHINO)\nvoid register_')
    return text.replace('#define __packed __attribute__((packed))',
                        '#ifndef __packed\n#define __packed __attribute__((packed))\n#endif')


def main_source():
    text = (ROOT / 'firmware/bsp/esp32/alios_iperf/native_iperf.c').read_text()
    start, end = text.index('struct native_entry {'), text.index('static void activate_ap(')
    text = text[:start] + text[end:]
    text = text.replace('#include "aos/kernel.h"', '#include "aos/kernel.h"\n#include "aos/cli.h"\n#include "k_api.h"')
    text = text.replace('#include "tcpip_adapter.h"', '#include "tcpip_adapter.h"\n#include "soc/rtc.h"\nextern int esp_clk_cpu_freq(void);')
    anchor = 'int application_start(int argc, char *argv[])'
    text = text.replace(anchor, 'int zperf_udp_receiver_main(int argc, char **argv);\n'
        'static void receiver_command(char *output, int length, int argc, char **argv)\n'
        '{\n    (void)output; (void)length;\n'
        '    unsigned bytes=krhino_cur_task_get()->stack_size*sizeof(cpu_stack_t);\n'
        '    printf("COMMON_NETWORK_RECEIVER_STACK bytes=%u\\n", bytes);\n'
        '    if (bytes!=8192) { puts("ORIGINAL_ZPERF_RX ERROR receiver stack"); return; }\n'
        '    zperf_udp_receiver_main(argc, argv);\n}\n'
        'static const struct cli_command receiver = {"zperf_udp_receiver", "Original UDP receiver", receiver_command};\n\n' + anchor)
    text = text.replace('    wifi_config_t configuration;',
        '    /* Match the native clock initialization of the measured message configuration. */\n'
        '    rtc_clk_cpu_freq_set(RTC_CPU_FREQ_240M);\n'
        '    setvbuf(stdout, NULL, _IONBF, 0);\n'
        '    printf("COMMON_NETWORK_CONDITIONS cpu_hz=%d cores=%d tick_hz=%d\\n",\n'
        '        esp_clk_cpu_freq(), RHINO_CONFIG_CPU_NUM, RHINO_CONFIG_TICKS_PER_SECOND);\n'
        '    if (esp_clk_cpu_freq()!=240000000 || RHINO_CONFIG_CPU_NUM!=1 || RHINO_CONFIG_TICKS_PER_SECOND!=100) return -1;\n'
        '    wifi_config_t configuration;')
    text = text.replace('    /* The native component initializer registers the unchanged iPerf CLI. */',
        '    if (aos_cli_register_command(&receiver)) return -1;\n'
        '    puts("COMMON_NETWORK AliOS-Rhino IPv4=192.168.4.1 receiver_core=original-zperf clock_resolution_us=10000");')
    return text


def build(root, work, output):
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace') or work.exists() or output.exists():
        raise ValueError('Use fresh directories on leon; preserve original evidence')
    source = root / 'AliOS-Things-bacc144bdc5df8fe8e302e3732675a920aa40bc5'
    if shutil.disk_usage('/dev/shm').free < 700 * 1024**2:
        raise ValueError('Insufficient temporary native build space')
    work.mkdir()
    output.mkdir(parents=True)
    # Copy selected sources; non-target MCU trees are read-only links, never built.
    def copy_tree(src, dst):
        dst.mkdir()
        for path in src.iterdir():
            target = dst / path.name
            if path.name in ('.git', 'out', '__pycache__', '.config', '.config.cmd', '.defconfig'):
                continue
            if path.is_dir():
                if src.name == 'mcu' and path.name != 'esp32':
                    target.symlink_to(path, target_is_directory=True)
                else:
                    copy_tree(path, target)
            else:
                shutil.copy2(path, target)
    native = work / 'source'
    copy_tree(source, native)
    app = native / 'app/example/native_iperf'
    (app / 'native_iperf.c').write_text(main_source())
    (app / 'port.c').write_text(adapter_source())
    maintained = ROOT / 'firmware/bsp/esp32/zperf_udp_receiver_rhino'
    for name in ('aos.mk', 'rhino_bindings.h'):
        shutil.copyfile(maintained / name, app / name)
    for name, text in original_receiver_parts().items():
        (app / name).write_text(text)
    shutil.copyfile(ROOT / 'firmware/bsp/esp32/alios_iperf/examples-Config.in',
                    native / 'app/example/Config.in')
    tools = work / 'tools'
    tools.mkdir()
    gcc = root / 'idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin'
    wrapper = ROOT / 'firmware/bsp/esp32/alios_board/xtensa-esp32-elf-gcc-legacy-newlib.sh'
    shutil.copyfile(wrapper, tools / 'xtensa-esp32-elf-gcc')
    (tools / 'xtensa-esp32-elf-gcc').chmod(0o755)
    for path in gcc.glob('xtensa-esp32-elf-*'):
        if path.name != 'xtensa-esp32-elf-gcc':
            (tools / path.name).symlink_to(path)
    env = dict(os.environ, ESP32_PILOT_ROOT=str(root), PYTHONDONTWRITEBYTECODE='1',
        PATH=str(tools) + ':' + str(root / 'alios-build-tools/bin') + ':' + os.environ['PATH'])
    commands = [['aos', 'make', 'native_iperf@esp32bench', '-c', 'config'],
                ['aos', 'make', 'wifi=1', 'IPERF_ENABLED=y', 'VERBOSE=1', 'TOOLCHAIN_PATH=' + str(tools) + '/']]
    code = 0
    for name, command in zip(('configure.log', 'build.log'), commands):
        with (output / name).open('x') as log:
            result = subprocess.run(command, cwd=native, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT)
        code = result.returncode
        if '[ERROR]' in (output / name).read_text() or 'make: ***' in (output / name).read_text():
            code = code or 1
        if name == 'configure.log' and not code and 'AOS_BUILD_APP="native_iperf"' not in (native / '.config').read_text().splitlines():
            code = 1
        if code:
            break
    binary = native / 'out/native_iperf@esp32bench/binary'
    passed = not code and (binary / 'native_iperf@esp32bench.elf').is_file()
    shutil.copytree(app, output / 'application-source')
    shutil.copyfile(__file__, output / 'builder.py')
    shutil.copyfile(wrapper, output / 'compiler-wrapper.sh')
    record = {'status': 'build_pass_not_measured' if passed else 'build_failed', 'returncode': code,
        'os': 'AliOS-Rhino', 'commands': commands, 'board_resets': 0, 'ranking_eligible': False,
        'optimization': {'native': '-Os', 'receiver': '-O2'},
        'original_receiver_sha256': RECEIVER_SHA, 'original_session_sha256': SESSION_SHA}
    if passed:
        for src, dst in (('native_iperf@esp32bench.elf', 'application.elf'),
                         ('native_iperf@esp32bench.bin', 'application.bin'),
                         ('native_iperf@esp32bench.map', 'application.map'), ('link.opts', 'link.opts')):
            shutil.copyfile(binary / src, output / dst)
        for src, dst in (('platform/mcu/esp32/bsp/bootloader.bin', 'bootloader.bin'),
                         ('platform/mcu/esp32/bsp/custom_partitions.bin', 'partitions.bin'),
                         ('.config', 'config'), ('board/esp32bench/sdkconfig.h', 'sdkconfig.h'),
                         ('board/esp32bench/k_config.h', 'k_config.h')):
            shutil.copyfile(native / src, output / dst)
        archive_host_sources(root, output)
    record['files'] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    (output / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k:v for k,v in record.items() if k != 'files'}))
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.home() / 'esp32-pilot')
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(build(args.root, args.workspace, args.output))
