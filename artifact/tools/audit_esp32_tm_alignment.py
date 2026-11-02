#!/usr/bin/env python3
"""Replay queue/compiler controls without admitting them into old-board scores."""
import hashlib
import json
import math
import statistics
from datetime import datetime
from pathlib import Path

from elftools.elf.elffile import ELFFile

from audit_esp32_tm_basic import audit
from audit_esp32_tm_reboots import require_self_check

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'artifacts/reports/esp32-tm-alignment-v1'
MAC = '34:98:7a:a2:85:28'
OLD_MAC = '84:1f:e8:8f:55:dc'
MARKER = 'Thread-Metric queue family=riot-official-esp32-copy-queue capacity=4 payload_bytes=16 ownership=copy'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(folder, name, digest):
    path = (folder / name).resolve()
    if not path.is_relative_to(folder.resolve()) or sha(path) != digest:
        raise ValueError('Changed or escaping evidence file: ' + name)
    return path


def raw_capture(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    raw = path.with_suffix('.bin').read_bytes()
    offset, previous, previous_utc = 0, -1, None
    for row in rows:
        size, elapsed = row['raw_bytes'], row['elapsed_s']
        if not isinstance(size, int) or size <= 0 or not math.isfinite(elapsed) or elapsed < previous:
            raise ValueError('Invalid raw size or monotonic time')
        chunk = raw[offset:offset + size]
        if len(chunk) != size or hashlib.sha256(chunk).hexdigest() != row['raw_sha256'] or \
                chunk.decode('utf-8', errors='replace').rstrip('\r\n') != row['line']:
            raise ValueError('Raw UART and JSONL differ')
        utc = datetime.fromisoformat(row['utc'])
        if utc.tzinfo is None or (previous_utc is not None and
                abs((utc - previous_utc).total_seconds() - (elapsed - previous)) > .1):
            raise ValueError('UART UTC and monotonic time disagree')
        offset, previous, previous_utc = offset + size, elapsed, utc
    if not rows or offset != len(raw):
        raise ValueError('Empty capture or unaccounted UART bytes')
    return rows


def riot_control(folder, expected_success):
    build = json.loads((folder / 'build.json').read_text())
    capture_folder = folder / ('board-' + MAC.replace(':', ''))
    capture = json.loads((capture_folder / 'capture.json').read_text())
    if build['status'] != 'PASS_BUILD_ONLY' or build['build_returncode'] or \
            capture['build_sha256'] != sha(folder / 'build.json') or capture['images'] != build['image_sha256']:
        raise ValueError('Build/capture identity mismatch')
    for name, digest in build['image_sha256'].items():
        checked(folder, name, digest)
    checked(folder, 'build.log', build['build_log_sha256'])
    for name, digest in build['source_sha256'].items():
        if name.startswith('downloads/tm-alignment-v1/'):
            checked(EVIDENCE, name.removeprefix('downloads/tm-alignment-v1/'), digest)
        else:
            checked(EVIDENCE / 'source-evidence', name, digest)
    with (folder / 'application.elf').open('rb') as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name('.symtab')
        if table is None or elf['e_machine'] != 'EM_XTENSA':
            raise ValueError('No native ESP32 ELF symbols')
        names = {symbol.name for symbol in table.iter_symbols() if symbol['st_shndx'] != 'SHN_UNDEF'}
    if not {'xQueueGenericCreate', 'xQueueGenericSend', 'xQueueGenericReceive'} <= names or \
            any(n.startswith('tm_legacy_mailbox_') for n in names):
        raise ValueError('Official copy queue not selected')
    for name, digest in capture['files'].items():
        checked(capture_folder, name, digest)
    if capture['board_mac'] != MAC or capture['old_energy_board_mac'] != OLD_MAC or \
            capture['same_board_as_old_energy'] or capture['energy_measured'] or capture['ranking_eligible'] or \
            not capture['original_flash_restored']:
        raise ValueError('Board segregation or restoration violated')
    for name in ('identity-before.log', 'identity-before-restore.log'):
        if ('MAC: ' + MAC) not in (capture_folder / name).read_text():
            raise ValueError('Wrong connected board')
    restore = (capture_folder / 'restore-verify.log').read_text()
    if 'Verifying 0x400000 (4194304) bytes @ 0x00000000' not in restore or 'verify OK (digest matched)' not in restore:
        raise ValueError('No full original Flash restoration verification')
    runs, starts, ends = [], [], []
    for path in sorted(capture_folder.glob('reset[1-3].jsonl')):
        rows = raw_capture(path)
        starts.append(datetime.fromisoformat(rows[0]['utc']))
        ends.append(datetime.fromisoformat(rows[-1]['utc']))
        if expected_success:
            require_self_check(rows, 'queue')
            if sum(r['line'] == MARKER for r in rows) != 1:
                raise ValueError('No native queue ownership contract')
            resets = [r for r in rows if r['line'].startswith('rst:0x')]
            if len(resets) != 1 or resets[0]['elapsed_s'] > 2:
                raise ValueError('Not an independent clean boot')
            runs.append(audit(path, 'RIOT', 'message_processing'))
    if expected_success:
        if capture['status'] != 'PASS_NEW_BOARD_CONTROL_ONLY' or len(runs) != 3 or \
                any(b <= a for a, b in zip(ends, starts[1:])) or runs != capture['runs']:
            raise ValueError('Incomplete or overlapping repeated control')
        totals = [r['original_window_totals'][0] for r in runs]
        return {'status': 'PASS_COPY_QUEUE_CONTROL', 'independent_resets': 3,
                'original_counts_per_30s': totals, 'median': statistics.median(totals),
                'ranking_eligible': False, 'energy_measured': False}
    if capture['status'] != 'FAILED' or runs or capture['runs'] or len(starts) != 1:
        raise ValueError('Failed candidate misrepresented')
    lines = [r['line'] for r in raw_capture(capture_folder / 'reset1.jsonl')]
    if 'Single core mode' not in lines or any('Thread-Metric RIOT ESP32 boot' in line for line in lines):
        raise ValueError('GCC13 startup failure evidence changed')
    return {'status': 'BUILD_PASS_STARTUP_INCOMPLETE', 'attempted_resets': 1,
            'last_uart_line': lines[-1], 'root_cause': 'not yet established', 'ranking_eligible': False}


def replay():
    results = {label: riot_control(EVIDENCE / ('riot-' + label) / 'message_processing', label == 'gcc12')
               for label in ('gcc12', 'gcc13')}
    probes = {}
    for name in ('rhino-compiler-probe', 'rhino-compiler-probe-formatfix'):
        folder = EVIDENCE / name
        data = json.loads((folder / 'probe.json').read_text())
        counts = {label: 0 for label in ('gcc5', 'gcc13')}
        for row in data['runs']:
            checked(folder, row['log'], row['log_sha256'])
            if row['object']:
                checked(folder, row['object'], row['object_sha256'])
            counts[row['compiler']] += row['returncode'] == 0
        if counts != data['passed_by_compiler'] or data['board_boots'] or data['full_sdk_linked'] or data['ranking_eligible']:
            raise ValueError('Compile probe not a bootable OS qualification')
        if name.endswith('formatfix'):
            checked(folder, 'format.patch', data['format_patch_sha256'])
        probes[name] = counts
    return {'audit': 'pass', 'board_mac': MAC, 'old_energy_board_mac': OLD_MAC,
            'board_replacement': 'User confirmed same-model replacement; old board failed.',
            'riot': results, 'rhino_compile_only': probes, 'new_ranked_cells': 0,
            'new_energy_cells': 0, 'old_snapshot_modified': False}


if __name__ == '__main__':
    result = replay()
    (EVIDENCE / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
