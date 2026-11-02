#!/usr/bin/env python3
"""Pair an unchanged NuttX RAM observer with the verified IDF boot observer."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import shutil
import signal
import sys

from audit_esp32_followup import envelope, independent_captures, verified
from audit_esp32_bootloader_ram import build as boot_proof
from audit_esp32_resources import physical_intervals, union_bytes
from measure_esp32_bootloader_ram import observations
from run_esp32_followup import Board, read_raw_capture, sha
from run_esp32_nuttx_message_lifetimes import MAC, build_proof, fields, read_run

ROOT = Path(__file__).resolve().parents[1]
APPLICATION = 'artifacts/reports/esp32-nuttx-compact-startup-v1'
BASELINE = 'artifacts/reports/esp32-nuttx-compact-startup-b1-v1'
BOOT = 'artifacts/reports/esp32-boot-handoff-build-v1/paired-bootloader'
IMAGES = ('application.elf', 'application.bin', 'bootloader.bin', 'partitions.bin')


def specification(root):
    app, boot = root / APPLICATION, root / BOOT
    proof = build_proof(app)
    loader = boot_proof(boot)
    if not proof.get('compact_observer') or not proof.get('application_startup_stack_coverage'):
        raise ValueError('Requires the audited compact startup image')
    return {'id': 'esp32-nuttx-observed-loader-v1', 'board_mac': MAC,
        'resets': 5, 'seconds': 110, 'validation_resets': 1,
        'application': APPLICATION, 'baseline': BASELINE, 'bootloader': BOOT,
        'application_manifest_sha256': sha(app / 'build.json'),
        'bootloader_manifest_sha256': sha(boot / 'build.json'),
        'application_unchanged': True, 'os_configuration_unchanged': True,
        'bootloader_intervention': 'Replace only the prebuilt IDF 5.1-dev loader with the verified IDF 5.2.5 boot observer used by the FreeRTOS RAM diagnostic; retain the NuttX partition table.',
        'images': {name: sha((boot if name == 'bootloader.bin' else app) / name) for name in IMAGES},
        'original_bootloader_sha256': sha(app / 'bootloader.bin'),
        'bootloader_static_bytes': loader['bootloader_static']['static_sram_bytes'],
        'application_static_bytes': proof['static_sram_bytes'],
        'scope': 'Second-stage observer entry through console-deinit; unchanged NuttX native entry through third original message report. Transfer stack reservation is bounded separately; first-stage ROM and hardware ownership are not inferred.',
        'energy_measured': False, 'ranking_eligible': False, 'whole_lifecycle_complete': False}


def boot_before_application(lines):
    boot = observations(lines)
    first = [i for i, line in enumerate(lines) if line.startswith('TM_N_RAM event=')]
    reports = [i for i, line in enumerate(lines) if line.startswith('BOOT_RAM phase=')]
    if not first or len(reports) != 2 or max(reports) >= min(first):
        raise ValueError('Boot observations do not precede the native heap ledger')
    return boot


def result(root, folder, index, proof, validation=False):
    lines = [row['line'] for row in read_raw_capture(folder, index)]
    return {'boot_stages': boot_before_application(lines),
        'application': read_run(folder, index, proof, validation=validation)}


def collect(root, output, port):
    plan = specification(ROOT)
    if shutil.disk_usage(output.parent).free < 128 * 1024**2:
        raise ValueError('Insufficient persistent evidence space')
    with (root / 'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(exist_ok=False)
        build, captures, validation = [output / n for n in ('build', 'captures', 'validation')]
        for path in (build, captures, validation):
            path.mkdir()
        for name in IMAGES:
            origin = ROOT / (BOOT if name == 'bootloader.bin' else APPLICATION)
            shutil.copyfile(origin / name, build / name)
        shutil.copyfile(__file__, output / 'runner.py')
        shutil.copyfile(Path(__file__).with_name('run_esp32_followup.py'), output / 'board-helper.py')
        shutil.copyfile(root / 'capture_esp32_uart.py', output / 'capture_esp32_uart.py')
        (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
        state = {'mode': 'nuttx-observed-loader', 'status': 'incomplete',
            'board_mac': MAC, 'independent_resets': 0,
            'started_utc': datetime.now(timezone.utc).isoformat(),
            'original_flash_restored': False, 'old_cohort_modified': False,
            'energy_measured': False, 'external_independent_replication': False}
        proof = build_proof(ROOT / APPLICATION)
        board = Board(root, output, MAC, port)
        try:
            board.backup()
            try:
                pairs = board.flash(captures, build)
                board.capture(validation, 1, 25, stop='NUTTX_MESSAGE_RAM VALIDATION END',
                    send='iotosbench --validate-observer')
                board.verify(pairs, validation / 'verify-run1.log')
                checked = result(ROOT, validation, 1, proof, validation=True)
                (validation / 'result1.json').write_text(json.dumps(checked, indent=2) + '\n')
                for index in range(1, plan['resets'] + 1):
                    board.capture(captures, index, plan['seconds'],
                        stop='NUTTX_MESSAGE_RAM END', send='iotosbench')
                    board.verify(pairs, captures / ('verify-run%d.log' % index))
                    measured = result(ROOT, captures, index, proof)
                    (captures / ('result%d.json' % index)).write_text(json.dumps(measured, indent=2) + '\n')
                    state['independent_resets'] += 1
                    print('NUTTX LOADER', index, measured['application']['events'], flush=True)
                board.verify(pairs, captures / 'verify-after.log')
                state['status'] = 'collection_complete_audit_pending'
            finally:
                board.restore()
                state['original_flash_restored'] = True
        finally:
            state['completed_utc'] = datetime.now(timezone.utc).isoformat()
            state['files'] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
            (output / 'campaign.json').write_text(json.dumps(state, indent=2) + '\n')


def audit(root, folder):
    from audit_esp32_allocated_reservations import nuttx_bookkeeping_history
    state = envelope(folder)
    plan = json.loads((folder / 'plan.json').read_text())
    if plan != specification(root) or state['mode'] != 'nuttx-observed-loader' or \
            state['board_mac'] != MAC or state['independent_resets'] != plan['resets']:
        raise ValueError('Incomplete or changed paired-loader campaign')
    baseline_state = envelope(root / BASELINE)
    if baseline_state['board_mac'] != MAC or baseline_state['independent_resets'] != 5:
        raise ValueError('Historical comparison is not the same board/reset cohort')
    for name, digest in plan['images'].items():
        if sha(folder / 'build' / name) != digest:
            raise ValueError('Installed pair differs from frozen sources')
    proof = build_proof(root / APPLICATION)
    verified(folder / 'captures', folder / 'build', MAC)
    verified(folder / 'validation', folder / 'build', MAC, logs=('verify-run1.log',))
    independent_captures(folder / 'validation', indices=(1,))
    independent_captures(folder / 'captures', indices=range(1, 6))
    checked = result(root, folder / 'validation', 1, proof, validation=True)
    if json.loads(json.dumps(checked)) != json.loads((folder / 'validation/result1.json').read_text()):
        raise ValueError('Separate validation replay changed')
    runs = []
    for index in range(1, 6):
        verified(folder / 'captures', folder / 'build', MAC, logs=('verify-run%d.log' % index,))
        value = result(root, folder / 'captures', index, proof)
        if json.loads(json.dumps(value)) != json.loads((folder / 'captures' / ('result%d.json' % index)).read_text()):
            raise ValueError('Stored native result differs from raw replay')
        lines = [row['line'] for row in read_raw_capture(folder / 'captures', index)]
        events = [fields(s) for s in lines if s.startswith('TM_N_RAM event=')]
        identities = [fields(s) for s in lines if s.startswith('TM_N_ID at=')]
        regions = [(r['start'], r['end'] - r['start']) for r in (
            fields(s, 2) for s in lines if s.startswith('RAM_EVENTS region '))]
        heaps = [fields(s, 2)['heap'] for s in lines if s.startswith('TM_N_RAM layout ')]
        if len(heaps) != 1:
            raise ValueError('Missing unique native heap control')
        history = nuttx_bookkeeping_history(events, identities, regions, heaps[0], proof['static_sram_bytes'])
        baseline = read_run(root / BASELINE / 'captures', index, proof)
        old_lines = [row['line'] for row in read_raw_capture(root / BASELINE / 'captures', index)]
        for prefix in ('TM_N_RAM event=', 'TM_N_ID at='):
            if [fields(s) for s in lines if s.startswith(prefix)] != [
                    fields(s) for s in old_lines if s.startswith(prefix)]:
                raise ValueError('Loader intervention changed a native allocation transition')
        current = value['application']
        if any(current[k] != baseline[k] for k in ('events', 'native_heap_peak_bytes',
                'native_heap_final_bytes', 'native_heap_regions', 'allocation_identity_replay')):
            raise ValueError('Loader intervention changed native allocated ownership')
        runs.append({'reset': index, 'boot_stages': value['boot_stages'],
            'raw_sha256': sha(folder / 'captures' / ('reset%d.raw' % index)),
            'native_events': current['events'], 'native_regions': [list(r) for r in regions],
            'software_peak_bytes': max(r['accounted_bytes'] for r in history),
            'native_heap_peak_bytes': current['native_heap_peak_bytes'],
            'original_counts': current['original_message']['original_window_totals'],
            'startup': current['application_startup_stack']})
    loader = boot_proof(root / BOOT)
    static = [p for section in loader['bootloader_static']['ram_sections']
        for p in physical_intervals(int(section['address'], 16), section['bytes'])]
    # A reservation envelope is deliberately not an observed simultaneous peak.
    reserved = physical_intervals(0x3ffe0440, 0x3ffe3f20 - 0x3ffe0440)
    app = [p for section in proof['ram_sections']
        for p in physical_intervals(int(section['address'], 16), section['bytes'])]
    return {'audit': 'pass', 'board_mac': MAC, 'independent_resets': 5,
        'separate_validation_resets': 1, 'application_binary_unchanged': True,
        'native_ownership_matches_baseline': True, 'original_flash_restored': True,
        'plan_sha256': sha(folder / 'plan.json'), 'runs': runs,
        'bootloader_static_bytes': union_bytes(static),
        'inherited_boot_stack_reservation_bytes': union_bytes(reserved),
        'loader_application_stack_reservation_envelope_bytes_not_observed_peak': union_bytes(static + reserved + app),
        'whole_lifecycle_peak_allocated_occupancy_bytes': None, 'ranking_eligible': False,
        'scope': plan['scope'],
        'remaining': ['Source-bound loading/release ownership intervals, first-stage ROM/cache/RTC scope, and matched observer controls for the controlled cohort.'],
        'energy_reused': False, 'new_model_calls': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'audit'))
    parser.add_argument('--root', type=Path, default=Path.home() / 'esp32-pilot')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Experimental evidence stays on leon')
    if args.mode == 'collect':
        def interrupted(signum, frame):
            signal.alarm(0)
            raise RuntimeError('Interrupted; restore original full Flash')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(1200)
        try:
            collect(args.root, args.output, args.port)
        finally:
            signal.alarm(0)
    else:
        value = audit(ROOT, args.output)
        with (args.output / 'audit.json').open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        print(json.dumps({k: value[k] for k in ('audit', 'independent_resets',
            'native_ownership_matches_baseline', 'original_flash_restored')}))
