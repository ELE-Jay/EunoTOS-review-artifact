#!/usr/bin/env python3
"""Read boot-policy eFuses without writes and qualify pinned ROM allocator facts."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import shutil
import struct
import sys

from run_esp32_followup import Board, read_raw_capture, sha

ROOT = Path(__file__).resolve().parents[1]
MAC = '34:98:7a:a2:85:28'
FIELDS = ('MAC', 'FLASH_CRYPT_CNT', 'ABS_DONE_0', 'ABS_DONE_1',
          'CONSOLE_DEBUG_DISABLE', 'DISABLE_APP_CPU')
BACKUP = 'private-backups/esp32-nuttx-compact-loader-observer-pairs-b1-v1/original-flash.bin'
DECODER = ('espefuse/__init__.py', 'espefuse/efuse/base_operations.py',
           'espefuse/efuse/esp32/fields.py', 'espefuse/efuse_defs/esp32.yaml')
LAYOUT = {'FLASH_CRYPT_CNT': (0, 0, 20, 7), 'ABS_DONE_0': (0, 6, 4, 1),
          'ABS_DONE_1': (0, 6, 5, 1), 'CONSOLE_DEBUG_DISABLE': (0, 6, 2, 1),
          'DISABLE_APP_CPU': (0, 3, 0, 1)}


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def readonly_command(board, operation, *, backup=None, output=None):
    if operation == 'verify-original':
        return board.base + ['verify_flash', '0', str(backup)]
    if operation == 'boot-policy-summary':
        return [board.python, '-m', 'espefuse', '--chip', 'esp32', '--port', board.port,
                '--baud', '115200', '--before', 'default_reset', 'summary',
                '--format', 'json', '--file', str(output), *FIELDS]
    raise ValueError('Only original-Flash verification and selected eFuse reads are permitted')


def boot_policy(data):
    if set(data) != set(FIELDS) or any(row.get('name') != name or row.get('readable') is not True
                                      for name, row in data.items()):
        raise ValueError('Incomplete or unreadable boot-policy field inventory')
    values = {name: row['value'] for name, row in data.items()}
    if not isinstance(values['MAC'], str) or not re.fullmatch(
            re.escape(MAC)+r' \(CRC 0x[0-9a-f]{1,2} OK\)', values['MAC']):
        raise ValueError('eFuse MAC/CRC does not match the physical board')
    if any(tuple(data[name].get(k) for k in ('block', 'word', 'pos', 'bit_len')) != expected
           for name, expected in LAYOUT.items()):
        raise ValueError('Boot-policy physical field layout differs')
    if type(values['FLASH_CRYPT_CNT']) is not int or not 0 <= values['FLASH_CRYPT_CNT'] < 128 or any(
            type(values[n]) not in (bool, int) or values[n] not in (0, 1) for n in FIELDS[2:]):
        raise ValueError('Unexpected eFuse value types/ranges')
    encrypted = bin(values['FLASH_CRYPT_CNT']).count('1') % 2 == 1
    return {'selected_fields': values, 'flash_encryption_enabled': encrypted,
            'secure_boot_v1_enabled': bool(values['ABS_DONE_0']),
            'secure_boot_v2_enabled': bool(values['ABS_DONE_1']),
            'rom_basic_fallback_disabled': bool(values['CONSOLE_DEBUG_DISABLE']),
            'app_cpu_permanently_disabled': bool(values['DISABLE_APP_CPU']),
            'plain_boot_policy_matches': not encrypted and not values['ABS_DONE_0'] and not values['ABS_DONE_1']}


def collect(root, folder, port):
    if shutil.disk_usage(folder.parent).free < 32 * 1024**2:
        raise ValueError('Insufficient persistent evidence space')
    with (root / 'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        folder.mkdir(exist_ok=False)
        backup = root / BACKUP
        if backup.stat().st_size != 0x400000:
            raise ValueError('Requires the complete retained original Flash image')
        board = Board(root, folder, MAC, port)
        original_sha = sha(backup)
        commands = [readonly_command(board, 'verify-original', backup=backup),
                    readonly_command(board, 'boot-policy-summary', output=folder/'efuses.json'),
                    readonly_command(board, 'verify-original', backup=backup)]
        save(folder/'plan.json', {'board_mac': MAC, 'commands': commands, 'fields': FIELDS,
            'original_flash_sha256': original_sha, 'flash_bytes': backup.stat().st_size,
            'diagnostic_boot_seconds': 8, 'firmware_write_permitted': False, 'efuse_write_permitted': False})
        shutil.copyfile(__file__, folder/'runner.py')
        shutil.copyfile(Path(__file__).with_name('run_esp32_followup.py'), folder/'board-helper.py')
        shutil.copyfile(root/'capture_esp32_uart.py', folder/'capture_esp32_uart.py')
        for name in DECODER:
            target = folder/'decoder'/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root/'esptool-4.8.1'/name, target)
        state = {'mode': 'boot-policy-readback', 'board_mac': MAC, 'status': 'incomplete',
            'started_utc': datetime.now(timezone.utc).isoformat(), 'flash_written': False,
            'efuses_written': False, 'original_flash_unchanged': False, 'new_benchmark_samples': 0}
        try:
            board.identify(folder/'identity-before.log')
            board.command(commands[0], folder/'verify-before.log')
            board.command(commands[1], folder/'summary.log')
            if sha(backup) != original_sha:
                raise ValueError('Retained original Flash file changed')
            board.command(commands[2], folder/'verify-after.log')
            state['original_flash_unchanged'] = True
            captures = folder/'captures'
            captures.mkdir()
            board.capture(captures, 1, 8, monotonic_clock=True)
            state['status'] = 'read_complete_audit_pending'
        finally:
            state['completed_utc'] = datetime.now(timezone.utc).isoformat()
            state['files'] = {p.relative_to(folder).as_posix(): sha(p) for p in folder.rglob('*') if p.is_file()}
            save(folder/'campaign.json', state)


def audit(folder):
    state = json.loads((folder/'campaign.json').read_text())
    plan = json.loads((folder/'plan.json').read_text())
    if state['status'] != 'read_complete_audit_pending' or state['board_mac'] != MAC or \
            state['flash_written'] or state['efuses_written'] or not state['original_flash_unchanged']:
        raise ValueError('Incomplete or writing boot-policy campaign')
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()
              and p not in (folder/'campaign.json', folder/'audit.json')}
    if set(state['files']) != actual or any(sha(folder/n) != h for n, h in state['files'].items()):
        raise ValueError('Boot-policy evidence inventory/bytes differ')
    if plan['board_mac'] != MAC or plan['fields'] != list(FIELDS) or plan['flash_bytes'] != 0x400000 or \
            plan['firmware_write_permitted'] or plan['efuse_write_permitted'] or len(plan['commands']) != 3:
        raise ValueError('Boot-policy protocol changed')
    for i, command in enumerate(plan['commands']):
        expected = ('verify_flash' if i != 1 else 'summary')
        if command.count(expected) != 1 or any(re.match(r'burn_|write_|erase_', part) for part in command):
            raise ValueError('Non-readonly or changed command')
        if i == 1:
            tail = command[command.index('summary')+1:]
            if len(tail) != 4+len(FIELDS) or tail[:3] != ['--format', 'json', '--file'] or \
                    Path(tail[3]).name != 'efuses.json' or tail[4:] != list(FIELDS):
                raise ValueError('Changed boot-policy selection/output')
    identity = (folder/'identity-before.log').read_text()
    if set(re.findall(r'^MAC: ([0-9a-f:]+)$', identity, re.M)) != {MAC} or 'revision v1.1' not in identity:
        raise ValueError('Unexpected physical device')
    for name in ('verify-before.log', 'verify-after.log'):
        text = (folder/name).read_text()
        if set(re.findall(r'^MAC: ([0-9a-f:]+)$', text, re.M)) != {MAC} or \
                'Verifying 0x400000 (4194304) bytes @ 0x00000000' not in text or 'verify OK (digest matched)' not in text:
            raise ValueError('Original complete Flash was not verified before/after the read')
    if 'espefuse.py v4.8.1' not in (folder/'summary.log').read_text():
        raise ValueError('Different eFuse decoder version')
    policy = boot_policy(json.loads((folder/'efuses.json').read_text()))
    lines = [r['line'] for r in read_raw_capture(folder/'captures', 1)]
    resets = [s for s in lines if s.startswith('rst:')]
    if resets != ['rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)'] or \
            sum(bool(re.fullmatch(r'entry 0x[0-9a-f]+', s)) for s in lines) != 1:
        raise ValueError('Original image did not return to the declared cold SPI boot')
    return {'audit': 'pass', 'board_mac': MAC, **policy, 'plan_sha256': sha(folder/'plan.json'),
        'efuses_sha256': sha(folder/'efuses.json'), 'original_flash_sha256': plan['original_flash_sha256'],
        'original_flash_unchanged': True, 'flash_written': False, 'efuses_written': False,
        'diagnostic_cold_boots': 1, 'new_benchmark_samples': 0, 'new_model_calls': 0,
        'whole_lifecycle_peak_allocated_occupancy_bytes': None, 'ranking_eligible': False,
        'scope': 'Physical boot-policy prerequisites only; CPU1 permanent-disable differs from runtime core activation. Fallback permission does not imply fallback execution. Not an exhaustive ROM allocation proof.'}


def instruction_bytes(memory, address, encoded):
    expected = bytes.fromhex(encoded)[::-1]
    if memory(address, len(expected)) != expected:
        raise ValueError('Pinned ROM instruction differs at '+hex(address))


def rom_facts(root, folder):
    from elftools.elf.elffile import ELFFile
    policy = audit(folder)
    saved = json.loads((folder/'audit.json').read_text())
    if policy != saved:
        raise ValueError('Readback audit changed')
    spec = json.loads((root/'registry/esp32_allocated_lifecycle_v1.json').read_text())['rom']
    path = root/spec['directory']/spec['elf']
    if sha(path) != spec['sha256']:
        raise ValueError('Different official ROM ELF')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name('.symtab')
        def symbol(name):
            rows = symbols.get_symbol_by_name(name)
            if not rows or len(rows) != 1:
                raise ValueError('Missing/ambiguous ROM symbol: '+name)
            return rows[0]
        def memory(address, size):
            for section in elf.iter_sections():
                if section['sh_type'] != 'SHT_NOBITS' and section['sh_addr'] <= address and \
                        address+size <= section['sh_addr']+section['sh_size']:
                    return section.data()[address-section['sh_addr']:address-section['sh_addr']+size]
            raise ValueError('ROM proof bytes outside initialized sections')
        # These guards consume the physical bit read above, not a guessed build option.
        expected = {0x40007b8a:'fecb21', 0x40007b8d:'0020c0', 0x40007b90:'0228',
            0x40007b92:'0e6227', 0x40007ba1:'ffff06', 0x40007ba4:'52dda5',
            0x40007bad:'fec221', 0x40007bb0:'0020c0', 0x40007bb3:'0022c2',
            0x40007bb6:'04a022', 0x40007bb9:'10cc20', 0x40007bbc:'011c56',
            0x40007bc7:'fed865', 0x40007bdd:'ffff06', 0x40007b80:'0c0c',
            0x4000701e:'c149', 0x40007622:'c138', 0x40007626:'1c1327',
            0x4000762d:'0003e0', 0x40000718:'000c', 0x40000731:'0409',
            0x4000073d:'06f855', 0x4000bea3:'ff3f31', 0x4000bea6:'0338',
            0x4000bea8:'1338', 0x4000beaf:'0003e0', 0x4000bce7:'ffae81',
            0x4000bcec:'0888', 0x4000bcf0:'f888', 0x4000bcf2:'0008e0'}
        for address, encoded in expected.items():
            instruction_bytes(memory, address, encoded)
        if struct.unpack('<I', memory(0x400076b8,4))[0] != 0x3ff5a018 or \
                struct.unpack('<I', memory(0x4000bba0,4))[0] != symbol('syscall_table_ptr_pro')['st_value']:
            raise ValueError('ROM guard/syscall literal binding differs')
        lo, hi = [symbol(n)['st_value'] for n in ('_bss_table_start', '_bss_table_end')]
        zero = list(struct.iter_unpack('<III', memory(lo,hi-lo)))
        pointer = symbol('syscall_table_ptr_pro')
        rows = [r for r in zero if r[0] <= pointer['st_value'] and pointer['st_value']+4 <= r[1]]
        if rows != [(0x3ffae020,0x3ffae030,0)] or pointer['st_size'] != 4:
            raise ValueError('PRO C-library table does not belong to its reset-zeroed interval')
        callback = symbol('ets_unpack_flash_code')
        if not callback['st_value'] <= 0x4000762d < callback['st_value']+callback['st_size']:
            raise ValueError('Modern loader callback is outside its declared function')
    disabled = policy['rom_basic_fallback_disabled']
    return {'audit':'pass', 'rom_sha256':sha(path), 'physical_policy_sha256':sha(folder/'audit.json'),
        'instruction_guards':{hex(a):v for a,v in expected.items()},
        'console_callsite':{'pc':'0x40007ba4', 'guard_pc':'0x40007b92',
            'physical_bit':'EFUSE_BLK0_RDATA6 bit 2', 'excluded_by_readback':disabled},
        'legacy_loader_callsite':{'pc':'0x40007bc7', 'guard_pc':'0x40007bbc',
            'physical_bit':'EFUSE_BLK0_RDATA6 bit 2', 'excluded_by_readback':disabled},
        'modern_loader_callback':{'pc':'0x4000762d', 'flag_argument_in_main':0,
            'excluded_for_main_call_at':'0x40007b84',
            'scope':'This direct caller passes zero in a12; the callee stores/reloads it before its callback guard. Other possible callers are not certified.'},
        'newlib_table':{'address':pointer['st_value'], 'reset_zero_interval':list(rows[0]),
            'initial_value':0, 'malloc_callback_offset_bytes':4, 'sbrk_callback_offset_bytes':60,
            'scope':'The ROM C-library wrappers delegate through this table. Reset zero does not prove that the pointer remains zero through every later path.'},
        'whole_lifecycle_peak_allocated_occupancy_bytes':None, 'rom_owner_exhaustiveness_verified':False,
        'new_model_calls':0, 'new_benchmark_samples':0,
        'remaining':['Resolve other ROM call sites and temporary ownership before qualifying an exhaustive capacity bound; no claim that allocator symbols alone imply a dedicated ROM heap.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'audit', 'rom-facts'))
    parser.add_argument('--root', type=Path, default=Path.home()/'esp32-pilot')
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--port', default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Collect and audit real evidence on leon')
    if args.mode == 'collect':
        collect(args.root, args.folder, args.port)
    elif args.mode == 'audit':
        value = audit(args.folder)
        save(args.folder/'audit.json', value)
        print(json.dumps(value, indent=2))
    else:
        if args.output is None:
            parser.error('--output required for ROM facts')
        value = rom_facts(ROOT,args.folder)
        save(args.output,value)
        print(json.dumps(value,indent=2))
