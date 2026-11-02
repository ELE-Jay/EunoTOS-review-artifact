#!/usr/bin/env python3
"""Collect RIOT/Rhino with the existing original IPv4 UDP load and audit rules."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import shlex
from statistics import median

from run_esp32_followup import Board, sha
from run_esp32_common_tcp import save
from run_esp32_native_network_b1 import MAC, peer_link, QUEUE_PROFILE, NEIGHBOR_PROFILE, BSSID, DEVICE
from run_esp32_common_udp_receiver import PLAN, SOURCES as OLD_SOURCES, proofs as old_proofs, read_capture, controlled_queue_capture, controlled_queue_restoration
from build_esp32_common_tcp_ports import original_receiver_parts, HOST_SOURCES, RECEIVER_SHA, SESSION_SHA

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / 'artifacts/reports'
SOURCES = {**OLD_SOURCES, 'RIOT': 'esp32-common-udp-receiver-riot-v8',
           'AliOS-Rhino': 'esp32-common-udp-receiver-rhino-v6'}
PROFILES = {'FreeRTOS':'idf','Zephyr':'zephyr','NuttX':'nuttx','RIOT':'riot-common','AliOS-Rhino':'rhino-common'}


def proof(system):
    if system in OLD_SOURCES:
        return old_proofs()[system]
    from elftools.elf.elffile import ELFFile
    from audit_esp32_resources import audit_elf_image
    import build_esp32_riot_common_udp as riot
    import build_esp32_rhino_common_udp as rhino
    folder = REPORTS / SOURCES[system]
    metadata = json.loads((folder / 'build.json').read_text())
    if metadata['status'] != 'build_pass_not_measured' or metadata['returncode'] or \
            metadata['os'] != system or metadata.get('startup_diagnostic_only', False) or \
            metadata['original_receiver_sha256'] != RECEIVER_SHA or metadata['original_session_sha256'] != SESSION_SHA:
        raise ValueError('Wrong original receiver candidate')
    for name, digest in metadata['files'].items():
        path = folder / name
        if not path.resolve().is_relative_to(folder.resolve()) or sha(path) != digest:
            raise ValueError('Native source/image binding changed: ' + name)
    app = folder / 'application-source'
    for name, text in original_receiver_parts().items():
        if (app / name).read_text() != text:
            raise ValueError('Original receiver/session body differs')
    binding = riot if system == 'RIOT' else rhino
    if (app / 'port.c').read_text() != binding.adapter_source():
        raise ValueError('Native socket/clock binding differs')
    for name, digest in HOST_SOURCES.items():
        if sha(folder / 'host-source' / name) != digest:
            raise ValueError('Original host sender/reporter source differs')
    if system == 'RIOT':
        if (app/'main.c').read_bytes()!=(ROOT/'firmware/bsp/esp32/zperf_udp_receiver_riot/main.c').read_bytes():
            raise ValueError('RIOT native entry/actual clock check differs')
        if (folder / 'native-sock-posix-count.c').read_text() != riot.posix_sock_source((folder / 'native-sock-original.c').read_text()):
            raise ValueError('Native POSIX readiness repair differs')
        config = (folder / 'config.h').read_text()
        if '#define MODULE_ESP_WIFI_AP 1' not in config or \
                '-DCONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ_240=1' not in (app / 'Makefile').read_text() or \
                '-fno-tree-loop-distribute-patterns' not in (folder / 'receiver-cc.sh').read_text():
            raise ValueError('Native RIOT AP/clock/IRAM compatibility profile differs')
    else:
        if (app/'native_iperf.c').read_text()!=rhino.main_source():
            raise ValueError('Rhino native entry/clock initialization differs')
        units=[shlex.split(s) for s in (folder/'build.log').read_text().splitlines()
            if ' -c ' in s and s.rstrip().endswith(' kernel/cli/cli.c')]
        if len(units)!=1 or '-DCLI_CONFIG_STACK_SIZE=8192' not in units[0]:
            raise ValueError('Actual native receiver CLI stack compilation differs')
        config = (folder / 'sdkconfig.h').read_text().splitlines()
        if not {'#define CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ 240', '#define CONFIG_FREERTOS_UNICORE 1',
                '#define CONFIG_FREERTOS_HZ 100'} <= set(config):
            raise ValueError('Native Rhino clock/core/tick configuration differs')
    with (folder / 'application.elf').open('rb') as stream:
        elf = ELFFile(stream)
        compile_units = []
        compiled_posix_repair = False
        receiver_source = (Path(metadata['command'][2]) / 'port.c' if system == 'RIOT'
                           else Path('app/example/native_iperf/port.c'))
        for unit in elf.get_dwarf_info().iter_CUs():
            attrs = unit.get_top_DIE().attributes
            name = attrs.get('DW_AT_name')
            if name and Path(name.value.decode()) == receiver_source:
                compile_units.append(attrs['DW_AT_producer'].value.decode())
            if name and system == 'RIOT' and Path(name.value.decode()) == receiver_source.parent.parent / 'posix-lwip-sock.c':
                compiled_posix_repair = True
        options = re.findall(r'(?:^|\s)(-O(?:[0-3sg]|fast))(?=\s|$)', compile_units[0]) if len(compile_units) == 1 else []
        if len(compile_units) != 1 or '13.2.0' not in compile_units[0] or not options or options[-1] != '-O2':
            raise ValueError('Actual receiver translation unit is not GCC13 -O2')
        if system == 'RIOT' and not compiled_posix_repair:
            raise ValueError('Native POSIX readiness repair was not actually compiled')
    audit_elf_image(folder / 'application.elf', folder / 'application.bin')
    return {'build': SOURCES[system], 'build_json_sha256': sha(folder / 'build.json'),
        'compiler_unit': compile_units[0], 'original_parts': {n:sha(app/n) for n in original_receiver_parts()},
        'images': {n:sha(folder/n) for n in ('application.elf', 'application.bin', 'bootloader.bin', 'partitions.bin')}}


def protocol(systems,source_warmup=False,native_peer_identity=False):
    if not systems or len(set(systems)) != len(systems) or not set(systems) <= set(SOURCES):
        raise ValueError('Select each native OS once')
    spec=json.loads((ROOT/'registry/esp32_common_udp_fixed_peer_v1.json').read_text())
    if spec['source_queue_profile']!=QUEUE_PROFILE or spec['source_neighbor_profile']!=NEIGHBOR_PROFILE or \
            spec['original_receiver_sha256']!=RECEIVER_SHA or spec['original_session_sha256']!=SESSION_SHA or \
            spec['sender_datagrams']!=PLAN['expected_sender_datagrams'] or spec['packet_bytes']!=PLAN['packet_bytes']:
        raise ValueError('Frozen fixed-peer protocol differs from the common original workload')
    result={**PLAN, 'scope': 'Five-system mainboard extension; native OS/network implementation is part of the SUT',
        'host_path_protocol':spec,
        'schedule': [{'round': r+1, 'system': s} for r in range(5)
                     for s in systems[r % len(systems):] + systems[:r % len(systems)]],
        'host_source_queue_profile': QUEUE_PROFILE, 'host_source_path_snapshots': True,
        'host_neighbor_profile': NEIGHBOR_PROFILE,
        'legacy_network_reuse': 'Retain old dynamic-ARP sessions as controls; collect all five systems again under the same fixed peer mapping',
        'receive_timebase': '10-ms original statistic resolution; RIOT native tickless and Rhino native 100-Hz tick'}
    if source_warmup:
        warm=json.loads((ROOT/'registry/esp32_common_udp_warmup_v1.json').read_text())
        if warm['parent']!=spec['id'] or warm['preconditioning']!={
                'icmp_count':1000,'icmp_payload_bytes':1024,'interval_seconds':.01,'settle_seconds':1}:
            raise ValueError('Frozen shared preconditioning differs')
        result.update(host_preconditioning=warm,legacy_network_reuse=warm['reuse'])
    if native_peer_identity:
        identity=json.loads((ROOT/'registry/esp32_common_udp_peer_identity_v1.json').read_text())
        if not source_warmup or identity['parent']!=warm['id'] or identity['associated_bssid']!=BSSID or \
                identity['ipv4_peer_macs']!={s:MAC if s=='Zephyr' else BSSID for s in SOURCES}:
            raise ValueError('Native IPv4 peer amendment differs')
        result['native_peer_identity']=identity
    return result


def diagnostic_plan(systems):
    if len(systems)!=1:
        raise ValueError('Warmup diagnosis uses one original full-load session')
    plan=protocol(systems)
    return {**plan,'schedule':plan['schedule'][:1],'diagnostic_only':True,
        'source_preconditioning':{'icmp_count':1000,'icmp_payload_bytes':1024,'interval_seconds':.01},
        'scope':'One original full UDP load after fixed pre-session ICMP traffic; diagnose link readiness, never a mainboard score'}


def source_warmup_capture(folder):
    actions=json.loads((folder/'udp_rx/actions.json').read_text())
    rows=[(i,a['host_udp_source_warmup']) for i,a in enumerate(actions) if 'host_udp_source_warmup' in a]
    pinned=[i for i,a in enumerate(actions) if 'host_udp_neighbor' in a and not a['host_udp_neighbor']['restored']]
    sender=[i for i,a in enumerate(actions) if 'host_command' in a]
    if len(rows)!=1 or len(pinned)!=1 or len(sender)!=1 or not pinned[0]<rows[0][0]<sender[0]:
        raise ValueError('Shared preconditioning does not precede the original workload')
    row=rows[0][1]
    if row['traffic']['arguments']!=['ping','-n','-I',DEVICE,'-i','0.01','-c','1000','-s','1024','-W','2','192.168.4.1'] or \
            row['traffic']['returncode'] or any(row[k]['returncode'] or BSSID not in row[k]['output'].lower()
                for k in ('before_link','after_link')):
        raise ValueError('Shared preconditioning traffic or actual peer differs')
    return {'profile':'esp32-common-udp-fixed-peer-warmup-v1','completed':True}


def fixed_neighbor_capture(folder):
    actions=json.loads((folder/'udp_rx/actions.json').read_text())
    rows=[(i,a['host_udp_neighbor']) for i,a in enumerate(actions) if 'host_udp_neighbor' in a]
    hosts=[i for i,a in enumerate(actions) if 'host_command' in a]
    returns=[i for i,a in enumerate(actions) if 'host_returncode' in a]
    if len(rows)!=2 or len(hosts)!=1 or len(returns)!=1 or not rows[0][0]<hosts[0]<returns[0]<rows[1][0]:
        raise ValueError('Fixed peer does not bracket the full original host session')
    address=MAC if folder.name=='Zephyr' else BSSID
    expected=['ip','neigh','replace','192.168.4.1','lladdr',address,'nud','permanent','dev',DEVICE]
    for (i,row),restored in zip(rows,(False,True)):
        wanted=['ip','neigh','del','192.168.4.1','dev',DEVICE] if restored else expected
        if row['profile']!=NEIGHBOR_PROFILE or row['restored']!=restored or row['action']['arguments']!=wanted or \
                row['action']['returncode'] or row['before']['returncode'] or row['after']['returncode']:
            raise ValueError('Fixed peer mutation/query differs')
    if rows[0][1]['after']['output'].split()!=['192.168.4.1','lladdr',address,'PERMANENT'] or \
            'PERMANENT' in rows[1][1]['after']['output']:
        raise ValueError('Fixed peer was not applied or removed')
    monitor=[a for a in actions if 'host_neighbor_returncode' in a]
    if len(monitor)!=1 or monitor[0]['host_neighbor_returncode']!=-2:
        raise ValueError('Read-only peer monitor did not remain active until completion')
    if folder.name=='AliOS-Rhino':
        lines=[json.loads(s)['line'] for s in (folder/'udp_rx/uart.jsonl').read_text().splitlines()]
        if lines.count('COMMON_NETWORK_RECEIVER_STACK bytes=8192')!=1:
            raise ValueError('Native receiver stack lacks its runtime witness')
    return {'profile':NEIGHBOR_PROFILE,'restored':True}


def compatible_prefix_plan(previous,current,count):
    if previous==current:return True
    amended=dict(current);identity=amended.pop('native_peer_identity',None)
    return bool(identity and previous==amended and all(
        identity['ipv4_peer_macs'][p['system']]==BSSID for p in current['schedule'][:count]))


def resume_prefix(parent,plan,frozen,seen=()):
    from audit_esp32_followup import envelope,verified
    state=envelope(parent,allow_incomplete=True)
    if parent.resolve() in seen or len(seen)>16:
        raise ValueError('Cyclic or excessive acquisition ancestry')
    count=state['completed_resets']
    if state['mode']!='unified-native-original-udp-receiver' or state['status']!='incomplete' or \
            state['board_mac']!=MAC or not state['original_flash_restored'] or \
            not 0<count<len(plan['schedule']) or not compatible_prefix_plan(json.loads((parent/'plan.json').read_text()),plan,count) or \
            json.loads((parent/'proofs.json').read_text())!=frozen:
        raise ValueError('Partial parent is not the same restored original cohort')
    if state.get('parent'):
        if Path(state['parent']).name!=state['parent']:
            raise ValueError('Acquisition parent escapes the report directory')
        upstream=parent.parent/state['parent']
        _,prior=resume_prefix(upstream,plan,frozen,(*seen,parent.resolve()))
        receipt=json.loads((parent/'reuse-parent.json').read_text())
        if state.get('reused_complete_resets')!=len(prior) or receipt['campaign_sha256']!=sha(upstream/'campaign.json') or \
                receipt['captures']!=[p.as_posix() for p,_ in prior]:
            raise ValueError('Nested verified reset receipt differs')
        for relative,_ in prior:
            for p in (upstream/relative).rglob('*'):
                if p.is_file() and sha(p)!=sha(parent/relative/p.relative_to(upstream/relative)):
                    raise ValueError('Copied ancestor reset changed')
    controlled_queue_restoration(parent)
    if not json.loads((parent/'host-after.json').read_text()).get('source_neighbor_restored'):
        raise ValueError('Partial parent fixed peer was not restored')
    result=[]
    for item in plan['schedule'][:count]:
        system=item['system'];relative=Path('runs')/('round%d'%item['round'])/system
        folder=parent/relative
        if any(sha(parent/'builds'/system/n)!=v for n,v in frozen[system]['images'].items()):
            raise ValueError('Parent measured image differs from its current frozen proof')
        verified(folder,parent/'builds'/system,MAC)
        value=read_capture(folder,system,host_buffer=PLAN['host_send_buffer_bytes'])
        controlled_queue_capture(folder);fixed_neighbor_capture(folder)
        if plan.get('host_preconditioning'): source_warmup_capture(folder)
        if value!=json.loads((folder/'result.json').read_text()):
            raise ValueError('Retained reset does not independently replay')
        result.append((relative,value))
    return state,result


def acquisition_attempts(output):
    total=0;seen=set()
    while output is not None:
        if output.resolve() in seen:
            raise ValueError('Cyclic acquisition ancestry')
        seen.add(output.resolve())
        state=json.loads((output/'campaign.json').read_text())
        total+=len(list((output/'runs').glob('round*/*/udp_rx')))-state.get('reused_complete_resets',0)
        output=output.parent/state['parent'] if state.get('parent') else None
    return total


def collect(root, output, restore_uuid, port, systems, parent=None, diagnostic_warmup=False, source_warmup=False,
            native_peer_identity=False):
    import run_esp32_iperf_original as native
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace') or not os.environ.get('BENCHMARK_SSH_PASSWORD'):
        raise ValueError('Collect only on leon with its private sudo environment')
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.environ['LC_ALL'] = 'C'
    if diagnostic_warmup and (parent or source_warmup):
        raise ValueError('A changed pre-session diagnosis cannot inherit mainboard observations')
    frozen={s:proof(s) for s in systems}
    plan=diagnostic_plan(systems) if diagnostic_warmup else protocol(systems,source_warmup,native_peer_identity)
    parent_state,reused=resume_prefix(parent,plan,frozen) if parent else ({},[])
    with (root / 'tm-sync-power.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        save(output / 'plan.json', plan)
        save(output / 'host-path-protocol.json', plan['host_path_protocol'])
        save(output / 'proofs.json', frozen)
        if reused:
            save(output/'reuse-parent.json',{'parent':parent.name,'campaign_sha256':sha(parent/'campaign.json'),
                'captures':[p.as_posix() for p,_ in reused],
                'reason':'Retain only independently replayed complete original resets; incomplete/rejected attempts remain in the restored parent'})
            for relative,value in reused:
                shutil.copytree(parent/relative,output/relative)
        for system in systems:
            build = output / 'builds' / system
            build.mkdir(parents=True)
            for name in frozen[system]['images']:
                shutil.copyfile(REPORTS / SOURCES[system] / name, build / name)
        shutil.copyfile(REPORTS / 'esp32-network-common-zephyr-v2/iperf-host', output / 'iperf-host')
        (output / 'iperf-host').chmod(0o755)
        for source, name in ((Path(__file__), 'runner.py'), (Path(native.__file__), 'native-capture.py'),
                             (Path(Board.backup.__code__.co_filename), 'board-helper.py'),
                             (Path(peer_link.__code__.co_filename), 'network-guard.py')):
            shutil.copyfile(source, output / name)
        state = {'status': 'incomplete', 'mode': 'unified-native-original-udp-receiver', 'systems': systems,
            'board_mac': MAC, 'completed_resets': len(reused), 'original_flash_restored': False,
            'started_utc': parent_state.get('started_utc',datetime.now(timezone.utc).isoformat()), 'energy_measured': False,
            'reused_complete_resets':len(reused),
            'old_cohort_modified': False, 'external_independent_replication': False}
        if reused:
            state.update(parent=parent.name,resumed_utc=datetime.now(timezone.utc).isoformat())
        if diagnostic_warmup:
            state.update(diagnostic_only=True,ranking_eligible=False)
        board = Board(root, output, MAC, port)
        try:
            board.backup()
            try:
                with peer_link(output, native.run, 'Common', restore_uuid, source_queue_profile=QUEUE_PROFILE) as connection:
                    native.CONNECTION, native.SERIAL_PORT = connection, port
                    for item in plan['schedule'][len(reused):]:
                        system = item['system']
                        folder = output / 'runs' / ('round%d' % item['round']) / system
                        folder.mkdir(parents=True)
                        installed = board.flash(folder, output / 'builds' / system)
                        native.trial(folder / 'udp_rx', 'udp_rx', 60, PROFILES[system], str(output / 'iperf-host'),
                            controlled_peer=True, board_command='zperf_udp_receiver',
                            completion_token='ORIGINAL_ZPERF_RX CLOSED status=0', host_csv=True, host_compat=True,
                            fixed_udp_bytes=PLAN['requested_bytes'], fixed_udp_send_buffer=PLAN['host_send_buffer_bytes'],
                            host_udp_path_diagnostics=True, source_queue_state=output / 'wifi-restore-state.json',
                            fixed_peer_neighbor=True,diagnostic_warmup=diagnostic_warmup,source_warmup=source_warmup,
                            fixed_peer_mac=plan['native_peer_identity']['ipv4_peer_macs'][system]
                                if native_peer_identity and system=='Zephyr' else None)
                        board.verify(installed, folder / 'verify-after.log')
                        value = read_capture(folder, system, host_buffer=PLAN['host_send_buffer_bytes'])
                        controlled_queue_capture(folder)
                        fixed_neighbor_capture(folder)
                        if source_warmup: source_warmup_capture(folder)
                        save(folder / 'result.json', value)
                        state['completed_resets'] += 1
                        save(output / 'progress.json', {**item, **state, 'result': value})
                        print('UNIFIED_NATIVE_UDP', item['round'], system, value['receiver_bits_s'], flush=True)
                state['status'] = 'collection_complete_audit_pending'
            finally:
                board.restore()
                state['original_flash_restored'] = True
        except BaseException as error:
            state['error'] = repr(error)
            raise
        finally:
            state['completed_utc'] = datetime.now(timezone.utc).isoformat()
            state['files'] = {p.relative_to(output).as_posix():sha(p) for p in output.rglob('*') if p.is_file()}
            save(output / 'campaign.json', state)


def audit(output,allow_diagnostic=False):
    from audit_esp32_followup import envelope, verified
    state = envelope(output)
    systems = state['systems']
    diagnostic=state.get('diagnostic_only',False)
    if diagnostic!=allow_diagnostic:
        raise ValueError('Diagnoses and complete mainboard cohorts require separate audit modes')
    recorded_plan=json.loads((output/'plan.json').read_text())
    conditioned=bool(recorded_plan.get('host_preconditioning'))
    plan = diagnostic_plan(systems) if diagnostic else protocol(systems,conditioned,bool(recorded_plan.get('native_peer_identity')))
    frozen = {s:proof(s) for s in systems}
    if state['mode'] != 'unified-native-original-udp-receiver' or state['board_mac'] != MAC or \
            state['completed_resets'] != len(plan['schedule']) or not state['original_flash_restored'] or \
            json.loads((output / 'plan.json').read_text()) != plan or \
            json.loads((output / 'proofs.json').read_text()) != frozen:
        raise ValueError('Native common receiver campaign is incomplete or changed')
    if json.loads((output/'host-path-protocol.json').read_text())!=plan['host_path_protocol']:
        raise ValueError('Fixed host-path protocol binding differs')
    controlled_queue_restoration(output)
    if state.get('parent'):
        parent=output.parent/state['parent'];previous,reused=resume_prefix(parent,plan,frozen)
        reuse=json.loads((output/'reuse-parent.json').read_text())
        if state.get('reused_complete_resets')!=len(reused) or reuse['campaign_sha256']!=sha(parent/'campaign.json') or \
                reuse['captures']!=[p.as_posix() for p,_ in reused]:
            raise ValueError('Verified parent-prefix receipt differs')
        for relative,value in reused:
            for source in (parent/relative).rglob('*'):
                if source.is_file() and sha(source)!=sha(output/relative/source.relative_to(parent/relative)):
                    raise ValueError('Retained source reset changed after copying')
    if not json.loads((output/'host-after.json').read_text()).get('source_neighbor_restored') or \
            json.loads((output/'wifi-restore-state.json').read_text()).get('source_neighbor_restore_pending') is not False:
        raise ValueError('Fixed peer recovery state is incomplete')
    reference_peer = REPORTS / 'esp32-network-common-zephyr-v2/iperf-host'
    if sha(output / 'iperf-host') != sha(reference_peer):
        raise ValueError('Original host executable differs')
    rows, previous = {s:[] for s in systems}, None
    for item in plan['schedule']:
        system = item['system']
        build, folder = output / 'builds' / system, output / 'runs' / ('round%d' % item['round']) / system
        if any(sha(build/n) != v for n,v in frozen[system]['images'].items()):
            raise ValueError('Measured image differs from native source build')
        verified(folder, build, MAC)
        value = read_capture(folder, system, host_buffer=PLAN['host_send_buffer_bytes'])
        controlled_queue_capture(folder)
        fixed_neighbor_capture(folder)
        if conditioned: source_warmup_capture(folder)
        if diagnostic:
            actions=json.loads((folder/'udp_rx/actions.json').read_text())
            warm=[a['diagnostic_udp_source_warmup'] for a in actions if 'diagnostic_udp_source_warmup' in a]
            if len(warm)!=1 or warm[0]['traffic']['arguments']!=['ping','-n','-I',DEVICE,'-i','0.01','-c','1000','-s','1024','-W','2','192.168.4.1']:
                raise ValueError('Source preconditioning diagnosis changed')
        if value != json.loads((folder / 'result.json').read_text()):
            raise ValueError('Saved result differs from raw original session')
        start, end = (datetime.fromisoformat(value[k]) for k in ('start_utc', 'end_utc'))
        if start >= end or previous is not None and start <= previous:
            raise ValueError('Independent reset chronology differs')
        previous = end
        rows[system].append(value)
    attempts=acquisition_attempts(output)
    return {'audit': 'pass', 'board_mac': MAC, 'independent_resets': state['completed_resets'],
        **({'diagnostic_only':True,'ranking_eligible':False,'qualified_mainboard_resets':0} if diagnostic else {}),
        'acquisition_attempts':attempts,'rejected_or_incomplete_attempts':attempts-state['completed_resets'],
        'reused_complete_resets':state.get('reused_complete_resets',0),
        'original_flash_restored': True, 'management_wifi_restored': True, 'source_queue_restored': True,
        'cells': [{'os':s, 'runs':r, 'independent_resets':len(r),
                   'median_mbit_s':median(v['receiver_bits_s']/1e6 for v in r)} for s,r in rows.items()]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'audit', 'proof','audit-warmup-diagnostic'))
    parser.add_argument('--root', type=Path, default=Path.home() / 'esp32-pilot')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--restore-uuid')
    parser.add_argument('--resume-parent',type=Path)
    parser.add_argument('--diagnostic-warmup',action='store_true')
    parser.add_argument('--source-warmup',action='store_true')
    parser.add_argument('--native-peer-identity',action='store_true')
    parser.add_argument('--port', default='/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0')
    parser.add_argument('--systems', nargs='+', choices=tuple(SOURCES), default=['AliOS-Rhino','RIOT'])
    args = parser.parse_args()
    if args.mode == 'collect':
        collect(args.root, args.output, args.restore_uuid, args.port, args.systems,args.resume_parent,args.diagnostic_warmup,args.source_warmup,args.native_peer_identity)
    elif args.mode in ('audit','audit-warmup-diagnostic'):
        result = audit(args.output,allow_diagnostic=args.mode=='audit-warmup-diagnostic')
        save(args.output / 'audit.json', result)
        print(json.dumps({k:v for k,v in result.items() if k != 'cells'}))
    else:
        print(json.dumps({s:proof(s) for s in args.systems}, indent=2))
