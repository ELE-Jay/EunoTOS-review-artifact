#!/usr/bin/env python3
"""Observe behavioral facts around the original Tenon suite; no model or score."""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from import_iotos_subjects import config_text
from tenonos_kvm_reproduce import boot, command, save, sha, sources, utc, original_results

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'iotos-tenon-runtime-oracle-'
PLAN = 'registry/tenonos_runtime_oracle_v2.json'
IRQ_BLOBS = {
    'lib/ukintctlr/ukintctlr.c': '6a5bcde9a4c40c25fed5e4ef681d5bc03b744a27',
    'drivers/ukintctlr/gic/gic-v2.c': '2d4d06b7b3c201750452903ad5d18d7219e5907a',
    'drivers/ukintctlr/gic/gic-v3.c': '31bfa6d9a04b7db9db87d9c3dcb726523d0a097a',
}
CASES = ('rst_task_switch_init', 'rst_task_switch_multi_threaded_init', 'rst_task_preempt_init',
         'rst_semaphore_shuffle_init', 'rst_interrupt_latency_init', 'rst_set_timer_offset_init')
APIS = ('rst_task_create', 'rst_task_yield', 'rst_task_suspend', 'rst_task_resume', 'rst_task_delete',
        'rst_sem_lock', 'rst_sem_unlock', 'rst_isr_install', 'rst_isr_trigger', 'rst_task_sleep',
        'rst_irq_mask', 'rst_irq_unmask')
ALIASES = {
    'src/rst_task_switch.c': {'count1': 'iotos_switch_count1', 'count2': 'iotos_switch_count2'},
    'src/rst_task_switch_multi_threaded.c': {'count': 'iotos_multi_count'},
    'src/rst_task_preempt.c': {'count': 'iotos_preempt_count'},
    'src/rst_semaphore_shuffle.c': {'count': 'iotos_sem_count', 'rst_sem': 'iotos_sem_object'},
    'src/rst_interrupt_latency.c': {'isr_handled': 'iotos_isr_handled'},
    'src/rst_set_timer_offset.c': {'count': 'iotos_timer_count'},
}
HELPERS = ('tenonos_runtime_oracle.py', 'tenonos_runtime_oracle.c', 'tenonos_kvm_reproduce.py',
           'tenonos_memory_observer.py', 'import_iotos_subjects.py')
FIELDS = ('case status a b created entered yields transitions suspends resumes locks unlocks violations '
          'preempt_checks preempt_errors irq_triggers irq_handlers irq_masked irq_context sleeps masks unmasks sem_value owner_deleted').split()


def alias_source(name, raw):
    for original, alias in ALIASES[name].items():
        raw += ('\nextern __typeof__(%s) %s __attribute__((alias("%s")));\n' % (original, alias, original)).encode()
    return raw


def instrument(name, raw):
    if name in ALIASES:
        return alias_source(name, raw)
    if name == 'main.c':
        from tenonos_memory_observer import instrument_main
        return instrument_main(raw)
    if name == 'Makefile.uk':
        # Tenon merges an application's objects before final linking; wrap there.
        return raw + b'\nAPPRHEALSTONEBENCHMARK_SRCS-y += $(APPRHEALSTONEBENCHMARK_BASE)/iotos_runtime.c\n' + \
            ('APPRHEALSTONEBENCHMARK_LDFLAGS-y += ' + ' '.join('-Wl,--wrap=' + n for n in (*CASES, *APIS)) + '\n').encode()
    return raw


def evaluate(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith('IOTOS_RUNTIME case='):
            continue
        parts = [p.split('=') for p in line.split()[1:]]
        if len(parts) != len(FIELDS) or any(len(p) != 2 or not re.fullmatch('-?[0-9]+', p[1]) for p in parts) or \
                {p[0] for p in parts} != set(FIELDS):
            raise ValueError('Malformed or repeated runtime fact fields')
        rows.append({k: int(v) for k, v in parts})
    if [r['case'] for r in rows] != list(range(1, 7)) or \
            re.findall(r'(?m)^IOTOS_RUNTIME END cases=6 workers=(\d+)\r?$', text) != ['62']:
        raise ValueError('Incomplete runtime cases/worker inventory')
    results = []
    for r in rows:
        n = r['case']
        checks = {'native_status': r['status'] == 0, 'workers': r['created'] == r['entered'] == [2, 51, 2, 4, 1, 2][n-1],
                  'no_ownership_or_create_error': r['violations'] == 0, 'no_preemption_error': r['preempt_errors'] == 0,
                  'nonnegative_facts': all(v >= 0 for k, v in r.items() if k != 'sem_value')}
        if n == 1:
            checks.update(completed_loops=r['a'] == 499 and r['b'] == 500, worker_handoffs=r['transitions'] >= 500)
        elif n == 2:
            checks.update(completed_shared_loop=25000 <= r['a'] <= 25050, worker_handoffs=r['transitions'] >= 500)
        elif n == 3:
            checks.update(preempted_endpoint=r['a'] == 499, resumed_target_progress=r['preempt_checks'] >= 499)
        elif n == 4:
            balance = r['locks'] - r['unlocks']
            checks.update(completed_loop=r['a'] == 500, exercised_locks=r['locks'] >= 500,
                terminal_balance=balance in (0, 1) and r['sem_value'] + balance == 1,
                original_retained_owner=r['owner_deleted'] == balance)
        elif n == 5:
            checks.update(handled_flag=r['a'] == 1,
                real_irq_context=r['irq_triggers'] == r['irq_handlers'] == r['irq_context'] == 1 and r['irq_masked'] in (0, 1))
        else:
            checks.update(completed_timer_loop=r['a'] == r['sleeps'] == 500,
                          interrupt_interference=r['masks'] > 0 and r['unmasks'] > 0)
        if n != 5:
            checks['no_stray_test_sgi'] = r['irq_triggers'] == r['irq_handlers'] == r['irq_masked'] == r['irq_context'] == 0
        results.append({'case': n, 'checks': checks, 'admitted': all(checks.values()), 'facts': r})
    return {'admitted': all(r['admitted'] for r in results), 'cases': results,
            'boundary': 'Observed original-loop, handoff, semaphore ownership and SGI facts in a separate observer image; not timing fidelity, reclamation or full RAM',
            'whole_live_ram_peak_bytes': None, 'ranking_eligible': False}


def configs_equal(before, after, app):
    a, da = config_text(before.read_text())
    b, db = config_text(after.read_text())
    diff = {n: [a.get(n), b.get(n)] for n in a.keys() | b.keys() if a.get(n) != b.get(n)}
    if da or db or diff != {'CONFIG_UK_APP': [a['CONFIG_UK_APP'], json.dumps(str(app))]}:
        raise ValueError('Observer changed non-source configuration controls')
    return diff


def linked_irq_preflight(elf, output):
    # Symbol-specific objdump can omit local functions; decode their actual range.
    symbols = {}
    for line in subprocess.check_output(['nm', '-S', '--defined-only', str(elf)]).decode().splitlines():
        fields = line.split()
        if len(fields) == 4:
            symbols[fields[3]] = int(fields[0], 16), int(fields[1], 16)
    start, size = symbols['gicv2_handle_irq']
    assembly = subprocess.check_output(['objdump', '-d', '--start-address='+hex(start),
        '--stop-address='+hex(start+size), str(elf)]).decode()
    output.write_text(assembly)
    targets = []
    for pc, encoded in re.findall(r'(?m)^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', assembly):
        word = int(encoded, 16)
        if word & 0x7c000000 == 0x14000000:
            delta = word & 0x3ffffff
            if delta & (1 << 25): delta -= 1 << 26
            targets.append(int(pc,16) + 4*delta)
    if symbols['__wrap_uk_intctlr_irq_handle'][0] not in targets:
        raise ValueError('GIC bypasses IRQ observer; refuse to boot')


def on_pi(workspace, output):
    from tenonos_memory_observer import retain_link_inputs
    if output.parent != Path('/dev/shm') or not output.name.startswith(PREFIX):
        raise ValueError('Unsafe Pi temporary path')
    identity = sources(workspace, True, 'abi')
    original = workspace / 'apps/app-rtos-benchmark-abi'
    app = output / 'source/app-rtos-benchmark-runtime'
    app.mkdir(parents=True, exist_ok=False)
    names = subprocess.check_output(['git', '-C', str(original), 'ls-files', '-z']).decode().split('\0')[:-1]
    before = {}
    for name in names:
        path = app / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (original / name).read_bytes()
        before[name] = sha(original / name)
        path.write_bytes(instrument(name, raw))
    shutil.copyfile(Path(__file__).with_name('tenonos_runtime_oracle.c'), app / 'iotos_runtime.c')
    for name, blob in IRQ_BLOBS.items():
        raw = (workspace/'tenon-c11'/name).read_bytes()
        if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() != blob:
            raise ValueError('Native IRQ source differs')
        dest = output/'source/native-irq'/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
    save(output / 'source-proof.json', {'identity': identity, 'original_sha256': before,
        'observed_sha256': {n: sha(app / n) for n in [*names, 'iotos_runtime.c']},
        'test_bodies_changed': False, 'wrappers_inside_performance_paths': True})
    build = output / 'build'
    build.mkdir()
    shutil.copyfile(output / 'input.config', build / 'input.defconfig')
    make = ['make', '-C', str(workspace / 'tenon-c11'), 'A=' + str(app), 'O=' + str(build / 'build'),
            'C=' + str(build / '.config'), 'L=' + str(workspace / 'libs'), 'CROSS_COMPILE=', 'COMPILER=gcc',
            'UK_LDFLAGS=-Wl,--wrap=uk_intctlr_irq_handle']
    for name, argv in (('compiler', ['gcc', '--version']), ('configure', [*make, 'UK_DEFCONFIG=' + str(build/'input.defconfig'), 'defconfig']),
                       ('build', ['timeout', '--kill-after=10', '900', *make, '-j2'])):
        if command(build, name, argv)['returncode']:
            raise ValueError('Oracle build failed: ' + name)
    diff = configs_equal(output / 'input.config', build / '.config', app)
    images = list((build/'build').glob('*_qemu-arm64'))
    if len(images) != 1:
        raise ValueError('Expected one observed image')
    retain_link_inputs(images[0], build, workspace/'tenon-c11')
    assembly = subprocess.check_output(['objdump', '-d', '--disassemble=iotos_original_main', str(build/'linked-symbols.elf')]).decode()
    (build/'original-main-disassembly.txt').write_text(assembly)
    if any('<__wrap_' + name + '>' not in assembly for name in CASES):
        raise ValueError('Original main bypasses runtime wrappers; refuse to boot')
    linked_irq_preflight(build/'linked-symbols.elf', build/'gic-disassembly.txt')
    shutil.copyfile(images[0], build/'runtime-image')
    save(output/'config-rebinding.json', diff)
    save(build/'build-result.json', {'application': 'app-rtos-benchmark-runtime', 'image': str(build/'runtime-image'),
        'image_sha256': sha(build/'runtime-image'), 'config_sha256': sha(build/'.config'),
        'source_commits': sources(workspace, True, True), 'c11_timer_fix': True, 'ranking_eligible': False})
    boot(workspace, build, output/'boots', 'kvm')
    observations = []
    for index in (1, 2, 3):
        stdout = (output/('boots/boot%d.stdout' % index)).read_bytes()
        stderr = (output/('boots/boot%d.stderr' % index)).read_bytes()
        step = json.loads((output/('boots/boot%d.json' % index)).read_text())
        original_output = original_results(stdout, stderr, step['returncode'])
        if not original_output['original_output_complete']:
            raise ValueError('Original output incomplete')
        observations.append({'original_output': original_output, 'oracle': evaluate(stdout.decode())})
    if sources(workspace, True, 'abi') != identity:
        raise ValueError('Canonical worktrees changed')
    save(output/'runtime-result.json', {'guests': observations, 'admitted': all(r['oracle']['admitted'] for r in observations),
         'model_calls': 0, 'fresh_guests': 3, 'whole_live_ram_peak_bytes': None, 'ranking_eligible': False})


def collect(output, socket, host, workspace, plan_path=None):
    from run_tenonos_energy import references, host_state, governor
    from tenonos_memory_observer import retain_pi_evidence
    if ROOT != Path('/home/reviewer/esp32-pilot/audit-workspace') or output.exists():
        raise ValueError('Use leon and a new persistent directory')
    output.relative_to(ROOT/'artifacts/reports')
    additional = plan_path is not None
    plan_path = plan_path or ROOT/PLAN
    plan = json.loads(plan_path.read_text())
    reference_path = ROOT/plan['reference_registry']
    reference = json.loads(reference_path.read_text())
    if additional:
        if sha(reference_path) != plan['reference_registry_sha256']:
            raise ValueError('Registered candidate inventory changed')
        variants = {v['id']:v for v in reference['variants']}
        if len(variants) != len(reference['variants']) or set(variants) != set(plan['profiles']):
            raise ValueError('Missing/duplicated additional profile')
        for value in variants.values():
            build = (ROOT/value['build']).resolve()
            build.relative_to(ROOT)
            if sha(build/'.config') != value['config_sha256'] or sha(build/'runtime-image') != value['image_sha256']:
                raise ValueError('Additional profile reference changed')
    else:
        variants = references(reference, ROOT)
    ssh = ['ssh', '-S', socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host]
    initial = host_state(ssh)
    if initial['qemu_running'] or initial['throttled'] != 'throttled=0x0' or initial['serial'] != ['10000000c1b4a936']:
        raise ValueError('Wrong or busy/throttled Pi')
    output.mkdir(parents=True)
    shutil.copyfile(plan_path, output/'protocol.json')
    shutil.copyfile(reference_path, output/'references.json')
    (output/'helpers').mkdir()
    for name in HELPERS:
        shutil.copyfile(ROOT/'tools'/name, output/'helpers'/name)
    campaign = {'status': 'incomplete', 'started_utc': utc(), 'initial_host': initial,
        'protocol_sha256': sha(plan_path), 'helper_sha256': {n: sha(output/'helpers'/n) for n in HELPERS},
        'completed': [], 'model_calls': 0, 'energy_measured': False}
    save(output/'campaign.json', campaign)
    try:
        governor(ssh, 'performance')
        for name in plan['profiles']:
            folder = output/name
            folder.mkdir()
            shutil.copyfile(ROOT/variants[name]['build']/'.config', folder/'input.config')
            remote = '/dev/shm/' + PREFIX + output.name + '-' + name
            subprocess.run([*ssh, shlex.join(['mkdir', '-m', '700', remote])], check=True, timeout=20)
            subprocess.run([*ssh, shlex.join(['mkdir', remote+'/helpers'])], check=True, timeout=20)
            scp = ['scp', '-o', 'ControlPath='+socket, '-o', 'BatchMode=yes']
            subprocess.run([*scp, str(folder/'input.config'), host+':'+remote+'/'], check=True, timeout=30)
            subprocess.run([*scp, *[str(output/'helpers'/n) for n in HELPERS], host+':'+remote+'/helpers/'], check=True, timeout=30)
            before = host_state(ssh)
            argv = ['timeout', '--kill-after=10', '1850', 'python3', remote+'/helpers/tenonos_runtime_oracle.py',
                    'on-pi', '--workspace', str(workspace), '--output', remote]
            with (folder/'remote.log').open('xb') as log:
                step = subprocess.run([*ssh, shlex.join(argv)], stdout=log, stderr=subprocess.STDOUT, timeout=1880)
            retain_pi_evidence(ssh, host, socket, remote, folder, step.returncode, prefix=PREFIX)
            after = host_state(ssh)
            if step.returncode or after['qemu_running'] or after['throttled'] != 'throttled=0x0' or \
                    before['governor'] != 'performance' or after['governor'] != 'performance':
                raise ValueError('Profile infrastructure failed; raw evidence retained')
            result = json.loads((folder/'runtime-result.json').read_text())
            campaign['completed'].append({'profile': name, 'admitted': result['admitted'], 'host_before': before, 'host_after': after})
            save(output/'campaign.json', campaign)
            print(name, 'three fresh guests, admitted=', result['admitted'], flush=True)
        campaign['status'] = 'complete'
    except BaseException as error:
        campaign.update(status='failed', error=repr(error))
        raise
    finally:
        governor(ssh, initial['governor'])
        campaign['host_after_restore'] = host_state(ssh)
        campaign['governor_restored'] = campaign['host_after_restore']['governor'] == initial['governor']
        save(output/'campaign.json', campaign)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('collect', 'on-pi'))
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--workspace', type=Path, default=Path('/home/pi/tenonos-benchmark-v1'))
    p.add_argument('--socket', default='/tmp/iotos-pi-energy.sock')
    p.add_argument('--host', default='pi@192.168.31.76')
    p.add_argument('--plan', type=Path, help='Frozen additional-profile plan; default retains the original protocol')
    a = p.parse_args()
    if a.action == 'on-pi':
        on_pi(a.workspace.resolve(), a.output.resolve())
    else:
        with (Path.home()/'esp32-pilot/.tenonos-paper-campaign.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collect(a.output.resolve(), a.socket, a.host, a.workspace, a.plan.resolve() if a.plan else None)
