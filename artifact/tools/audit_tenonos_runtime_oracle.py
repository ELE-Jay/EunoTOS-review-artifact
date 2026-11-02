#!/usr/bin/env python3
"""Replay source-bound original-suite facts and linked wrapper paths on leon."""
import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from audit_tenonos_tasks import require, configuration
from audit_tenonos_policy_sequence import guest_checks
from tenonos_kvm_reproduce import sha, original_results
from tenonos_runtime_oracle import CASES, APIS, ALIASES, IRQ_BLOBS, instrument, evaluate


def independent_admission(rows):
    require([r['case'] for r in rows] == list(range(1, 7)), 'Case order differs')
    valid = []
    for n, r in enumerate(rows, 1):
        ok = r['status'] == r['violations'] == r['preempt_errors'] == 0 and \
            r['created'] == r['entered'] == (2, 51, 2, 4, 1, 2)[n-1] and \
            all(v >= 0 for k, v in r.items() if k != 'sem_value')
        if n == 1: ok &= r['a'] == 499 and r['b'] == 500 and r['transitions'] >= 500
        if n == 2: ok &= r['a'] in range(25000, 25051) and r['transitions'] >= 500
        if n == 3: ok &= r['a'] == 499 and r['preempt_checks'] >= 499
        if n == 4:
            remaining = r['locks'] - r['unlocks']
            ok &= r['a'] == 500 and r['locks'] >= 500 and remaining in (0, 1) and \
                r['sem_value'] == 1 - remaining and r['owner_deleted'] == remaining
        if n == 5: ok &= r['a'] == r['irq_triggers'] == r['irq_handlers'] == r['irq_context'] == 1 and r['irq_masked'] in (0, 1)
        if n == 6: ok &= r['a'] == r['sleeps'] == 500 and min(r['masks'], r['unmasks']) > 0
        if n != 5: ok &= r['irq_triggers'] == r['irq_handlers'] == r['irq_masked'] == r['irq_context'] == 0
        valid.append(bool(ok))
    return valid


def linked_paths(elf_path, image_path):
    with elf_path.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf['e_machine'] == 'EM_AARCH64', 'Wrong architecture')
        table = elf.get_section_by_name('.symtab')
        def symbol(name):
            values = table.get_symbol_by_name(name)
            require(values is not None and len(values) == 1, 'Missing/ambiguous symbol: ' + name)
            return values[0]
        def body(name):
            s = symbol(name)
            section = elf.get_section(s['st_shndx'])
            offset = s['st_value'] - section['sh_addr']
            return s['st_value'], section.data()[offset:offset+s['st_size']]
        def calls(name):
            pc, data = body(name)
            targets = []
            for i in range(0, len(data)-3, 4):
                word = int.from_bytes(data[i:i+4], 'little')
                if word & 0x7c000000 == 0x14000000:
                    delta = word & 0x3ffffff
                    if delta & (1 << 25): delta -= 1 << 26
                    targets.append(pc + i + 4 * delta)
            return targets
        flat = image_path.read_bytes()
        anchor, raw = body('iotos_original_main')
        offset = flat.find(raw)
        require(len(raw) >= 32 and offset >= 0 and flat.find(raw, offset+1) == -1, 'ELF main not uniquely bound to measured image')
        base = anchor - offset
        names = ('iotos_original_main', 'main', 'interrupt_entry', 'rst_irq_dispatch', 'gicv2_handle_irq',
                 '__wrap_uk_intctlr_irq_handle', 'uk_intctlr_irq_handle') + CASES + tuple('__wrap_' + n for n in (*CASES, *APIS))
        for name in names:
            address, data = body(name)
            require(len(data) > 0 and address >= base and flat[address-base:address-base+len(data)] == data,
                    'Linked function differs from guest image: ' + name)
        for name in CASES:
            require(symbol('__wrap_' + name)['st_value'] in calls('iotos_original_main') and
                    symbol(name)['st_value'] in calls('__wrap_' + name), 'Original case does not traverse its observer')
            for api in ('rst_task_create', 'rst_task_suspend'):
                require(symbol('__wrap_' + api)['st_value'] in calls(name), 'Original task API bypasses observer: ' + name)
        require(symbol('__wrap_uk_intctlr_irq_handle')['st_value'] in calls('gicv2_handle_irq') and
                symbol('uk_intctlr_irq_handle')['st_value'] in calls('__wrap_uk_intctlr_irq_handle'), 'GIC IRQ path bypasses observer')
        aliases = {}
        for mapping in ALIASES.values():
            for original, name in mapping.items():
                alias = symbol(name)
                expected = 8 if name == 'iotos_sem_object' else 1 if name == 'iotos_isr_handled' else 4
                require(alias['st_size'] == expected and alias['st_info']['type'] == 'STT_OBJECT' and
                        alias['st_info']['bind'] == 'STB_GLOBAL' and
                        any(s['st_value'] == alias['st_value'] and s['st_size'] == expected
                            for s in table.get_symbol_by_name(original) or []), 'Alias does not expose its original storage')
                aliases[name] = {'address': alias['st_value'], 'bytes': expected}
        return {'original_cases_wrapped': 6, 'api_wrappers': len(APIS), 'aliases': aliases,
                'measured_image_code_matches_elf': True}


def audit(root, folder, plan_path=None):
    plan = json.loads((folder/'protocol.json').read_text())
    state = json.loads((folder/'campaign.json').read_text())
    refs = json.loads((folder/'references.json').read_text())
    require(plan == json.loads((plan_path or root/'registry/tenonos_runtime_oracle_v2.json').read_text()) and
        sha(folder/'protocol.json') == state['protocol_sha256'] and state['status'] == 'complete' and
        state['governor_restored'] and state['initial_host']['serial'] == ['10000000c1b4a936'] and
        state['initial_host']['governor'] == state['host_after_restore']['governor'] and
        state['model_calls'] == 0 and not state['energy_measured'], 'Campaign identity/envelope differs')
    require(sha(folder/'references.json') == sha(root/plan['reference_registry']) and
            [r['profile'] for r in state['completed']] == plan['profiles'], 'Reference/profile coverage differs')
    if plan_path:
        require(sha(folder/'references.json') == plan['reference_registry_sha256'], 'Additional-profile inventory differs')
    for name, digest in state['helper_sha256'].items():
        require(sha(folder/'helpers'/name) == digest, 'Frozen helper changed')
    manifest = json.loads((root/'artifacts/dependency_stage/generative_subjects/TenonOS-audit/rtos-benchmark/manifest.json').read_text())
    require(manifest['commit'] == '0b71b8e722acfab4733eb99b07b67fbe8472c31d' and not manifest['truncated'], 'Public source manifest differs')
    originals = {r['path']: r for r in manifest['files']}
    profiles = []
    for completed in state['completed']:
        name = completed['profile']
        p = folder/name
        ref = next(r for r in refs['variants'] if r['id'] == name)
        require(sha(p/'input.config') == ref['config_sha256'], 'Input configuration changed')
        require(sha(root/ref['build']/'runtime-image') == ref['image_sha256'] and
                sha(root/ref['build']/'.config') == ref['config_sha256'], 'Retained reference identity changed')
        transfer = json.loads((p/'runtime-transfer-check.json').read_text())
        require(transfer['all_equal'] and transfer['remote_returncode'] == 0, 'Transfer incomplete')
        for rel, digest in transfer['files'].items():
            path = (p/rel).resolve()
            path.relative_to(p.resolve())
            require(sha(path) == digest, 'Transferred evidence changed: ' + rel)
        proof = json.loads((p/'source-proof.json').read_text())
        app = p/'source/app-rtos-benchmark-runtime'
        patches = proof['identity']['rtos_adapter_patch']['files']
        require(set(proof['original_sha256']) == set(originals) and
            patches == {'adapter/os/tenonos/rst_isr.c': '738792173125d862712cf17d40640a3f1c3488a761d2ac321cfe537982d1a707',
                        'adapter/os/tenonos/rst_task.c': '71c41a94f0ccdf644b0afb0f266afe072e3048df42816bf2a8893dcece304bed'},
            'Original source/adapter coverage differs')
        for rel, original in originals.items():
            raw = (app/rel).read_bytes()
            require(sha(app/rel) == proof['observed_sha256'][rel], 'Compiled source changed')
            if rel in ALIASES:
                suffix = instrument(rel, b'')
                require(raw.endswith(suffix), 'Alias declaration differs')
                raw = raw[:-len(suffix)]
            elif rel == 'main.c':
                raw = raw.replace(b'int iotos_original_main(', b'int main(')
            elif rel == 'Makefile.uk':
                suffix = instrument(rel, b'')
                require(raw.endswith(suffix), 'Source registration differs')
                raw = raw[:-len(suffix)]
            require(hashlib.sha256(raw).hexdigest() == proof['original_sha256'][rel], 'Original body changed')
            if rel in patches:
                require(hashlib.sha256(raw).hexdigest() == patches[rel], 'ABI adapter changed')
            else:
                require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == original['sha'], 'Public Git blob differs')
        require(sha(app/'iotos_runtime.c') == sha(folder/'helpers/tenonos_runtime_oracle.c'), 'Oracle C changed')
        for rel, blob in IRQ_BLOBS.items():
            raw = (p/'source/native-irq'/rel).read_bytes()
            require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == blob, 'Native public IRQ source differs')
        build = p/'build'
        b = json.loads((build/'build-result.json').read_text())
        require(sha(build/'runtime-image') == b['image_sha256'] and sha(build/'.config') == b['config_sha256'], 'Measured image/config changed')
        a, c = configuration(p/'input.config'), configuration(build/'.config')
        difference = {n: [a.get(n), c.get(n)] for n in a.keys() | c.keys() if a.get(n) != c.get(n)}
        require(set(difference) == {'UK_APP'} and {'CONFIG_'+k:v for k,v in difference.items()} ==
                json.loads((p/'config-rebinding.json').read_text()), 'Native controls differ')
        require(sha(build/'compiler.stdout') == sha(root/ref['build']/'compiler.stdout'), 'Compiler differs')
        for step_name in ('compiler', 'configure', 'build'):
            step = json.loads((build/(step_name+'.json')).read_text())
            require(step['returncode'] == 0 and step['state'] == 'finished' and
                sha(build/(step_name+'.stdout')) == step['stdout_sha256'] and sha(build/(step_name+'.stderr')) == step['stderr_sha256'], 'Build logs differ')
        paths = linked_paths(build/'linked-symbols.elf', build/'runtime-image')
        outcomes, complete = guest_checks(p/'boots', b['image_sha256'])
        require(complete and len(outcomes) == 3, 'Original output incomplete')
        result = json.loads((p/'runtime-result.json').read_text())
        oracles = []
        for index in (1, 2, 3):
            text = (p/('boots/boot%d.stdout' % index)).read_text()
            primary = evaluate(text)
            secondary = []
            for line in text.splitlines():
                if line.startswith('IOTOS_RUNTIME case='):
                    secondary.append({k: int(v) for k, v in (item.split('=', 1) for item in line.split()[1:])})
            require([r['facts'] for r in primary['cases']] == secondary and
                    [r['admitted'] for r in primary['cases']] == independent_admission(secondary), 'Independent fact judge differs')
            step = json.loads((p/('boots/boot%d.json' % index)).read_text())
            original_output = original_results((p/('boots/boot%d.stdout' % index)).read_bytes(),
                (p/('boots/boot%d.stderr' % index)).read_bytes(), step['returncode'])
            require(original_output['original_output_complete'] and
                result['guests'][index-1] == {'original_output': original_output, 'oracle': primary}, 'Recorded verdict differs')
            args = step['argv']
            require(all(args[args.index(k)+1] == v for k,v in (('-accel','kvm'),('-smp','1'),('-m','128M'),('-nic','none'))), 'Guest envelope differs')
            oracles.append(primary)
        require(result['admitted'] == all(r['admitted'] for r in oracles) == completed['admitted'], 'Profile verdict differs')
        for key in ('host_before', 'host_after'):
            h = completed[key]
            require(h['serial'] == state['initial_host']['serial'] and h['governor'] == 'performance' and
                    h['throttled'] == 'throttled=0x0' and not h['qemu_running'], 'Host envelope differs')
        profiles.append({'profile': name, 'admitted': completed['admitted'], 'image_sha256': b['image_sha256'], 'linked_paths': paths, 'guests': oracles})
    return {'audit': 'pass', 'profiles': profiles, 'fresh_guests': 3*len(profiles), 'new_model_calls': 0,
        'original_flash_or_old_campaigns_modified': False, 'full_live_ram_peak_bytes': None, 'ranking_eligible': False,
        'campaign_sha256': sha(folder/'campaign.json'),
        'scope': 'Behavioral admission of the separate original-body observer images; historical model-task counts and timing/energy qualifications unchanged'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--plan', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if root != Path('/home/reviewer/esp32-pilot/audit-workspace'):
        parser.error('Evidence audit runs on leon')
    result = audit(root, args.folder.resolve(), args.plan.resolve() if args.plan else None)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print('Runtime source/image/fact audit passed')
