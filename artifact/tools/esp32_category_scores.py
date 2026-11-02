#!/usr/bin/env python3
"""Reference-normalized category views of the measured B1 configurations."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from statistics import median

SYSTEMS = ('FreeRTOS', 'Zephyr', 'NuttX')
NATIVE_SYSTEMS = ('RIOT', 'AliOS-Rhino')
CASES = ('preemptive_scheduling', 'message_processing', 'synchronization_processing',
         'interrupt_processing', 'interrupt_preemption_processing')
ROOT = Path(__file__).resolve().parents[1]


def summarize(kernel, energy, network, ram, native=None):
    if set(kernel) != set(CASES):
        raise ValueError('The fixed five-case kernel set is required; missing cases cannot be reweighted')
    for values in [*kernel.values(), energy, network, ram]:
        if set(values) != set(SYSTEMS) or any(not math.isfinite(v) or v <= 0 for v in values.values()):
            raise ValueError('Three complete positive finite configuration values required')
    categories = []
    definitions = (
        ('kernel', '内核性能', 'Kernel performance', 'geometric mean of five original count ratios', False,
         {os: 100 * math.exp(sum(math.log(kernel[k][os] / kernel[k]['FreeRTOS']) for k in CASES) / len(CASES))
          for os in SYSTEMS}, None),
        ('network', '通信吞吐', 'Communication', 'Mbit/s, fixed offered UDP sequence', False,
         {os: 100 * network[os] / network['FreeRTOS'] for os in SYSTEMS}, network),
        ('energy', '任务能效', 'Energy efficiency', 'microjoule/original message completion', False,
         {os: 100 * energy['FreeRTOS'] / energy[os] for os in SYSTEMS}, energy),
        ('ram', '峰值分配 RAM*', 'Allocated RAM*', 'bytes, fixed observer image', True,
         {os: 100 * ram['FreeRTOS'] / ram[os] for os in SYSTEMS}, ram))
    for key, zh, en, unit, observer, scores, values in definitions:
        categories.append({'id': key, 'label': zh, 'english_label': en, 'unit': unit,
            'observer_profile_only': observer,
            'cells': [{'os': os, 'score': scores[os], 'value': values[os] if values else None} for os in SYSTEMS]})
    return {'schema': 'esp32-b1-category-indices-v2', 'baseline': 'FreeRTOS', 'reference_score': 100,
            'board_mac': '34:98:7a:a2:85:28', 'systems': list(SYSTEMS), 'kernel_cases': list(CASES),
            'all_systems': list(SYSTEMS + NATIVE_SYSTEMS) if native else list(SYSTEMS),
            'native_profiles': native or [],
            'categories': categories, 'kernel_values': kernel, 'composite_score': None,
            'category_weights': None, 'new_measurements': 0,
            'excluded': [{'os': 'RIOT', 'reason': 'Native compiler/timer profile differs from the controlled cohort'},
                         {'os': 'AliOS-Rhino', 'reason': 'Native compiler/SDK profile differs from the controlled cohort'}],
            'interpretation': 'Higher is better within each declared category; 100 is the fixed FreeRTOS reference. '
                'RAM indices compare F1/Z1/N1 observer images, not uninstrumented OS memory. '
                'Network is fixed-load receiver throughput, not maximum capacity. Energy is the paired '
                'message-workload board-input observation, without external meter calibration. '
                'No cross-category weighted total; throughput and energy per completion share work-rate information.'}


def native_observations(alignment, suite, energy, networks):
    if energy['board_mac'] != '34:98:7a:a2:85:28' or energy['audit'] != 'pass':
        raise ValueError('Native energy belongs to a different board or failed audit')
    counts = {(c['os'], c['case']): c['median'] for c in suite['cells']}
    for c in alignment:
        counts[c['os'], 'message_processing'] = c['result']['median']
    energy_cells = {c['os']: c for c in energy['cells']}
    net = {c['system']: c for c in networks}
    rows = []
    for os in NATIVE_SYSTEMS:
        system = 'Rhino' if os == 'AliOS-Rhino' else os
        group = net[system]
        if group['board_mac'] != energy['board_mac'] or group['audit'] != 'pass':
            raise ValueError('Native network board or audit differs')
        case = 'payload1024-interval1000' if os == 'RIOT' else 'udp_rx'
        cell = group['cases'][case]
        values = ([r['final_published_original_row']['bandwidth_bytes_per_second'] for r in cell['runs']]
                  if os == 'RIOT' else cell['values'])
        kernels = {key: counts[os, key] for key in CASES}
        e = energy_cells[os]
        energy_value = e['medians']['energy_per_original_count_uj']
        if cell['independent_resets'] != 3 or e['independent_resets'] != 3 or len(values) != 3 or \
                any(not math.isfinite(v) or v <= 0 for v in list(kernels.values()) + values + [energy_value]):
            raise ValueError('Incomplete native observations; cannot fill or normalize missing data')
        rows.append({'os': os, 'profile': next(c['profile'] for c in alignment if c['os'] == os),
            'kernel_counts_30s': kernels, 'energy_uj_per_original_message_completion': energy_value,
            'network': {'test': 'GNRC IPv6 UDP echo' if os == 'RIOT' else 'lwIP iPerf UDP RX',
                        'case': case, 'median': median(values), 'unit': 'B/s' if os == 'RIOT' else 'Mbit/s'},
            'peak_allocated_occupancy_bytes': None, 'ram_status': 'not_closed',
            'ranking_eligible': False, 'score': None, 'independent_resets_per_cell': 3})
    return rows


def native_energy():
    from audit_esp32_b1_native_energy import audit, equal_observation
    folder = ROOT / 'artifacts/reports/esp32-native-message_processing-energy-b1-v1'
    result = audit(folder)
    if not equal_observation(result, json.loads((folder / 'audit.json').read_text())):
        raise ValueError('Native energy differs from signed packet/source replay')
    return result


def native_from_evidence():
    from audit_esp32_native_suite_builds import audit_campaign
    from audit_esp32_rhino_gcc13 import audit as rhino_audit
    from audit_esp32_riot_startup import audit as riot_audit
    from run_esp32_native_network_b1 import audit as network_audit
    reports = ROOT / 'artifacts/reports'
    alignment = []
    for os, name, build, check in (
            ('RIOT', 'esp32-riot-gcc13-legacy-b1-v1', 'esp32-riot-gcc13-legacy-v1', riot_audit),
            ('AliOS-Rhino', 'esp32-rhino-gcc13-b1-v1', 'esp32-rhino-gcc13-legacy-v1', rhino_audit)):
        result = check(reports / name, reports / build, False) if os == 'RIOT' else check(reports / name, reports / build)
        if result != json.loads((reports / name / 'audit.json').read_text()):
            raise ValueError('Native original-message replay differs')
        alignment.append({'os': os, 'profile': ('240 MHz / 单核 / 原生 tickless / GCC13；GCC12 兼容头文件，C 库按镜像核对'
            if os == 'RIOT' else '240 MHz / 单核 / 100 Hz / GCC13；旧版 SDK libc'), 'result': result})
    cells = []
    for name in ('esp32-native-task-suite-b1-v1', 'esp32-native-irq-suite-b1-v1'):
        result = audit_campaign(reports / name)
        if result != json.loads((reports / name / 'audit.json').read_text()):
            raise ValueError('Native original-suite replay differs')
        cells.extend(result['cells'])
    networks = []
    for name in ('esp32-native-network-riot-b1-v2', 'esp32-native-network-rhino-b1-v1'):
        result = network_audit(reports / name)
        if result != json.loads((reports / name / 'audit.json').read_text()):
            raise ValueError('Native original-network replay differs')
        networks.append(result)
    return native_observations(alignment, {'cells': cells}, native_energy(), networks)


def from_audit(result):
    value = result['reset_level_values']
    kernel = {key: {os: median(value[key][os]) for os in SYSTEMS} for key in CASES}
    energy = {os: median(value['energy_' + os]['uj_per_original_count']) for os in SYSTEMS}
    network = {r['system']: r['median_mbit_s'] for r in value['common_original_udp_receiver']}
    ram = {r['os']: r['peak_allocated_occupancy_bytes'] for r in value['normal_boot_observer_capacity']['rows']}
    return summarize(kernel, energy, network, ram, native_from_evidence())


def from_view(view):
    groups = {g['case']: g for g in view['b1_kernel']['groups'] if g['case'] in CASES}
    groups['message_processing'] = view['b1_message']
    if any(g['board_mac'] != '34:98:7a:a2:85:28' for g in groups.values()):
        raise ValueError('Category indices cannot pool boards')
    kernel = {key: {c['os']: c['median'] for c in group['cells']} for key, group in groups.items()}
    energy = {c['os']: c['medians']['energy_per_original_count_uj'] for c in view['b1_energy']['cells']}
    network = {c['system']: c['median_mbit_s'] for c in view['common_original_udp_receiver']['cells']}
    ram = {c['os']: c['peak_allocated_occupancy_bytes'] for c in view['allocated_capacity']['rows']}
    native = native_observations(view['native_alignment'], view['native_suite'], native_energy(), view['native_network_groups'])
    return summarize(kernel, energy, network, ram, native)


def svg(value):
    colors = ('#16786c', '#b75b25', '#526cc1')
    width, height, left, top, bottom, right = 1080, 540, 65, 52, 302, 1050
    ymax = 330
    scale = lambda v: bottom - v / ymax * (bottom - top)
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 540" role="img" '
             'aria-label="B1 五个已测 OS：三系统分项指数与 RIOT、Rhino 原生配置实测"><style>text{font:14px system-ui,sans-serif;fill:#263437}</style>',
             '<rect width="1080" height="540" fill="white"/>',
             '<defs><pattern id="ram-lines" width="6" height="6" patternUnits="userSpaceOnUse"><path d="M-1,1L1,-1M0,6L6,0M5,7L7,5" stroke="white" stroke-width="1.5"/></pattern></defs>']
    for tick in range(0, 301, 50):
        y = scale(tick)
        parts.append('<path d="M%d %.2fH%d" stroke="#dfe5e4"/><text x="%d" y="%.2f" text-anchor="end">%d</text>' %
                     (left, y, right, left - 10, y + 5, tick))
    parts.append('<path d="M%d %.2fH%d" stroke="#6d787b" stroke-dasharray="5 4"/>' % (left, scale(100), right))
    for i, os in enumerate(SYSTEMS):
        parts.append('<rect x="%d" y="13" width="14" height="14" fill="%s"/><text x="%d" y="26">%s</text>' %
                     (left + i * 145, colors[i], left + i * 145 + 22, os))
    parts.append('<text x="1045" y="26" text-anchor="end">FreeRTOS = 100；越高越好</text>')
    group_width = (right - left) / 4
    for i, category in enumerate(value['categories']):
        center = left + (i + .5) * group_width
        for j, cell in enumerate(category['cells']):
            x, score = center - 69 + j * 46, cell['score']
            y = scale(score)
            parts.append('<rect x="%.2f" y="%.2f" width="36" height="%.2f" fill="%s"><title>%s: %.2f</title></rect>' %
                         (x, y, bottom - y, colors[j], cell['os'], score))
            if category['observer_profile_only']:
                parts.append('<rect x="%.2f" y="%.2f" width="36" height="%.2f" fill="url(#ram-lines)"/>' % (x, y, bottom - y))
            parts.append('<text x="%.2f" y="%.2f" text-anchor="middle">%.1f</text>' % (x + 18, y - 7, score))
        parts.append('<text x="%.2f" y="327" text-anchor="middle">%s</text>' % (center, category['label']))
    parts.append('<text x="65" y="355" style="font-size:12px;fill:#586467">* RAM 为 F1/Z1/N1 固定观察镜像，含观察器；类别之间不加权合成。</text>')
    parts.append('<text x="65" y="389" style="font-weight:600">另两种已测 OS · 原生配置实测值（不套用上方评分）</text>')
    headers = [(65, 'OS'), (205, '五项内核计数 / 百万次·30 s'), (585, '原生通信测试'), (840, '能量 / μJ·原操作'), (995, '整机 RAM')]
    for x, label in headers:
        parts.append('<text x="%d" y="418" style="font-size:12px">%s</text>' % (x, label))
    for index, row in enumerate(value['native_profiles']):
        y = 447 + index * 31
        net = row['network']
        texts = [row['os'], ' / '.join('%.3f' % (row['kernel_counts_30s'][k] / 1e6) for k in CASES),
                 ('UDP echo: ' if row['os'] == 'RIOT' else 'UDP RX: ') + '%s %s' % (format(net['median'], ',.0f' if row['os'] == 'RIOT' else '.3f'), net['unit']),
                 '%.3f' % row['energy_uj_per_original_message_completion'], '正在测']
        for (x, _), label in zip(headers, texts):
            parts.append('<text x="%d" y="%d" style="font-size:12px">%s</text>' % (x, y, label))
    parts.append('<text x="65" y="513" style="font-size:12px;fill:#586467">内核顺序：抢占调度 / 消息 / 同步 / 中断 / 中断抢占；原生网络端点不同，每项三次独立复位。</text></svg>')
    return ''.join(parts)


def plot(value, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family': 'DejaVu Serif', 'font.size': 9, 'pdf.fonttype': 42})
    fig, ax = plt.subplots(figsize=(7, 3.1))
    colors = ('#16786c', '#b75b25', '#526cc1')
    for j, os in enumerate(SYSTEMS):
        scores = [c['cells'][j]['score'] for c in value['categories']]
        bars = ax.bar([i + (j - 1) * .23 for i in range(4)], scores, .20, color=colors[j], label=os, zorder=3)
        bars[-1].set_hatch('///')
        bars[-1].set_edgecolor('white')
        for bar, score in zip(bars, scores):
            ax.text(bar.get_x() + bar.get_width() / 2, score + 5, '%.1f' % score, ha='center', fontsize=7.5)
    ax.axhline(100, color='#666666', lw=.8, ls='--', zorder=2)
    ax.set_ylim(0, 330)
    ax.set_yticks((0, 100, 200, 300))
    ax.set_ylabel('Reference index')
    ax.set_xticks(range(4))
    ax.set_xticklabels([c['english_label'] for c in value['categories']])
    ax.grid(axis='y', color='#e2e6e5', lw=.6, zorder=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.legend(frameon=False, ncol=3, loc='upper left', bbox_to_anchor=(0, 1.18))
    fig.subplots_adjust(left=.09, right=.99, top=.84, bottom=.40)
    fig.text(.09, .98, '(a) Controlled-cohort category indices', fontsize=9, va='top')
    native_ax = fig.add_axes((.03, .015, .96, .25))
    native_ax.axis('off')
    native_ax.text(0, 1.03, '(b) Additional measured OSes: native-profile observations (raw units)', fontsize=9)
    labels = ['OS (native)', 'Kernel counts, M / 30 s\nP / M / S / I / IP', 'Native communication', 'Energy\n$\\mu$J / count', 'RAM']
    rows = []
    for row in value['native_profiles']:
        net = row['network']
        network = ('IPv6 UDP echo\n%s B/s' % format(net['median'], ',.0f') if row['os'] == 'RIOT' else
                   'iPerf UDP RX\n%.3f Mbit/s' % net['median'])
        rows.append(['RIOT' if row['os'] == 'RIOT' else 'AliOS/Rhino',
            ' / '.join('%.3f' % (row['kernel_counts_30s'][k] / 1e6) for k in CASES), network,
            '%.3f' % row['energy_uj_per_original_message_completion'], 'Pending'])
    table = native_ax.table(cellText=rows, colLabels=labels, colWidths=[.13, .41, .23, .15, .08],
                            cellLoc='center', bbox=(0, .05, 1, .88))
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor('#bfc8c6')
        cell.set_linewidth(.4)
        if row == 0:
            cell.set_facecolor('#edf2f1')
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(output), metadata={'CreationDate': None, 'ModDate': None})
    plt.close(fig)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('summarize', 'plot'))
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    data = json.loads(args.input.read_text())
    if args.mode == 'plot':
        plot(data, args.output)
        if args.receipt:
            import matplotlib
            args.receipt.write_text(json.dumps({'scores': data,
                'scores_json_sha256': hashlib.sha256(args.input.read_bytes()).hexdigest(),
                'renderer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'pdf_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                'matplotlib_version': matplotlib.__version__}, indent=2) + '\n')
    else:
        result = from_audit(data)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(json.dumps({c['id']: {r['os']: round(r['score'], 2) for r in c['cells']} for c in result['categories']}))
