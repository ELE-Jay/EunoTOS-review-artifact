#!/usr/bin/env python3
"""Project existing evidence into fixed-reference indices and explicit contracts.

Reuse UnixBench's fixed-reference/geometric-mean idea, not its Unix workloads,
its baseline scale, or its discard-worst-pass estimator. No acquisition here.
"""
import copy
import hashlib
import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'tools/data/esp32-tm-reference-v1.json'
INPUT = ROOT / 'artifacts/reports/esp32-benchmark-v1.json'
OUTPUT = ROOT / 'artifacts/reports/esp32-method-standardization-v1.json'
COHORT = ('FreeRTOS', 'Zephyr', 'NuttX')
CASES = ('cooperative_scheduling', 'preemptive_scheduling', 'message_processing',
         'synchronization_processing', 'interrupt_processing', 'interrupt_preemption_processing')
UNIX = 'https://github.com/kdlucas/byte-unixbench/blob/e949d4402f76b4bc9b7b114418faace882f0ef12/UnixBench/'
LM = 'https://github.com/intel/lmbench/blob/27b43aeec9dc0bb45f420388c78e42dde4c23bf0/doc/'
CONTRACTS = (
    ('内核事件吞吐', 'Thread-Metric 原计数 / s', '高', '原 30 s 总数 / 30；三次独立重启取中位数',
     '六项固定集合用于指数；Basic 仅为对照；固定块池/通用堆分组。循环吞吐不是上下文切换或单操作延迟。'),
    ('操作延迟', '原测试 μs / 原操作或迭代', '低', '保留原均值/单次样本等统计量；再汇总重启级中位数与范围',
     '明确起止点、对象和校准扣除；同名但不同端点不混排；不从吞吐取倒数。'),
    ('实时负载承载', 'Hartstone PH1–PH4 原单位', '高', '每轮首次失约前最后完整成功阶梯；三轮中位数和范围',
     '保留频率、倍率、KWI/任务、额外任务数，不合成跨单位实时性总分；不是最坏响应时间保证。'),
    ('固件与内存资源', 'Flash / 静态 SRAM / RAM 观察 · B 或 KiB', '低', '静态字节计量与三轮运行观察分别标明',
     '同工作负载/镜像/生命周期才可比；已分配栈不是实际使用峰值；RAM 容量不是内存带宽。'),
    ('整板工作负载能耗', 'μJ / 原操作；mW', '低', '同轮 30→90 s 的能量与原计数配对；三轮原值、中位数与范围',
     '旧板 POWER-Z 历史实测；不配新板/新固件；不从性能指数推算，不与吞吐重复加权。'),
    ('网络', '接收吞吐 Mbit/s 或 B/s；原丢包率 %、抖动 ms', '吞吐高；丢包/抖动低', '原接收统计、原方向及三次重启',
     'RF、方向、核数、tick 和栈配置不一致时仅列实测；固定负载字节率不是饱和带宽。'),
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def measured_row(data, os, case):
    rows = [r for r in data['rows'] if r['section'] == 'tm' and r['os'] == os and r['metric'] == case]
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('Duplicate original case: ' + os + '/' + case)
    row = rows[0]
    values = row['values']
    if not row['measurement_eligible'] or row['unit'] != 'count/30s' or len(values) != 3 or \
            any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) or v <= 0 for v in values) or \
            row['median'] != statistics.median(values) or row['range'] != [min(values), max(values)]:
        raise ValueError('Invalid original throughput evidence: ' + os + '/' + case)
    captures = row['extra'].get('captures', [])
    if len(captures) != 3 or len({c['path'] for c in captures}) != 3 or \
            len({c['sha256'] for c in captures}) != 3:
        raise ValueError('No distinct three-reset capture identities')
    return row


def standardize(data, reference=None):
    reference = copy.deepcopy(reference if reference is not None else json.loads(REFERENCE.read_text()))
    if tuple(reference['cases']) != CASES or reference['reference_index'] != 100 or \
            reference['original_window_seconds'] != 30 or reference['os'] != 'FreeRTOS':
        raise ValueError('Fixed protocol/reference changed; requires a new revision')
    base_rows = [measured_row(data, 'FreeRTOS', c) for c in CASES]
    if any(r is None for r in base_rows) or digest(base_rows) != reference['baseline_rows_sha256'] or \
            any(r['median'] != reference['cases'][r['metric']]['count'] for r in base_rows):
        raise ValueError('Frozen reference no longer matches its measured source')
    proof = data.get('offline_audits', {}).get('primary', {})
    if not proof.get('thread_metric_scoped_ranking_eligible') or \
            set(proof['thread_metric_scoped_ranked_cases']) != set(CASES):
        raise ValueError('Source/configuration admission is absent')
    cases, totals = [], []
    for os in COHORT:
        indices = []
        for case in CASES:
            row = measured_row(data, os, case)
            if row is None:
                continue
            base = reference['cases'][case]['count']
            index = 100 * row['median'] / base
            cases.append({'os': os, 'case': case, 'source_values': row['values'],
                          'median_count_30s': row['median'], 'count_per_second': row['median'] / 30,
                          'reference_count_30s': base, 'index': index,
                          'source_evidence': row['evidence'], 'captures': row['extra']['captures']})
            indices.append(index)
        totals.append({'os': os, 'included_cases': len(indices), 'required_cases': 6,
                       'index': math.exp(sum(math.log(v) for v in indices) / 6) if len(indices) == 6 else None,
                       'status': '完整六项 · 限定配置指数' if len(indices) == 6 else '缺项 · 不计算汇总指数'})
    totals.sort(key=lambda r: (r['index'] is None, -(r['index'] or 0), r['os']))
    orders = {case: ([[r['os'] for r in cases if r['case'] == case and r['median_count_30s'] == value]
                     for value in sorted({r['median_count_30s'] for r in cases if r['case'] == case}, reverse=True)]
                    if sum(r['case'] == case for r in cases) == len(COHORT) else None)
              for case in CASES}
    return {'schema': 'iot-os-reporting-protocol-v2', 'date': '2026-10-19', 'new_board_boots': 0,
            'new_raw_metrics': False, 'formal_cross_suite_total': None,
            'index_name': 'Thread-Metric 六项内核吞吐指数', 'official_upstream_score': False,
            'reference': reference, 'reference_sha256': digest(reference),
            'source_rows_sha256': digest(data['rows']), 'cohort': list(COHORT), 'cases': cases, 'case_orders': orders, 'indices': totals,
            'aggregation': '100 × exp(mean(log(raw original count / frozen FreeRTOS count))); six cases each 1/6',
            'selection': 'Frozen six source-audited kernel cases; Basic and non-equivalent allocators are outside the index.',
            'scope': 'Configured whole systems on the old board, not pure kernel speed or 12-OS completeness. No Basic correction or energy/Hartstone/resource weighting.',
            'contracts': [dict(zip(('dimension', 'unit', 'direction', 'statistic', 'boundary'), c)) for c in CONTRACTS],
            'method_sources': [
                {'label': 'UnixBench 固定基准与分类指数', 'url': UNIX + 'USAGE', 'anchor': 'The BYTE Index; Multiple CPUs'},
                {'label': 'UnixBench 归一化与几何平均实现', 'url': UNIX + 'Run', 'anchor': 'combinePassResults; indexResults'},
                {'label': 'LMbench 计时、初始化/清理与重复', 'url': LM + 'lmbench.3', 'anchor': 'benchmp; initialize; cleanup; warmup; repetitions'},
                {'label': 'LMbench 上下文切换的具体语义', 'url': LM + 'lat_ctx.8', 'anchor': 'Unix-pipe process ring; working set and overhead'},
            ],
            'differences_from_sources': [
                'Not a UnixBench or LMbench port or official score; reference 100 is this project convention, versus UnixBench baseline 10.',
                'Retain all three independent reset results and their median; do not copy UnixBench worst-third discard or claim LMbench default repetitions.',
                'Existing first-window measurements were not retroactively warmed up. Cache state and timer-overhead qualification remain per original test.',
                'Historical Basic-corrected orders and three-dimensional policy draft remain separate and are not silently rewritten.',
                'All six cases required; no zero imputation or automatic reweighting. Clock/core/tick/compiler/profile/board changes require new admission.',
            ],
            'unmeasured_originals': [
                {'test': 'LMbench bw_mem / lat_mem_rd', 'status': '未移植/未测', 'reason': '现有 RAM 字节占用不提供内存带宽或访存延迟。'},
                {'test': 'LMbench lat_ctx / lat_pipe; UnixBench Pipe Switching', 'status': '原测试未测', 'reason': '现有线程/队列测试不是原 Unix 进程管道环，不能替名填数。'},
                {'test': 'UnixBench fork/exec/shell/syscall/file; LMbench mmap/pagefault', 'status': '不属于当前共同 MCU 配置', 'reason': '需要共同进程/保护域/文件系统或虚拟内存语义；某 OS 支持子集也不等于所有 OS 可横排。'},
                {'test': 'UnixBench Dhrystone / Double Whetstone', 'status': '未产生原成绩', 'reason': 'Basic Processing 和 Hartstone Small Whetstone 不能冒充这些原测试。'},
            ]}


if __name__ == '__main__':
    data = json.loads(INPUT.read_text())
    result = standardize(data)
    result['source_snapshot_sha256'] = hashlib.sha256(INPUT.read_bytes()).hexdigest()
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'indices': result['indices'], 'new_board_boots': 0}, ensure_ascii=False))
