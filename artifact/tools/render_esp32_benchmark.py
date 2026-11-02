#!/usr/bin/env python3
"""Publish existing ESP32 measurements without building, flashing or acquiring data."""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "artifacts/reports"
OUTPUT = EVIDENCE / "esp32-benchmark-v1.json"
OS_NAMES = ("FreeRTOS", "Zephyr", "NuttX", "RIOT", "AliOS-Rhino")
PRIMARY = OS_NAMES[:3]


def same_published_evidence(computed, recorded):
    """Preserve sealed values across float runtimes and added zperf diagnostics."""
    from audit_esp32_b1_native_energy import equal_observation
    computed = json.loads(json.dumps(computed, allow_nan=False))
    additions = {"original_board_duration_printed", "original_board_decimal_mbit_s",
                 "original_board_rate_resolution_mbit_s", "original_board_endpoint"}

    def compare(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            extra = a.keys()-b.keys()
            if b.keys()-a.keys() or extra and (not extra <= additions or not {
                    "uart_sha256", "raw_uart_sha256", "host_sha256", "wire"} <= b.keys()):
                return False
            return all(compare(a[k], b[k]) for k in b)
        if isinstance(a, list) and isinstance(b, list):
            return len(a) == len(b) and all(compare(x,y) for x,y in zip(a,b))
        return equal_observation(a,b)

    return compare(computed, recorded)


TM_SOURCE = "https://github.com/eclipse-threadx/threadx/tree/v6.2.1_rel/utility/benchmarks/thread_metric"
SOURCES = {
    "Thread-Metric": TM_SOURCE,
    "Hartstone PH": "https://www.sei.cmu.edu/documents/6/1990_012_001_15890.pdf",
    "Zephyr latency_measure": "https://github.com/zephyrproject-rtos/zephyr/tree/v3.7.0/tests/benchmarks/latency_measure",
    "Zephyr sys_kernel": "https://github.com/zephyrproject-rtos/zephyr/tree/v3.7.0/tests/benchmarks/sys_kernel",
    "RIOT native": "https://github.com/RIOT-OS/RIOT/tree/dd06b3727c41c2c44bf93f47ff7831fdd501d68b/tests/bench",
    "FreeRTOS native": "https://github.com/espressif/esp-idf/tree/v5.2.5/components/freertos/test_apps/freertos",
    "ESP-IDF ISR（修正版）": "https://github.com/espressif/esp-idf/blob/v5.2.5/components/freertos/test_apps/freertos/performance/test_isr_latency.c",
    "Rhealstone": "https://github.com/RTEMS/rtems/tree/acb78c0c8c76f4ae12c60b729948e541c1e3930c/testsuites/rhealstone",
    "ESP-IDF iPerf": "https://github.com/espressif/esp-idf/blob/v5.2.5/examples/wifi/iperf/README.md",
    "Zephyr zperf": "https://github.com/zephyrproject-rtos/zephyr/tree/v3.7.0/samples/net/zperf",
    "NuttX iPerf": "https://github.com/apache/nuttx-apps/blob/nuttx-12.2.1/netutils/iperf/iperf.c",
    "RIOT benchmark_udp": "https://github.com/RIOT-OS/RIOT/blob/dd06b3727c41c2c44bf93f47ff7831fdd501d68b/examples/benchmark_udp/README.md",
    "AliOS iPerf": "https://github.com/alibaba/AliOS-Things/blob/bacc144bdc5df8fe8e302e3732675a920aa40bc5/network/lwip/apps/iperf/iperf_cli.c",
}
TM_NAMES = {
    "basic_processing": ("基础处理（对照）", "1024 元素数组更新的完整 sweep；用于 CPU / 编译器对照，不是内核速度分。"),
    "cooperative_scheduling": ("协作调度吞吐", "五个同优先级线程主动让出 CPU，累加原循环计数；原整数均值平衡检查作为准入。"),
    "preemptive_scheduling": ("抢占调度吞吐", "五个不同优先级线程按原程序恢复高优先级线程并自挂起；包含原生唤醒和调度成本。"),
    "message_processing": ("消息队列吞吐", "同一线程向四槽 FIFO 发送并接收 16 字节消息；是发送 / 接收循环，不是跨线程交接延迟。"),
    "synchronization_processing": ("信号量吞吐", "同一线程执行原 get / put 循环，信号量计数 1→0→1；不是阻塞线程唤醒延迟。"),
    "memory_allocation": ("内存分配吞吐", "原程序申请并释放 128 字节；变长私有堆与固定块池保留分配器家族区别，不给通用内存排名。"),
    "interrupt_processing": ("中断处理吞吐", "CPU 软件请求 peripheral 26 / level 1，进入真实 ISR 并按原程序同步；不是外部 GPIO 中断入口延迟。"),
    "interrupt_preemption_processing": ("中断抢占吞吐", "同一真实 ISR 路径唤醒更高优先级线程，线程按原程序自挂起；计数不是单次 IRQ→任务延迟。"),
}
PH_NAMES = {
    1: ("PH1 · 单任务频率", "Hz", "只提高最高频率任务的请求频率：200 + 40 × 最后无失约 step。"),
    2: ("PH2 · 全任务频率", "倍", "同比放大五个基础任务的频率：(10 + 最后无失约 step) / 10。"),
    3: ("PH3 · 任务工作量", "KWI/任务", "每次释放、每个基础任务增加的 Small Whetstone 工作量；数值是最后无失约 step。"),
    4: ("PH4 · 额外任务数", "个", "向原五个任务逐次加入 8 Hz / 500 KWI 工作线程；数值是最后无失约的额外线程数。"),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(name):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def stats(values):
    if not values or any(not isinstance(v, (int, float)) for v in values):
        raise ValueError("missing real numerical repetitions")
    return {"values": values, "median": statistics.median(values), "range": [min(values), max(values)]}


def profile(os):
    return {
        "FreeRTOS": "ESP-IDF 5.2.5 / GCC 13.2 / 100 Hz tick / 抢占开启、时间片关闭",
        "Zephyr": "Zephyr 3.7.0 / GCC 13.2 / 100 Hz tick / 单核、时间片关闭",
        "NuttX": "NuttX 12.2.1 / GCC 13.2 / 100 Hz tick / 原生 FIFO",
        "RIOT": "RIOT dd06b372 / GCC 12.2 / 原生 tickless / priority FIFO",
        "AliOS-Rhino": "AliOS rel_3.0.0 bacc144b / GCC 5.2 / 100 Hz tick / 原生 Rhino、无 RR",
    }[os]


def make_row(section, suite, metric, os, values, unit, *, description="", evidence="", eligible=True,
             condition="", status="已测 · 不具备排名资格", source="", extra=None):
    reported_os = os
    os = next((name for name in OS_NAMES if os.startswith(name)), "AliOS-Rhino" if os.startswith("AliOS") else os)
    return {"section": section, "suite": suite, "metric": metric, "os": os, "unit": unit,
            **stats(values), "measurement_eligible": eligible, "status": status,
            "description": description, "evidence": evidence, "condition": condition,
            "source": source or SOURCES.get(suite, ""), "extra": {**(extra or {}), "reported_os_identity": reported_os}}


def ordered(values, descending=True):
    groups = []
    for os in sorted(values, key=values.get, reverse=descending):
        if groups and values[groups[-1][0]] == values[os]:
            groups[-1].append(os)
        else:
            groups.append([os])
    return groups


def latency_scope(suite, metric, os):
    os = next((name for name in OS_NAMES if os.startswith(name)), "AliOS-Rhino" if os.startswith("AliOS") else os)
    if suite == "Zephyr sys_kernel":
        return ("原固定块池分配 / 释放迭代" if metric.startswith("Memslab") else
                "原多线程往返迭代，包含工作线程创建与退出")
    if metric.startswith("thread.") and ".yield." not in metric:
        return {
            "Zephyr": "原生 k_thread 生命周期路径",
            "FreeRTOS": "静态任务 + 启动通知及完成信号量适配；包含适配成本",
            "NuttX": "nxtask 任务组 / TCB / TLS 等生命周期；暂停恢复走 SIGSTOP / SIGCONT",
            "RIOT": "原生休眠线程 + 完成互斥锁 / 队列退休适配",
            "AliOS-Rhino": "原生静态任务 + 完成信号量及任务删除适配",
        }[os]
    if metric.startswith("heap."):
        return "原 10 B 即时分配 / 释放；原生堆与适配成本，保留各端堆状态"
    if metric.startswith("stack.") and os == "FreeRTOS":
        return "4 B 队列头部拷贝 / 接收，含原生阻塞唤醒与复制成本"
    if metric.startswith(("fifo.", "lifo.")):
        return "原生侵入式 FIFO / LIFO；alloc / free 项另含节点分配成本"
    if metric.startswith("isr."):
        return "起点为 ISR 内 give 之后；至线程继续 / 调度，保留适配路径"
    if metric.startswith("condvar."):
        return "原条件变量阻塞 / 通知端点，含互斥锁、确认与原生适配成本"
    if metric.startswith("events."):
        return "原事件位即时 / 阻塞操作；wake 项包含上下文切换与原生适配"
    if metric.startswith("mutex."):
        return "原递归有主互斥锁；保留各端优先级继承配置"
    if metric.startswith("semaphore."):
        return "原信号量即时 / 阻塞端点；wake 项包含上下文切换与原生适配"
    return "原程序指定端点与循环，保留原生对象和适配成本"


def hartstone_observations(folder, experiment, runs):
    from audit_esp32_hartstone_series import BASELINE, TASK, TRIAL
    from hartstone_ph_protocol import baseline_tasks, trial_tasks

    observations, utilizations, activations = [], [], []
    paths = sorted(folder.glob("reset*.jsonl"))
    if len(paths) != len(runs):
        raise ValueError("Hartstone context lacks its original captures")
    for path, run in zip(paths, runs):
        tasks = trial_tasks(baseline_tasks(BASELINE), experiment, run["best_step"])
        utilizations.append(float(100 * sum(hz * work for hz, work in tasks) / run["raw_speed_kwips"]))
        activations.append(int(sum(hz * 10 for hz, _ in tasks)))
        lines = [json.loads(line)["line"] for line in path.read_text(encoding="utf-8").splitlines()]
        matches = [(i, m) for i, line in enumerate(lines) if (m := TRIAL.fullmatch(line))
                   and int(m.group(4)) == run["first_loss_step"]]
        if len(matches) != 1:
            raise ValueError("Hartstone context lacks its audited first-loss trial")
        index, header = matches[0]
        counters = [TASK.fullmatch(line) for line in lines[index + 1:index + 1 + int(header.group(5))]]
        if any(m is None or m.group(8) != "us" for m in counters):
            raise ValueError("Hartstone first-loss task counters or time units differ")
        observations.append({"path": str(path.relative_to(ROOT)), "sha256": sha(path),
                             "step": run["first_loss_step"],
                             **{name: sum(int(m.group(group)) for m in counters) for name, group in
                                (("met", 5), ("missed", 6), ("skipped", 7), ("late_sum_us", 9))}})
    return {"last_loss_free_requested_utilization_pct": utilizations,
            "last_loss_free_activations": activations, "first_loss_observations": observations,
            "trial_duration_s": 10, "timestamp_quantum_us": 10}


def metric_rows(group, key):
    if isinstance(group, list):
        for i, value in enumerate(group):
            yield from metric_rows(value, f"{key}[{i}]")
        return
    if not isinstance(group, dict) or "metrics" not in group:
        return
    # Captures also contain per-run metrics; do not count those as additional cases.
    for metric, result in group["metrics"].items():
        values = result.get("means_ns", result.get("resets_ns"))
        if values is None:
            continue
        if group.get("resets") != len(values) or len(values) != 3:
            raise ValueError("metric lacks three independent resets: " + key + "/" + metric)
        suite = "Zephyr sys_kernel" if "syskernel" in key or group.get("benchmark") == "sys_kernel" or \
            "sys_kernel" in group.get("benchmark", "") else "Zephyr latency_measure"
        condition = {n: group[n] for n in ("compiler", "tick_hz", "clock_mhz", "cores", "original_iterations",
                                          "iterations", "worker_stack_bytes") if n in group}
        description = str(group.get("boundary", group.get("ranking_reason", "原程序指定测量路径及均值；包含原生适配成本。")))
        extra = {"cohort": key, "statistic": "三次重启的原均值；展示其中位数和 min–max",
                 "measurement_scope": latency_scope(suite, metric, group["os"])}
        if key.startswith("groups.zephyr_native["):
            description = "Zephyr 原生程序的原均值；本版另列其他 OS 已测适用子集。对象、适配层和计时准备条件不同，暂无合格跨 OS 排名。"
            extra["archived_ranking_reason"] = group.get("ranking_reason", "")
        yield make_row("latency", suite, metric, group["os"], values, "ns",
                       description=description,
                       evidence=f"esp32-public-extensions-v1.json:{key}.metrics.{metric}",
                       condition=condition, extra=extra)


def assemble(verify=True):
    from audit_esp32_report import TM, audit_report, audit_tm, report_rows
    from audit_esp32_migration_report import audit_report as audit_migration
    from audit_esp32_public_extensions import audit as audit_public
    from audit_esp32_riot_tm import audit_suite as audit_riot_tm
    from audit_esp32_alios_tm import audit_case as audit_alios_tm
    from audit_esp32_hartstone_series import audit as audit_ph
    from audit_esp32_riot_hartstone import audit_experiment as audit_riot_ph
    from audit_esp32_alios_hartstone import audit_experiment as audit_alios_ph

    text = (ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md").read_text(encoding="utf-8")
    public = read_json("esp32-public-extensions-v1.json")
    migration = read_json("esp32-migration-report-audit.json")
    if public["report_sha256"] != sha(ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md") or \
            public["gap_ledger_sha256"] != sha(ROOT / "ESP32_BENCHMARK_GAPS.md") or public["composite_score"] is not None:
        raise ValueError("canonical input report or eligibility is stale")
    audit_proof = {}
    if verify:
        audit_proof["primary"] = audit_report(text)
        print("PASS: existing primary source/config/Flash/UART audit", flush=True)
        # Compare the same JSON wire representation as the archived audit entry points.
        migration_replay = audit_migration(text)
        migration_replay["report_sha256"] = sha(ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md")
        if not same_published_evidence(audit_public(), public) or not same_published_evidence(migration_replay, migration):
            raise ValueError("fresh offline audit differs from canonical measured evidence")
        audit_proof.update(public="pass; canonical values preserved; float tolerance 1e-12/1e-18; added native endpoint diagnostics allowed",
                           migration="pass; canonical values preserved; exact hashes, integers and structure")
        print("PASS: existing extension/resource/energy audits; no board calls", flush=True)

    table_rows = report_rows(text)
    rows, tm_cells = [], []
    for case, label, patterns in TM:
        for os in PRIMARY:
            paths = sorted(EVIDENCE.glob(patterns[os]))
            values = [audit_tm(p, os, case)["original_window_totals"][0] for p in paths]
            if len(paths) != 3 or statistics.median(values) != int(table_rows[label][1 + PRIMARY.index(os)].replace(",", "")):
                raise ValueError("primary published median differs from reset evidence")
            tm_cells.append({"os": os, "case": case, "first_window_values": values,
                             "evidence": [str(p.relative_to(ROOT)) for p in paths],
                             "captures": [{"path": str(p.relative_to(ROOT)), "sha256": sha(p)} for p in paths]})
    tm_cells.extend(audit_riot_tm(EVIDENCE / "riot-native-gcc12-v3")["cells"])
    tm_cells.extend(audit_alios_tm(EVIDENCE / "alios-native-gcc5-v3" / case, case) for case, *_ in TM)
    corrected = {c["case"]: c for c in public["separate_alios_original_tm_irq_vector_corrected"]["cells"]}
    tm_orders = {}
    basic = {c["os"]: statistics.median(c["first_window_values"]) for c in tm_cells if c["case"] == "basic_processing"}
    for cell in tm_cells:
        os, case = cell["os"], cell["case"]
        if os == "AliOS-Rhino" and case in corrected:
            cell = corrected[case]
        comparable = os in PRIMARY and case not in ("basic_processing", "memory_allocation")
        row = make_row("tm", "Thread-Metric", case, os, cell["first_window_values"], "count/30s",
                       description=TM_NAMES[case][1], evidence=cell["evidence"], condition=profile(os),
                       status="已测 · 限定配置组可比" if comparable else "已测 · 不具备排名资格",
                       extra={"captures": cell.get("captures", []), "cohort": "校正原生中断向量" if os == "AliOS-Rhino" and case in corrected else "原选择组",
                              "corrected_count": float(Fraction(statistics.median(cell["first_window_values"])) * basic["FreeRTOS"] / basic[os]) if comparable else None})
        row["label"] = TM_NAMES[case][0]
        rows.append(row)
    for case in TM_NAMES:
        if case not in ("basic_processing", "memory_allocation"):
            tm_orders[case] = ordered({r["os"]: Fraction(r["median"]) * basic["FreeRTOS"] / basic[r["os"]]
                                       for r in rows if r["section"] == "tm" and r["metric"] == case and r["os"] in PRIMARY})

    ph_orders = {}
    for experiment in range(1, 5):
        ph_values = {}
        for os in OS_NAMES:
            if os in PRIMARY:
                folder = EVIDENCE / ("hartstone-native-us-fifo-v1/freertos" if os == "FreeRTOS" else
                                     "hartstone-native-us-v1/" + os.lower()) / f"ph{experiment}"
                runs = [audit_ph(p, os, experiment, high_resolution=True) for p in sorted(folder.glob("reset*.jsonl"))]
            else:
                folder = EVIDENCE / ("hartstone-riot-native-v4" if os == "RIOT" else "hartstone-alios-native-v4") / f"ph{experiment}"
                runs = (audit_riot_ph if os == "RIOT" else audit_alios_ph)(folder, experiment)["runs"]
            if len(runs) != 3 or any(r["completion"] != "FIRST_LOSS_REACHED" for r in runs):
                raise ValueError("incomplete Hartstone run cannot become a threshold")
            steps = [r["best_step"] for r in runs]
            values = [{1: 200 + 40 * s, 2: (10 + s) / 10, 3: s, 4: s}[experiment] for s in steps]
            metric = f"PH{experiment}"
            row = make_row("hartstone", "Hartstone PH", metric, os, values, PH_NAMES[experiment][1],
                           description=PH_NAMES[experiment][2] + " 首次失约即停止；不是保证的最大容量。SEI 衍生 C 实现，不冒充原 Ada 程序。",
                           evidence=str(folder.relative_to(ROOT)),
                           condition="240 MHz / 单核 / 10 μs 释放逻辑网格；FreeRTOS、NuttX 1 kHz tick 配合原生微秒定时器，Zephyr tickless 100 kHz 逻辑时钟；RIOT GCC12、Rhino GCC5 单列。",
                           status="已测 · 限定 C-port 配置组可比" if os in PRIMARY else "已测 · 不具备排名资格",
                           extra={"last_loss_free_steps": steps, "first_loss_steps": [r["first_loss_step"] for r in runs],
                                  "calibration_kwips": [r["raw_speed_kwips"] for r in runs],
                                  **hartstone_observations(folder, experiment, runs)})
            row["label"] = PH_NAMES[experiment][0]
            rows.append(row)
            if os in PRIMARY:
                ph_values[os] = statistics.median(values)
        ph_orders[metric] = ordered(ph_values)

    for i, group in enumerate(public["groups"]["zephyr_native"]):
        rows.extend(metric_rows(group, f"groups.zephyr_native[{i}]"))
    for key, value in public.items():
        if key.startswith("separate_") and "zephyr" in key:
            rows.extend(metric_rows(value, key))

    for suite in public["groups"]["riot_native"]:
        for metric, value in suite["metrics"].items():
            valid = value["measurement_eligible"]
            field, unit = ("original_count", "count/1s") if "median_original_count" in value else ("total_us", "μs/100万次循环")
            rows.append(make_row("native" if valid else "diagnostic", "RIOT native", metric, "RIOT",
                                 [r[field] for r in value["raw_resets"]], unit,
                                 eligible=valid, description=value["raw_resets"][0]["reason"],
                                 evidence="esp32-public-extensions-v1.json:groups.riot_native/" + suite["benchmark"],
                                 condition="原生 RIOT / GCC12 / tickless；原计数不是独立切换或孤立 API 延迟",
                                 status="已测 · 不具备排名资格" if valid else "原输出无效 · 不计成绩",
                                 extra={"raw_original": value["raw_resets"]}))
    for suite in public["groups"]["freertos_native"]:
        rows.append(make_row("native", "FreeRTOS native", suite["benchmark"], "FreeRTOS",
                             [r["microseconds"] for r in suite["captures"]], "μs",
                             description="每次重启内原 1023 个样本的中位数；再展示三个重启级中位数的中位数及范围。",
                             evidence="esp32-public-extensions-v1.json:groups.freertos_native", condition="原 FreeRTOS 调度性能测试；不是其他套件的线程切换结果"))

    isr = public["separate_corrected_original_method_isr"]
    if not isr["measurement_eligible"] or isr["unmodified_official_source"] or isr["ranking_eligible"]:
        raise ValueError("corrected ISR measurement or source qualification changed")
    for case, group in isr["groups"].items():
        if group["resets"] != 3 or len(group["captures"]) != 3:
            raise ValueError("corrected ISR requires three resets per original case")
        for metric in ("ISR_ENTER_CYCLES", "ISR_EXIT_CYCLES"):
            values = [r["original_average_cycles"][metric] for r in group["captures"]]
            if any(not r["measurement_eligible"] or not r["original_unity_pass"] for r in group["captures"]) or \
                    statistics.median(values) / isr["clock_mhz"] != group["median_of_original_averages_us"][metric]:
                raise ValueError("corrected ISR original averages or admission differ")
            rows.append(make_row("latency", "ESP-IDF ISR（修正版）", case + " · " + metric, isr["os"], values, "cycles",
                                 description="原 10000 次循环均值；仅修正两个未初始化 yield 标志并在测后释放信号量。入口为 CPU 软件触发至 ISR，返回为 ISR 尾部至原触发任务继续运行，不是 GPIO 入口或阻塞任务唤醒。",
                                 evidence="esp32-public-extensions-v1.json:separate_corrected_original_method_isr.groups." + case,
                                 condition={key: isr[key] for key in ("cores", "clock_mhz", "tick_hz", "source_change", "boundary")},
                                 status="已测修正版 · 不具备排名资格",
                                 extra={"clock_mhz": isr["clock_mhz"], "original_iterations": 10000,
                                        "unmodified_official_source": False, "image_sha256": isr["binary_sha256"],
                                        "captures": group["captures"], "reuse_controls_not_timing_results": True}))

    resources = read_json("esp32-resources-v1/resources.json")
    ram = read_json("esp32-resources-v1/ram-workloads-summary.json")
    for cell in resources["cells"]:
        for field, metric, description in (("installed_flash_bytes", "已安装 Flash", "已烧录镜像段的实际字节总量，含启动程序 / 分区；不是最小内核或 Flash 地址跨度。"),
                                           ("static_sram_bytes", "静态物理 SRAM", "链接静态占用的物理 SRAM 去重；不是运行峰值。")):
            rows.append(make_row("resources", "Firmware footprint", metric, cell["os"], [cell[field]], "B",
                                 description=description, evidence=cell["evidence"], condition="40 项原选择组资源固件；不与 RAM 观察器固件等同",
                                 extra={"workload": cell["case"], "elf_sha256": cell["elf_sha256"]}))
    for cell in ram["cells"]:
        values = [cell["static_sram_bytes"] + r["dynamic_heap_peak_bytes"] +
                  cell.get("native_heap_control", {}).get("native_heap_control_bytes", 0) for r in cell["runs"]]
        if len(values) != 3 or stats(values) != {"values": values, "median": cell["runtime_whole_ram_peak_bytes"],
                                               "range": [cell["runtime_whole_ram_peak_min_bytes"], cell["runtime_whole_ram_peak_max_bytes"]]}:
            raise ValueError("native per-reset RAM totals differ from audited summary")
        rows.append(make_row("resources", "Workload RAM", "工作负载软件 RAM 占用峰值", cell["os"], values, "B",
                             description=str(cell["definition"]), evidence=cell["evidence"], condition=str(cell["window"]),
                             extra={"workload": cell["original_case"], "includes_observer": True,
                                    "excludes": cell["excludes"], "elf_sha256": cell["elf_sha256"]}))
    for key, field, metric in (
        ("separate_lifecycle_ram_iram_observations", "observed_software_ram_peak_bytes", "PH4 软件 RAM 占用峰值"),
        ("separate_riot_hartstone_ph4_native_heap_ram_observation", "observed_software_ram_peak_bytes", "PH4 软件 RAM 占用峰值"),
        ("separate_zephyr_hartstone_ph4_static_ram_observation", "observed_static_software_reservation_bytes", "PH4 静态软件预留")):
        group = public[key]
        value = group[field]
        values = value if isinstance(value, list) else [value]
        rows.append(make_row("resources", "Hartstone RAM", metric, group["os"], values, "B",
                             description="含观察器、栈或堆预留；不是 live-stack、启动全程或无插桩峰值。三端负载上限不同，不排名。",
                             evidence="esp32-public-extensions-v1.json:" + key,
                             condition=group.get("window", group.get("reason", "原 PH4 参考负载覆盖已核对")),
                             extra={"workload": "PH4", "independent_resets": group["resets"],
                                    "elf_sha256": group["resources"]["elf_sha256"], "includes_observer": True,
                                    "first_loss_worker_counts": [5 + r["observed_hartstone_series"]["first_loss_step"] for r in group["runs"]],
                                    "reserved_worker_slots": group.get("worker_slots_reserved"),
                                    "worker_stack_reservation_bytes": group.get("worker_stack_reservation_bytes"),
                                    "allocation_scope": "静态栈 / 堆预留" if field == "observed_static_software_reservation_bytes" else
                                                        "静态占用 + 同时占用原生堆，含已分配栈"}))

    for cell in public["separate_alios_original_tm_irq_vector_ram_observations"]["cells"]:
        peaks = [cell["static_sram_bytes"] + r["dynamic_heap_peak_bytes"] for r in cell["runs"]]
        if len(peaks) != 3 or statistics.median(peaks) != cell["runtime_whole_ram_peak_bytes"] or \
                [min(peaks), max(peaks)] != [cell["runtime_whole_ram_peak_min_bytes"], cell["runtime_whole_ram_peak_max_bytes"]]:
            raise ValueError("corrected Rhino observer RAM differs from original resets")
        for metric, values, description in (
            ("已安装 Flash", [cell["installed_flash_bytes"]], "校正中断路径的 RAM 观察器固件安装字节；包含观察器。"),
            ("静态物理 SRAM", [cell["static_sram_bytes"]], "同一 RAM 观察器固件的静态物理 SRAM 去重占用。"),
            ("工作负载软件 RAM 占用峰值", peaks, cell["definition"])):
            rows.append(make_row("resources", "Workload RAM", metric, cell["os"], values, "B",
                                 description=description, evidence=cell["evidence"], condition=cell["window"],
                                 extra={"workload": cell["case"], "original_workload": cell["original_case"],
                                        "cohort": "校正中断路径 RAM 观察器", "includes_observer": True,
                                        "elf_sha256": cell["elf_sha256"], "excludes": cell["excludes"],
                                        "performance_or_energy_firmware_peak": False}))

    energy = read_json("powerz-thread-metric-energy-20261009-corrected/summary.json")
    for cell in energy["cells"]:
        if cell["os"] == "AliOS-Rhino" and cell["case"] in corrected:
            runs = corrected[cell["case"]]["energy_runs"]
            cohort = "后续校正中断向量组；不回写原 40 项能耗矩阵"
            evidence = "esp32-public-extensions-v1.json:separate_alios_original_tm_irq_vector_corrected"
        else:
            runs, cohort = cell["runs"], "原 40 项整板能耗采集组"
            evidence = "powerz-thread-metric-energy-20261009-corrected/summary.json"
        for field, metric, unit in (("energy_per_original_count_uj", "每原操作整板能耗", "μJ/原操作"),
                                     ("steady_average_power_w", "整板输入平均功率", "W")):
            rows.append(make_row("energy", "Whole-board energy", metric, cell["os"], [r[field] for r in runs], unit,
                                 evidence=evidence,
                                 description="同轮 30→60 s 与 60→90 s 的整板能量之和 / 对应原计数之和；仪表默认校准，包含板级外围与报告开销。" if field.startswith("energy") else "同一原工作负载 30→90 s 测量窗口内的整板输入平均功率。",
                                 condition=energy["calibration"], status="整板观察 · 非通用 OS 能效排名",
                                 extra={"workload": cell["case"], "cohort": cohort, "work_unit": cell["work_unit"],
                                        "drift_not_corrected": True}))

    for group_name, suite_name in (("iperf_native_network", "ESP-IDF iPerf"),
                                   ("zperf_native_network", "Zephyr zperf"),
                                   ("nuttx_iperf_native_network", "NuttX iPerf")):
        suite = public["groups"][group_name][0]
        condition = {key: suite[key] for key in ("benchmark", "cores", "clock_mhz", "tick_hz", "rr_interval_ms",
                                                "scope", "ranking_reason") if key in suite}
        for case, result in suite["cases"].items():
            captures = result["captures"]
            for field, label, unit in (("receiver_decimal_mbit_s", "接收端吞吐", "Mbit/s"),
                                       ("original_loss_percent", "原 UDP TX 丢包率", "%"),
                                       ("original_jitter_ms", "原 UDP 抖动", "ms")):
                values = [c[field] for c in captures if c.get(field) is not None]
                if len(values) != 3:
                    continue
                if field == "original_loss_percent" and not result.get("loss_measurement_eligible", False):
                    continue
                rows.append(make_row("network", suite_name, f"{case.upper()} · {label}", suite["os"], values, unit,
                                     description="原接收端统计；不同 RF / tick / 原生栈配置保留，不横排。方向以 ESP32 为主体。",
                                     evidence="esp32-public-extensions-v1.json:groups." + group_name + ".cases." + case,
                                     condition=condition, extra={"direction": case, "tick_hz": suite["tick_hz"],
                                                                "image_sha256": suite.get("image_sha256", suite.get("binary_sha256"))}))
    suite = public["separate_alios_corrected_clock_network"]
    condition = {key: suite["admission"][key] for key in ("cores", "configured_clock_mhz", "tick_hz",
                                                        "iperf_stack_bytes", "measurement_clock")}
    condition["clock_boundary"] = "240 MHz 为配置值；此网络镜像未独立验证实际 CPU 频率。"
    condition["boundary"] = suite["boundary"]
    for case, result in suite["cases"].items():
        values = [c["receiver_decimal_mbit_s"] for c in result["captures"] if c.get("receiver_decimal_mbit_s") is not None]
        if len(values) == 3:
            rows.append(make_row("network", "AliOS iPerf", case.upper() + " · 接收端吞吐", "AliOS-Rhino", values, "Mbit/s",
                                 description="原测试体；原字节 / 时间公式宽整数重放。原 UDP RX 窄整数溢出已排除。",
                                 evidence="esp32-public-extensions-v1.json:separate_alios_corrected_clock_network.cases." + case,
                                 condition=condition, extra={"direction": case, "image_sha256": suite["admission"]["image_sha256"]}))
    riot_readiness = read_json("riot-benchmark-udp-original-v2/readiness.json")
    if riot_readiness["image_sha256"] != public["groups"]["riot_udp_native_network"][0]["image_sha256"]:
        raise ValueError("RIOT network profile and measured image differ")
    for case, result in public["groups"]["riot_udp_native_network"][0]["cases"].items():
        values = [r["final_published_original_row"]["bandwidth_bytes_per_second"] for r in result["resets"]]
        rows.append(make_row("network", "RIOT benchmark_udp", "RIOT UDP · " + case, "RIOT", values, "B/s",
                             description="原 GNRC UDP 接收字节率；固定发送间隔，不是最大吞吐或完整会话丢包。原递归 RTT 不称为逐包 RTT。",
                             evidence="esp32-public-extensions-v1.json:groups.riot_udp_native_network.cases." + case,
                             condition={"cores": riot_readiness["cores"], "configured_clock_mhz": riot_readiness["configured_clock_mhz"],
                                        "payload_bytes": result["payload_bytes"], "interval_us": result["interval_us"]},
                             extra={"image_sha256": riot_readiness["image_sha256"],
                                    "profile_evidence": "riot-benchmark-udp-original-v2/readiness.json"}))

    for name, group in public["groups"].items():
        if not name.startswith("rhealstone"):
            continue
        for cell in group:
            rows.append(make_row("diagnostic", "Rhealstone", cell["case"] + " · 原扣除组", cell["os"], cell["raw_original_cycles"], "cycles",
                                 eligible=False, description=str(cell["measurement_reason"]),
                                 evidence="esp32-public-extensions-v1.json:groups." + name, status="诊断原输出 · 不计成绩",
                                 extra={"source_measurement_eligible": cell["measurement_eligible"]}))
    for key, group in public.items():
        if key.startswith("separate_original_rhealstone_calibrated_") and key.endswith("_port"):
            for cell in group["cells"]:
                rows.append(make_row("diagnostic", "Rhealstone", cell["case"] + " · 计时校准组", cell["os"], cell["raw_original_cycles"], "cycles",
                                     eligible=False, description=str(cell["measurement_reason"]), evidence="esp32-public-extensions-v1.json:" + key,
                                     status="方法未完全验证 · 不计成绩"))
        if key.endswith("rhealstone_original_single_irq_port") or key == "separate_rhealstone_original_single_irq_port":
            rows.append(make_row("latency", "Rhealstone", "ilatency · CPU 软件中断单次入口", group["os"], group["original_single_shot_cycles"], "cycles",
                                 description="每次重启只有一个原单次样本；不是均值、最坏值或外部 GPIO 入口。" + str(group["boundary"]),
                                 evidence="esp32-public-extensions-v1.json:" + key, extra={"clock_mhz": 240, "single_shot": True}))

    status = (ROOT / "ESP32_UNIFIED_BENCHMARK_STATUS.md").read_text(encoding="utf-8")
    ledger = status.split("## Twelve-OS migration ledger\n", 1)[1].split("\nThe official", 1)[0]
    support = [line.strip("|").split(" | ") for line in ledger.splitlines()
               if line.startswith("| ") and not line.startswith(("| Existing", "| ---"))]
    if len(support) != 12 or len([r for r in rows if r["section"] == "tm"]) != 40:
        raise ValueError("support or five-OS Thread-Metric coverage changed")
    build_labels = {"separate_nuttx_hartstone_ph4_freelist_ram_build": "Hartstone PH4 原工作负载 RAM 观察（NuttX 空闲链观察器）",
                    "separate_alios_hartstone_ph4_native_ram_build": "Hartstone PH4 原工作负载 RAM 观察（Rhino 原生堆观察器）"}
    pending_builds = [{"field": k, "os": v["os"], "measured": v["measured"], "board_boots": v["board_boots"],
                       "benchmark": v.get("benchmark") or build_labels[k],
                       "boundary": v.get("boundary", "原首次失约完整序列、参考工作线程覆盖和三次独立重启 RAM 审计仍待实板验证。")}
                      for k, v in public.items() if k.startswith("separate_") and k.endswith("_build")]
    if any(r["board_boots"] or r["measured"] for r in pending_builds):
        raise ValueError("build candidate cannot be silently treated as an unmeasured result")
    validations = []
    for os, slug in zip(OS_NAMES, ("freertos", "zephyr", "nuttx", "riot", "alios")):
        key = "separate_original_rtems_full_tmck_" + slug + "_validation"
        group = public[key]
        if not group["original_full_tmck_suite_measured"] or not group["measurement_eligible"] or group["ranking_eligible"]:
            raise ValueError("RTEMS timer validation scope changed")
        validations.append({"os": os, "benchmark": "RTEMS 原 tmck 计时器验证", "resets": group["resets"],
                            "boundary": group["boundary"], "evidence": "esp32-public-extensions-v1.json:" + key,
                            "ranking_eligible": False})
    gap_path = ROOT / "ESP32_BENCHMARK_GAPS.md"
    inputs = [ROOT / "ESP32_UNIFIED_BENCHMARK_REPORT.md", ROOT / "ESP32_UNIFIED_BENCHMARK_STATUS.md",
              ROOT / "ESP32_BENCHMARK_GAPS.md", EVIDENCE / "esp32-public-extensions-v1.json",
              EVIDENCE / "esp32-migration-report-audit.json", EVIDENCE / "esp32-resources-v1/resources.json",
              EVIDENCE / "esp32-resources-v1/ram-workloads-summary.json",
              EVIDENCE / "powerz-thread-metric-energy-20261009-corrected/summary.json",
              EVIDENCE / "riot-benchmark-udp-original-v2/readiness.json"]
    return {"schema": "iot-os-benchmark-report-v1", "edition": "2026-10-16", "last_board_measurement": "2026-10-11",
            "hardware": "ESP32-D0WDQ6 rev 1.1 / 4 MB Flash；核数、时钟与 tick 按测试配置列明",
            "new_board_boots": 0, "new_measurements": False, "composite_score": None, "new_metric_created": False,
            "profiles": [{"os": os, "condition": profile(os), "in_primary_comparison": os in PRIMARY,
                          "introduction": {
                              "FreeRTOS": "小型抢占式实时内核；本实验使用 ESP-IDF 的官方 Xtensa 端口，包含 SDK 配套运行服务。",
                              "Zephyr": "面向嵌入式与 IoT 的模块化实时操作系统；本实验使用 3.7.0 的 classic ESP32 procpu 配置。",
                              "NuttX": "强调 POSIX 接口的嵌入式实时操作系统；本实验是可在该 rev 1.1 板上运行的 12.2.1 原生内核。",
                              "RIOT": "面向低功耗联网设备的开源操作系统；本实验使用原生 RIOT 调度器和 tickless 定时机制。",
                              "AliOS-Rhino": "AliOS Things 的 Rhino 实时内核；本实验保留旧版官方 ESP32 BSP、GCC5 与配套 SDK 依赖。",
                          }[os], "upstream": {
                              "FreeRTOS": "https://github.com/espressif/esp-idf/tree/v5.2.5/components/freertos",
                              "Zephyr": "https://github.com/zephyrproject-rtos/zephyr/tree/v3.7.0",
                              "NuttX": "https://github.com/apache/nuttx/tree/nuttx-12.2.1",
                              "RIOT": "https://github.com/RIOT-OS/RIOT/tree/dd06b3727c41c2c44bf93f47ff7831fdd501d68b",
                              "AliOS-Rhino": "https://github.com/alibaba/AliOS-Things/tree/bacc144bdc5df8fe8e302e3732675a920aa40bc5",
                          }[os]} for os in OS_NAMES],
            "sources": SOURCES, "support": support, "rows": rows,
            "comparisons": {"thread_metric": tm_orders, "hartstone": ph_orders,
                            "energy_observed_only": energy["comparisons"]},
            "pending_builds": pending_builds, "deferred": "本轮不新增实板测量",
            "method_validations": validations,
            "gap_ledger": {"path": gap_path.name, "sha256": sha(gap_path)},
            "offline_audits": audit_proof,
            "inputs": [{"path": str(p.relative_to(ROOT)), "sha256": sha(p)} for p in inputs]}


def followup_data():
    from audit_esp32_followup import envelope, candidates, interrupts, ram

    captures = EVIDENCE / "esp32-irq-ablation-capture-b1-v1"
    if not captures.exists():
        return None
    collections = []
    for name in ("esp32-irq-ablation-capture-b1-v1", "esp32-original-followup-b1-v2",
                 "esp32-original-followup-b1-v3", "esp32-original-followup-b1-v4", "esp32-ram-followup-b1-v1"):
        folder = EVIDENCE / name
        if not (folder / "audit.json").exists():
            if name in ("esp32-ram-followup-b1-v1", "esp32-original-followup-b1-v4"):
                continue
            raise ValueError("Missing followup audit: " + name)
        campaign = envelope(folder)
        result = interrupts(folder, campaign, EVIDENCE / "esp32-irq-ablation-v2") if campaign["mode"] == "interrupts" else \
            candidates(folder, campaign) if campaign["mode"] == "candidates" else ram(folder, campaign)
        if json.loads(json.dumps(result)) != read_json(name + "/audit.json") or campaign["board_mac"] != "34:98:7a:a2:85:28":
            raise ValueError("Followup replay or physical board differs")
        collections.append({"evidence": "artifacts/reports/" + name, "mode": campaign["mode"], "result": result})
    return {"board": "B1", "date": "2026-10-19", "board_mac": "34:98:7a:a2:85:28",
            "collections": collections, "historical_cohort_modified": False, "energy_measured": False,
            "external_independent_replication": False, "ranking_eligible": False}


def publication_view(data, protocol, followup):
    """Classify presentation separately from the immutable historical snapshot."""
    admitted = {(r["os"], r["case"]) for r in protocol["cases"]}
    from audit_esp32_latency_semantics import audit as audit_latency
    latency = audit_latency()
    if latency != read_json("esp32-latency-semantics-v1.json"):
        raise ValueError("Latency semantic/source qualification is stale")
    synchronization = {(system, cell["metric"]): cell for cell in latency["cells"] for system in cell["values_ns"]}
    from audit_esp32_isr_semantics import audit as audit_isr
    isr = audit_isr()
    if isr != read_json("esp32-isr-semantics-v1.json"):
        raise ValueError("ISR endpoint/source qualification is stale")
    isr_rows = {(system, cell["metric"]): cell for cell in isr["cells"] for system in cell["values_ns"]}
    rows = []
    for index, row in enumerate(data["rows"]):
        section, metric = row["section"], row["metric"]
        kind, label, reason, missing = "configured", "原生配置实测", "按本镜像的原操作和配置解释。", []
        if not row["measurement_eligible"]:
            kind, label, reason = "diagnostic", "诊断记录", row["status"]
        elif section == "tm" and metric == "basic_processing":
            kind, label, reason = "control", "计算对照", "CPU / 编译器对照，不是内核事件吞吐。"
        elif section == "tm" and (row["os"], metric) in admitted:
            kind, label, reason = "primary", "已验证可比", "B0 三系统、原消息/调度/IRQ 契约及配置已审计。"
        elif section == "hartstone" and row["os"] in PRIMARY:
            kind, label, reason = "capacity", "限定配置容量比较", "比较完整 C-port 镜像承载量，须结合原计算校准；不是纯调度器分。"
        elif section in ("tm", "hartstone"):
            reason = ("固定块池与变长堆分别报告。" if metric == "memory_allocation" else
                      "本机原生配置已测，不属于已审计的三系统控制组。")
            missing = (["匹配分配器家族、分配状态和原测量边界"] if metric == "memory_allocation" else
                       ["逐工作负载核查编译器、tick、后台服务及原生对象差异的影响"])
        elif section == "latency":
            lifecycle = metric.startswith("thread.") and ".yield." not in metric
            qualified = synchronization.get((row["os"], metric))
            if qualified is not None and row["extra"].get("cohort") in (
                    "separate_freertos_original_zephyr_latency_subset", "separate_nuttx_original_zephyr_latency_subset"):
                if row["values"] != qualified["values_ns"][row["os"]]:
                    raise ValueError("Latency snapshot differs from its source-bound capture")
                kind, label = "comparable", "同组原操作可比"
                reason = "B0 两系统、240 MHz / 单核 / 1 Hz / GCC13；原同步子集，包含各端适配成本。"
            elif (row["os"], metric) in isr_rows:
                cell = isr_rows[row["os"], metric]
                if row["values"] != cell["values_ns"][row["os"]] or row["extra"].get("cohort") not in (
                        "separate_original_zephyr_software_irq_subset", "separate_nuttx_original_zephyr_software_irq_subset"):
                    raise ValueError("Original ISR snapshot differs from its qualified boot evidence")
                kind, label, reason = "comparable", "同组原操作可比", "B0 两系统；ISR 内 give 后的时间戳至高优先级 take 返回，含适配成本，不含中断入口或 give 本身。"
            elif metric == isr["native_only"]["metric"] and row["os"] in isr["native_only"]["values_ns"]:
                if row["values"] != isr["native_only"]["values_ns"][row["os"]]:
                    raise ValueError("Native ISR return snapshot differs")
                label, reason = "原生 ISR 适配实测", "ISR 内时间戳至被中断线程继续；包含 irq_offload 返回检查，NuttX 另含轮询保护。"
                missing = ["若比较纯 ISR 返回成本，需匹配或独立限定返回后适配器检查的开销"]
            elif lifecycle:
                reason = "轻量线程、完整任务组和适配器生命周期不同，按实际路径单列。"
                missing = ["选择实际原操作与起止端点一致的子集；不把任务组创建改名为轻量线程创建"]
            else:
                kind, label = "pending", "可比性待核查"
                reason = "原值有效；尚无逐项跨 OS 的完整语义和计时准备核查。"
                missing = ["逐项确认原生对象、阻塞/唤醒语义、起止端点与适配器成本",
                           "确认原均值/单次样本、计时开销、初始化及 cache 条件"]
                native_checks = (
                    (("semaphore.", "semaphore #"), "核查初始/最大计数、阻塞者优先级、唤醒及确认端点"),
                    (("mutex.",), "核查递归层级、所有者和优先级继承配置；不是普通信号量互斥"),
                    (("events.",), "核查 wait-any/wait-all、事件位自动清除和唤醒后的确认路径"),
                    (("stack.", "stack #"), "核查 LIFO 顺序、元素宽度，以及队列复制适配与原生栈操作的边界"),
                    (("fifo.", "lifo.", "fifo #", "lifo #"), "核查侵入式节点所有权；alloc/free 是否进入计时，及阻塞唤醒路径"),
                    (("heap.", "memslab #"), "区分固定块池与变长堆，核查块大小、堆初态和分配/释放边界"),
                    (("condvar.",), "核查互斥锁释放/重新获取、通知与确认协议及计时端点"),
                    (("isr.", "ilatency", "no-parameter", "parameter"), "核查触发源/级别、被中断任务与唤醒任务，起点是否已在 ISR 内"),
                    (("thread.yield.",), "核查线程优先级、让出/抢占路径和实际切换的确认端点"),
                )
                for prefixes, check in native_checks:
                    if metric.lower().startswith(prefixes):
                        missing[0] = check
                        break
                if row["suite"] == "Zephyr sys_kernel":
                    missing += ["复核整个多调用迭代与线程创建/退出的边界；不解释为孤立 API 延迟"]
        elif section == "resources":
            reason = "对应固件的字节计量或限定窗口占用；栈/堆预留、线程数及观察器不同。"
            missing = ["同工作负载和任务数量下的资源配置与计量范围核查"]
            if "RAM" in metric:
                missing += ["区分已分配量与 live 使用量；补齐所声明生命周期的堆与栈证据"]
        elif section == "energy":
            label, reason = "整板能耗实测", "B0 同轮能量与完成计数配对；未与 B1 或吞吐重复合成总分。"
            missing = ["小差距的仪表/供电/计时不确定度；睡眠能耗尚未测量"]
        elif section == "network":
            reason = "核数、RF、AP、栈及负载不同；固定发送负载不等于最大吞吐。"
            missing = ["对齐核数、方向、RF/AP、缓冲区及接收统计，并按原方法复测"]
        elif section == "native":
            reason = "该 OS 的原生补充程序，未与别的套件同名操作混排。"
            missing = ["需要跨 OS 比较时，先复用同一原程序并核查端点与原生对象"]
        record = {"row": index, "kind": kind, "label": label, "reason": reason, "missing": missing}
        if section == "latency" and metric.startswith("isr.resume"):
            record["measurement_scope"] = ("ISR 内 give 后时间戳 → 高优先级阻塞 take 返回；不含入口及 give"
                if ".different." in metric else "ISR 内时间戳 → irq_offload 返回；含返回后的适配器检查，无 give")
            record["description_override"] = "Zephyr 原 ISR 返回测试及原均值。原生适配层成本保留，不是线程创建/退出测试，不是外部 GPIO 中断入口延迟。"
        rows.append(record)

    completed, ram_states = {}, {}
    if followup:
        for group in followup["collections"]:
            if group["mode"] == "candidates":
                completed.update((r["original"], r) for r in group["result"]["cells"])
            elif group["mode"] == "ram":
                ram_states.update((r["os"], r) for r in group["result"]["cells"])
    candidates = []
    for item in data["pending_builds"]:
        field = item["field"]
        if "hartstone" in field:
            observation = ram_states.get(item["os"])
            measured = observation is not None
            state = ("已采集；完整生命周期证据待补" if measured else "已构建；待完整实板采集")
            need = "补齐 live 栈、启动前与内部瞬态；NuttX 另缺参考工作线程覆盖" if measured else item["boundary"]
        else:
            kind = "yield" if "_yield_" in field else "flags" if "_flags_" in field else "msg"
            system = {"FreeRTOS": "freertos", "Zephyr": "zephyr", "NuttX": "nuttx", "AliOS-Rhino": "alios"}[item["os"]]
            measured = any(name.startswith("riot-" + kind + "-" + system + "-") for name in completed)
            state = "B1 三次重启已完成；语义待核查" if measured else "已构建；启动/实测待完成"
            need = "核查原生对象、消息/事件及线程退役端点，不因完成采集自动加入排名" if measured else item["boundary"]
            if measured and system == "alios" and kind in ("yield", "flags"):
                state = "B1 三次重启、原程序及原生端点核查通过；配置单列"
                need = "GCC5 / 1 Hz FIFO；原生让出调度" if kind == "yield" else "GCC5 / 1 Hz FIFO；原生事件适配，阻塞/标志清除及线程退役已核查"
                need += "；与主组编译器及对象路径不同，仍不混排"
        candidates.append({"os": item["os"], "benchmark": item["benchmark"], "state": state,
                           "missing": need, "measured_on_b1": measured, "field": field})
    message = None
    message_path = EVIDENCE / "esp32-message-cohort-b1-v1"
    if (message_path / "audit.json").exists():
        from run_esp32_b1_message import audit as audit_message
        from replay_esp32_followup import replay
        message = audit_message(message_path)
        if message != read_json("esp32-message-cohort-b1-v1/audit.json"):
            raise ValueError("B1 message result differs from source-bound replay")
        separate = replay(message_path)
        if {r["os"]:r["values"] for r in message["cells"]} != {r["os"]:r["values"] for r in separate["cells"]}:
            raise ValueError("B1 message counts differ in separate arithmetic implementation")
    from run_esp32_b1_message import CASES, audit as audit_kernel, audit_failed_cooperative
    from replay_esp32_followup import replay
    groups = []
    for case in CASES:
        if case == "message_processing":
            continue
        for version in (3, 2, 1):
            name = "esp32-" + case + "-cohort-b1-v" + str(version)
            folder = EVIDENCE / name
            if not (folder / "audit.json").exists() or read_json(name + "/audit.json").get("result") == "original_correctness_failure":
                continue
            result = audit_kernel(folder)
            if result != read_json(name + "/audit.json"):
                raise ValueError("B1 kernel source-bound audit differs")
            separate = replay(folder)
            if {r["os"]:r["values"] for r in separate["cells"]} != {r["os"]:r["values"] for r in result["cells"]}:
                raise ValueError("B1 kernel independent count replay differs")
            groups.append({"evidence": "artifacts/reports/" + name, **result})
            break
    failure_path = EVIDENCE / "esp32-cooperative_scheduling-cohort-b1-v1"
    failed = None
    if (failure_path / "audit.json").exists():
        failed = audit_failed_cooperative(failure_path)
        if failed != read_json("esp32-cooperative_scheduling-cohort-b1-v1/audit.json"):
            raise ValueError("Retained cooperative failure report differs from raw replay")
    kernel = {"groups": groups, "complete_three_os_cases": (1 if message else 0) + sum(len(g["cells"]) == 3 for g in groups),
              "independent_resets": (9 if message else 0) + sum(g["independent_resets"] for g in groups),
              "failed_cooperative": failed, "six_case_index": None}
    from audit_esp32_rhino_gcc13 import build as rhino_build
    from audit_esp32_nuttx_heap_events import build as ram_build
    from run_esp32_network_controlled import configuration
    rhino = rhino_build(EVIDENCE / "esp32-rhino-gcc13-legacy-v1")
    ram_events = ram_build(EVIDENCE / "esp32-nuttx-heap-events-v1")
    from audit_esp32_rhino_gcc13 import audit as audit_rhino
    from audit_esp32_riot_startup import audit as audit_riot
    from audit_esp32_nuttx_heap_events import audit as audit_ram_events
    from audit_esp32_network_controlled import audit as audit_network
    alignment, lifecycle, network, native_suite, udp_network, irq_semantics = [], None, None, None, None, None
    freertos_lifecycle = None
    zephyr_lifecycle = None
    riot_lifecycle = None
    rhino_lifecycle = None
    native_riot_message = None
    nuttx_riot_message = None
    rhino_riot_message = None
    rhino_stack_coverage = None
    freertos_stack_coverage = None
    riot_stack_coverage = None
    zephyr_stack_coverage = None
    ram_scope = None
    b1_energy = None
    b1_kernel_energy = []
    energy_name = "esp32-message-energy-b1-v1"
    if (EVIDENCE/energy_name/"audit.json").exists():
        from audit_esp32_b1_controlled_energy import audit as audit_b1_energy
        from audit_esp32_b1_native_energy import equal_observation
        from replay_esp32_b1_energy import replay as replay_b1_energy
        from audit_esp32_tm_energy import comparison_order
        result = audit_b1_energy(EVIDENCE/energy_name)
        if not equal_observation({k:v for k,v in result.items() if k not in ("numeric_validation", "validator_sha256")}, read_json(energy_name+"/audit.json")):
            raise ValueError("B1 source-bound same-window energy audit differs")
        separate = replay_b1_energy(EVIDENCE/energy_name)
        for primary, independent in zip(result["cells"],separate["cells"]):
            if primary["os"] != independent["os"] or any(abs(primary["medians"][k]-independent["medians"][k]) > 1e-8 for k in independent["medians"]):
                raise ValueError("Independent B1 same-window energy arithmetic differs")
        group = []
        for cell in result["cells"]:
            values = [r["paired"]["joules_per_original_count"] for r in cell["runs"]]
            group.append({"os":cell["os"],"medians":{"joules_per_original_count":statistics.median(values)},
                "ranges":{"joules_per_original_count":[min(values),max(values)]},
                "runs":[{"reset":i,**r["paired"]} for i,r in enumerate(cell["runs"],1)]})
        b1_energy = {"evidence":"artifacts/reports/"+energy_name,**result,
                     "observed_order":comparison_order("message_processing",group)}
    from run_esp32_b1_kernel_energy import BASELINES as energy_cases
    from audit_esp32_b1_controlled_energy import audit as audit_kernel_energy
    from audit_esp32_b1_native_energy import equal_observation
    from replay_esp32_b1_energy import replay as replay_kernel_energy
    from audit_esp32_tm_energy import comparison_order
    for case in energy_cases:
        energy_name = "esp32-"+case+"-energy-b1-v1"
        folder = EVIDENCE/energy_name
        if not (folder/"audit.json").exists():
            continue
        result = audit_kernel_energy(folder)
        if not equal_observation({k:v for k,v in result.items() if k not in ("numeric_validation", "validator_sha256")}, read_json(energy_name+"/audit.json")):
            raise ValueError("B1 original kernel-workload energy audit differs")
        separate = replay_kernel_energy(folder)
        if len(result["cells"])!=len(separate["cells"]) or any(
                a["os"]!=b["os"] or any(abs(a["medians"][k]-b["medians"][k])>1e-8 for k in b["medians"])
                for a,b in zip(result["cells"],separate["cells"])):
            raise ValueError("Independent B1 kernel-workload energy arithmetic differs")
        group = []
        for cell in result["cells"]:
            values = [r["paired"]["joules_per_original_count"] for r in cell["runs"]]
            group.append({"os":cell["os"],"medians":{"joules_per_original_count":statistics.median(values)},
                "ranges":{"joules_per_original_count":[min(values),max(values)]},
                "runs":[{"reset":i,**r["paired"]} for i,r in enumerate(cell["runs"],1)]})
        b1_kernel_energy.append({"evidence":"artifacts/reports/"+energy_name,**result,
            "observed_order":comparison_order(case,group)})
    for system, name, source, audit_alignment, condition in (
        ("AliOS-Rhino", "esp32-rhino-gcc13-b1-v1", "esp32-rhino-gcc13-legacy-v1", audit_rhino,
         "240 MHz / 单核 / 100 Hz / GCC13；旧版 SDK libc"),
        ("RIOT", "esp32-riot-gcc13-legacy-b1-v1", "esp32-riot-gcc13-legacy-v1",
         lambda capture, source: audit_riot(capture, source, False),
         "240 MHz / 单核 / 原生 tickless / GCC13；GCC12 兼容头文件，C 库按镜像核对")):
        folder = EVIDENCE / name
        if (folder / "audit.json").exists():
            result = audit_alignment(folder, EVIDENCE / source)
            if result != read_json(name + "/audit.json"):
                raise ValueError("Native alignment audit differs")
            if result.get("independent_resets") == 3:
                alignment.append({"os": system, "result": result, "profile": condition,
                                  "evidence": "artifacts/reports/" + name})
    name = "esp32-nuttx-heap-events-b1-v2"
    ram_source = "esp32-nuttx-heap-events-v1"
    if (EVIDENCE / "esp32-nuttx-stack-lifetimes-b1-v1/audit.json").exists():
        name, ram_source = "esp32-nuttx-stack-lifetimes-b1-v1", "esp32-nuttx-stack-lifetimes-v2"
    if (EVIDENCE / "esp32-nuttx-task-cleanup-b1-v2/audit.json").exists():
        name, ram_source = "esp32-nuttx-task-cleanup-b1-v2", "esp32-nuttx-task-cleanup-v2"
    if (EVIDENCE / "esp32-nuttx-retained-owners-b1-v1/audit.json").exists():
        name, ram_source = "esp32-nuttx-retained-owners-b1-v1", "esp32-nuttx-retained-owners-v1"
    if (EVIDENCE / name / "audit.json").exists():
        lifecycle = json.loads(json.dumps(audit_ram_events(EVIDENCE / name, EVIDENCE / ram_source)))
        if lifecycle != read_json(name + "/audit.json"):
            raise ValueError("Native RAM lifetime replay differs")
        lifecycle = {"evidence": "artifacts/reports/" + name, **lifecycle}
    freertos_name = "esp32-freertos-lifetimes-b1-v1"
    if (EVIDENCE / freertos_name / "audit.json").exists():
        from audit_esp32_freertos_ram_lifetimes import audit as audit_freertos_lifetimes
        freertos_lifecycle = json.loads(json.dumps(audit_freertos_lifetimes(
            EVIDENCE / freertos_name, EVIDENCE / "esp32-freertos-lifetimes-v4")))
        if freertos_lifecycle != read_json(freertos_name + "/audit.json"):
            raise ValueError("Native FreeRTOS allocation/task lifecycle audit differs")
        freertos_lifecycle = {"evidence": "artifacts/reports/" + freertos_name, **freertos_lifecycle}
    freertos_stack_name = "esp32-freertos-stack-coverage-b1-v1"
    if (EVIDENCE/freertos_stack_name/"audit.json").exists():
        from audit_esp32_freertos_stack_coverage import audit as audit_freertos_stack
        from replay_esp32_followup import replay as replay_freertos_stack
        result = audit_freertos_stack(EVIDENCE/freertos_stack_name,EVIDENCE/"esp32-freertos-stack-coverage-v1")
        if result != read_json(freertos_stack_name+"/audit.json"):
            raise ValueError("FreeRTOS ordinary IRQ stack audit differs")
        separate = replay_freertos_stack(EVIDENCE/freertos_stack_name)["cells"][0]
        if [r["touched"] for r in separate["ordinary_irq_stack"]] != [r["touched_watermark_bytes"] for r in result["ordinary_irq_stack_runs"]]:
            raise ValueError("Independent FreeRTOS ordinary IRQ watermark replay differs")
        freertos_stack_coverage = {"evidence":"artifacts/reports/"+freertos_stack_name,**result}
    zephyr_name = "esp32-zephyr-lifetimes-b1-v1"
    if (EVIDENCE / zephyr_name / "audit.json").exists():
        from audit_esp32_zephyr_ram_lifetimes import audit as audit_zephyr_lifetimes
        zephyr_lifecycle = audit_zephyr_lifetimes(EVIDENCE / zephyr_name, EVIDENCE / "esp32-zephyr-lifetimes-v4")
        if zephyr_lifecycle != read_json(zephyr_name + "/audit.json"):
            raise ValueError("Native Zephyr static-resource lifecycle audit differs")
        zephyr_lifecycle = {"evidence":"artifacts/reports/" + zephyr_name, **zephyr_lifecycle}
    riot_name = "esp32-riot-lifetimes-b1-v2"
    zephyr_stack_name = "esp32-zephyr-stack-coverage-b1-v1"
    if (EVIDENCE/zephyr_stack_name/"audit.json").exists():
        from audit_esp32_zephyr_stack_coverage import audit as audit_zephyr_stack
        from replay_esp32_followup import replay as replay_zephyr_stack
        result = audit_zephyr_stack(EVIDENCE/zephyr_stack_name,EVIDENCE/"esp32-zephyr-stack-coverage-v1")
        if result != read_json(zephyr_stack_name+"/audit.json"):
            raise ValueError("Zephyr native initial-fill/idle/IRQ audit differs")
        separate = replay_zephyr_stack(EVIDENCE/zephyr_stack_name)["cells"][0]
        if separate["stack_coverage"] != [{k:r[k] for k in ("ordinary_irq_stack","current_idle_stack")} for r in result["native_stack_runs"]]:
            raise ValueError("Independent Zephyr native stack replay differs")
        zephyr_stack_coverage = {"evidence":"artifacts/reports/"+zephyr_stack_name,**result}
    if (EVIDENCE / riot_name / "audit.json").exists():
        from audit_esp32_riot_ram_lifetimes import audit as audit_riot_lifetimes
        riot_lifecycle = audit_riot_lifetimes(EVIDENCE / riot_name, EVIDENCE / "esp32-riot-lifetimes-v7")
        if riot_lifecycle != read_json(riot_name + "/audit.json"):
            raise ValueError("Native RIOT allocator/retained-worker lifecycle audit differs")
        riot_lifecycle = {"evidence":"artifacts/reports/" + riot_name, **riot_lifecycle}
    rhino_name = "esp32-rhino-lifetimes-b1-v3"
    riot_stack_name = "esp32-riot-stack-coverage-b1-v1"
    if (EVIDENCE/riot_stack_name/"audit.json").exists():
        from audit_esp32_riot_stack_coverage import audit as audit_riot_stack
        from replay_esp32_followup import replay as replay_riot_stack
        result = audit_riot_stack(EVIDENCE/riot_stack_name,EVIDENCE/"esp32-riot-stack-coverage-v1")
        if result != read_json(riot_stack_name+"/audit.json"):
            raise ValueError("RIOT native idle/IRQ stack audit differs")
        separate = replay_riot_stack(EVIDENCE/riot_stack_name)["cells"][0]
        if separate["stack_coverage"] != [{k:r[k] for k in ("ordinary_irq_stack","current_idle_stack")} for r in result["native_stack_runs"]]:
            raise ValueError("Independent RIOT native stack replay differs")
        riot_stack_coverage = {"evidence":"artifacts/reports/"+riot_stack_name,**result}
    if (EVIDENCE / rhino_name / "audit.json").exists():
        from audit_esp32_rhino_ram_lifetimes import audit as audit_rhino_lifetimes
        rhino_lifecycle = audit_rhino_lifetimes(EVIDENCE / rhino_name, EVIDENCE / "esp32-rhino-lifetimes-v4")
        if rhino_lifecycle != read_json(rhino_name + "/audit.json"):
            raise ValueError("Native Rhino heap/task/timer lifecycle audit differs")
        rhino_lifecycle = {"evidence":"artifacts/reports/" + rhino_name, **rhino_lifecycle}
    rhino_stack_name = "esp32-rhino-stack-coverage-b1-v2"
    if (EVIDENCE / rhino_stack_name / "audit.json").exists():
        from audit_esp32_rhino_stack_coverage import audit as audit_rhino_stack
        from replay_esp32_followup import replay as replay_rhino_stack
        rhino_stack_coverage = audit_rhino_stack(EVIDENCE / rhino_stack_name, EVIDENCE / "esp32-rhino-stack-coverage-v1")
        if rhino_stack_coverage != read_json(rhino_stack_name + "/audit.json"):
            raise ValueError("Rhino extended stack coverage audit differs")
        separate = replay_rhino_stack(EVIDENCE / rhino_stack_name)["cells"][0]
        if separate["stack_coverage"] != [r["stack_coverage"] for r in rhino_stack_coverage["runs"]]:
            raise ValueError("Rhino extended stack independent byte/watermark replay differs")
        rhino_stack_coverage = {"evidence":"artifacts/reports/" + rhino_stack_name, **rhino_stack_coverage}
    native_message_name = "esp32-riot-native-message-b1-v1"
    if (EVIDENCE / native_message_name / "audit.json").exists():
        from audit_esp32_riot_native_message import audit as audit_native_message
        native_riot_message = audit_native_message(EVIDENCE / native_message_name, EVIDENCE / "esp32-riot-native-message-v3")
        if native_riot_message != read_json(native_message_name + "/audit.json"):
            raise ValueError("Native RIOT message control audit differs")
        native_riot_message = {"evidence":"artifacts/reports/" + native_message_name, **native_riot_message}
    nuttx_message_name = "esp32-riot-msg-nuttx-b1-v2"
    if (EVIDENCE / nuttx_message_name / "audit.json").exists():
        from audit_esp32_riot_msg_nuttx import audit as audit_nuttx_message
        from replay_esp32_followup import replay as replay_nuttx_message
        nuttx_riot_message = audit_nuttx_message(EVIDENCE / nuttx_message_name, EVIDENCE / "riot-msg-nuttx-v1")
        if nuttx_riot_message != read_json(nuttx_message_name + "/audit.json"):
            raise ValueError("NuttX original RIOT message port audit differs")
        separate = replay_nuttx_message(EVIDENCE / nuttx_message_name)
        if separate["cells"][0]["values"] != nuttx_riot_message["original_counts"]:
            raise ValueError("NuttX original message independent count replay differs")
        nuttx_riot_message = {"evidence":"artifacts/reports/" + nuttx_message_name, **nuttx_riot_message}
        candidates.append({"os":"NuttX", "benchmark":"RIOT msg_pingpong original program / native NuttX MQ adapter",
            "state":"B1 三次独立复位完成；原程序与资源退役核查通过", "measured_on_b1":True,
            "field":"separate_original_riot_msg_nuttx_build",
            "missing":"原生双复制 MQ 单列；原发送交接计数不作单次延迟或载荷完整性证据，不混入 100 Hz 主组"})
    rhino_message_name = "esp32-riot-msg-alios-b1-v2"
    if (EVIDENCE / rhino_message_name / "audit.json").exists():
        from audit_esp32_riot_msg_alios import audit as audit_rhino_message
        from replay_esp32_followup import replay as replay_rhino_message
        rhino_riot_message = audit_rhino_message(EVIDENCE / rhino_message_name, EVIDENCE / "riot-msg-alios-v2")
        if rhino_riot_message != read_json(rhino_message_name + "/audit.json"):
            raise ValueError("Rhino original RIOT message port audit differs")
        separate = replay_rhino_message(EVIDENCE / rhino_message_name)
        if separate["cells"][0]["values"] != rhino_riot_message["original_counts"] or separate["cells"][0]["native_buffered_peaks"] != [0]*3:
            raise ValueError("Rhino original message independent count/path replay differs")
        rhino_riot_message = {"evidence":"artifacts/reports/" + rhino_message_name, **rhino_riot_message}
        candidates.append({"os":"AliOS-Rhino", "benchmark":"RIOT msg_pingpong original program / native Rhino queue adapter",
            "state":"B1 三次独立复位完成；原程序及原生直交接路径核查通过", "measured_on_b1":True,
            "field":"separate_original_riot_msg_alios_build",
            "missing":"高优先级单接收者限定；满队列发送不支持通用阻塞。原生 1 Hz 配置单列，不作载荷完整性或单次延迟证据"})
    name = "esp32-network-controlled-b1-v6"
    if (EVIDENCE / name / "audit.json").exists() and read_json(name + "/audit.json").get("independent_resets") == 18:
        network = audit_network(EVIDENCE / name)
        if network != read_json(name + "/audit.json"):
            raise ValueError("Controlled original TCP replay differs")
        network = {"evidence": "artifacts/reports/" + name, **network}
    udp_name = "esp32-network-udp-controlled-b1-v1"
    if (EVIDENCE / udp_name / "audit.json").exists():
        udp_network = audit_network(EVIDENCE / udp_name)
        if not same_published_evidence(udp_network, read_json(udp_name + "/audit.json")):
            raise ValueError("Controlled original UDP replay differs")
        udp_network = {"evidence": "artifacts/reports/" + udp_name, **udp_network}
    for system, folder in (("FreeRTOS", "idf"), ("Zephyr", "zephyr"), ("NuttX", "nuttx")):
        configuration(system, EVIDENCE / ("esp32-network-controlled-" + folder + ("-v2" if system == "NuttX" else "-v1")))
    progress = [
        {"name": "RIOT / GCC13", "state": "实板已定位到 syscalls_init；使用 GCC12 兼容头文件的 GCC13 候选已构建",
         "missing": "兼容库候选的三次原测试复位；原 tickless 配置保留，不能改标签冒充 100 Hz"},
        {"name": "Rhino / GCC13", "state": str(rhino["source_compiled_units"]) + " 个源码单元编译及链接通过；" +
         ("消息原测试已完成 B1 三次独立复位" if any(r["os"] == "AliOS-Rhino" for r in alignment) else "待完成实板重复"),
         "missing": "后台线程/软件定时器活动证据；其余七项 GCC13 原测试实测。SDK / C 库版本保留，尚非全 SDK 二进制重建"},
        {"name": "NuttX RAM 生命周期", "state": str(ram_events["native_event_sites"]) + " 个原生事件点、栈创建/释放及染色观察器已链接",
         "missing": "同一镜像先验证分配器账本，再跑完整 PH4；栈高水位不等于同时 live 栈峰值"},
        {"name": "受控网络", "state": "三系统已构建：240 MHz / 单核 / 100 Hz / GCC13，Wi-Fi 缓冲 10/32/32",
         "missing": "原 TCP 程序同板独立重启、固定链路及双端汇总；zperf 的块长/yield 差异仍须单列"},
        {"name": "NuttX / RIOT msg_pingpong", "state": "尚无可采集候选",
         "missing": "原程序的消息复制、容量、阻塞和线程退役适配，之后构建及实测"},
    ]
    if any(r["os"] == "RIOT" for r in alignment):
        progress[0].update(state="使用 GCC12 兼容头文件的 GCC13 消息候选已完成三次独立复位",
                           missing="保留原生 tickless 配置轨；若并入现 100 Hz 控制轨须核查计时政策。其余七项 GCC13 实测未完成")
    suite_builds = EVIDENCE / "esp32-native-suite-builds-v1.json"
    if suite_builds.exists():
        from audit_esp32_native_suite_builds import audit as audit_suite_builds
        built = audit_suite_builds()
        if built != read_json(suite_builds.name):
            raise ValueError("Native remaining-suite build audit differs")
        for index in (0, 1):
            progress[index]["state"] += "；其余七项 GCC13 ELF/BIN 已构建并核查（尚未实测）"
    for native_name in ("esp32-native-irq-suite-b1-v1", "esp32-native-task-suite-b1-v1"):
        if not (EVIDENCE / native_name / "audit.json").exists():
            continue
        from audit_esp32_native_suite_builds import audit_campaign
        current = audit_campaign(EVIDENCE / native_name)
        if current != read_json(native_name + "/audit.json"):
            raise ValueError("Native original-suite acquisition replay differs")
        current = {"evidence": "artifacts/reports/" + native_name, **current}
        if native_suite is None:
            native_suite = {**current, "campaigns": []}
        else:
            if {(r["os"], r["case"]) for r in native_suite["cells"]} & {(r["os"], r["case"]) for r in current["cells"]}:
                raise ValueError("Repeated native cells would be counted twice")
            native_suite["cells"] += current["cells"]
            native_suite["independent_resets"] += current["independent_resets"]
        native_suite["campaigns"].append({"evidence": current["evidence"], "independent_resets": current["independent_resets"]})
    if native_suite:
        for index, system in enumerate(("RIOT", "AliOS-Rhino")):
            measured = [c for c in native_suite["cells"] if c["os"] == system]
            progress[index]["state"] = progress[index]["state"].replace("（尚未实测）", "") + \
                "；新增 " + str(len(measured)) + " 项原测试已完成各三次独立复位"
            progress[index]["missing"] = ("其余 " + str(7 - len(measured)) + " 项 GCC13 原测试实测；" if len(measured) < 7 else
                "八项原测试均已实测；仍需核查 ") + \
                ("原生 tickless 计时契约仍单列" if system == "RIOT" else "后台线程/软件定时器活动及旧 SDK/C 库边界")
    irq_name = "esp32-native-irq-semantics-b1-v1"
    if (EVIDENCE / irq_name / "audit.json").exists():
        from audit_esp32_native_irq_semantics import audit as audit_native_irq
        irq_semantics = audit_native_irq()
        if irq_semantics != read_json(irq_name + "/audit.json"):
            raise ValueError("Native IRQ semantic evidence changed")
        irq_semantics = {"evidence": "artifacts/reports/" + irq_name, **irq_semantics}
    if lifecycle:
        progress[2].update(state="原生分配器验证 + 三次完整 PH4；栈创建/退役/存活账本复核通过",
                           missing="参考线程覆盖状态见 RAM 实测；尚非全部 OS 的同时 live 栈峰值，整机 RAM 仍在测")
        if lifecycle["build"].get("stack_lifetime_extension"):
            progress[2]["state"] += "；已补栈块归属、不重叠及 idle/IRQ 栈计量范围"
            if lifecycle["build"].get("task_cleanup_extension"):
                progress[2]["state"] += "；已跟踪至父进程等待结束、控制任务释放及原生延迟回收"
                if lifecycle["build"].get("retained_owners_extension"):
                    progress[2]["state"] += "；退出后 PID 表与待删除定时器的块归属、队列及增量账本已核对"
                progress[2]["missing"] += "；其他 OS 的同范围生命周期和完整整机 RAM 仍待闭合"
            else:
                progress[2]["missing"] += "；当前止于原序列返回，退出后的资源收尾与其余 OS 同范围证据仍待补齐"
    if network:
        progress[3].update(state="三系统双向 TCP、18 次独立复位及双端汇总已完成",
                           missing="因中断分批续测；包含 66.3 s 延长连接，尚非统一等时窗口。块长/yield、TCP/RF 栈及实验室空口差异保留，不作纯 OS 网络排名")
        if udp_network:
            progress[3]["state"] += "；另完成 18 次原 UDP 复位"
            progress[3]["missing"] += "；UDP 无原生最终握手的统计不补造，NuttX 无节流发送与固定发送率分列"
    elif (EVIDENCE / name / "campaign.json").exists():
        progress[3].update(state="已保留并审计 10 段有效原测试；补测遇 USB 重枚举，未产生新成绩",
                           missing="固定连接后补齐四个 OS-轮次的双向与双端汇总；原固件已校验恢复")
    if freertos_lifecycle:
        progress.append({"name":"FreeRTOS RAM 生命周期",
            "state":"原生堆注册起全程记账；同镜像分配器自检及三次完整 PH4；工作线程与 main 的实际块释放、原控制任务保留均已核对",
            "missing":"Zephyr、RIOT、Rhino 的同范围生命周期、各系统同时 live 栈和统一整机范围仍待闭合；整机 RAM 正在测，未加入评分"})
    if zephyr_lifecycle:
        for item in progress:
            if item["name"]=="FreeRTOS RAM 生命周期":
                item["missing"] = item["missing"].replace("Zephyr、RIOT、Rhino","RIOT、Rhino")
        progress.append({"name":"Zephyr RAM 生命周期",
            "state":"同镜像原生堆自检和三次完整 PH4；静态栈/TCB 逐代复用、全部工作线程 join、main 退出后由现有 idle 确认",
            "missing":"RIOT、Rhino 的同范围生命周期；固定预留与动态使用口径、各系统同时 live 栈及整机范围尚未统一，未加入评分"})
    if riot_lifecycle:
        for item in progress:
            if item["name"] in ("FreeRTOS RAM 生命周期","Zephyr RAM 生命周期"):
                item["missing"] = item["missing"].replace("RIOT、Rhino","Rhino")
        progress.append({"name":"RIOT RAM 生命周期",
            "state":"原生四段堆记账与移动 realloc 瞬态自检；三次完整 PH4；全部原工作线程、嵌入式 TCB/栈与原等待队列逐项核对，main 退出由现有 idle 确认",
            "missing":"Rhino 同范围生命周期；各系统同时 live 栈、固定预留与动态使用及整机范围仍待闭合，整机 RAM 正在测、未加入评分"})
    if rhino_lifecycle:
        for item in progress:
            if "RAM 生命周期" in item["name"]:
                item["missing"]="各系统同时 live 栈、固定预留与动态使用及整机范围仍待闭合；整机 RAM 正在测，未加入评分"
        progress.append({"name":"Rhino RAM 生命周期",
            "state":"初始化完成起的原生堆逐块核对、小块池空闲量及移动 realloc 自检；三次完整 PH4；工作线程/定时器保留、实际挂起控制线程由现有 idle 确认",
            "missing":"观察器与旧 SDK/C 库边界保留；当前 idle 高水位及跨系统统一整机范围仍待闭合，未加入评分"})
    if native_riot_message:
        progress.append({"name":"RIOT 原生 msg_pingpong · B1 对照",
            "state":"原程序、原一秒计数和原 tickless 配置；GCC13 原生 stdatomic 修复头文件冲突，完成三次独立复位",
            "missing":"这是原系统对照，不替代其他 OS 的移植，不是单次 IPC 延迟，不混入 100 Hz 主组"})
    if nuttx_riot_message:
        for item in progress:
            if item["name"] == "NuttX / RIOT msg_pingpong":
                item.update(state="已完成原程序适配、39 份固定源码核查及三次独立复位；原生 MQ、接收线程和计时器退役核查通过",
                    missing="原生双复制路径单列，不将一秒计数换称单次延迟")
    if rhino_riot_message:
        progress.append({"name":"Rhino / RIOT msg_pingpong",
            "state":"36 份固定输入、38 个机器路径函数及三次独立复位核查通过；原生队列缓冲峰值为零，接收线程/队列及 IRQ 退役完成",
            "missing":"保留旧 SDK/C 库与 1 Hz 原生配置；只覆盖高优先级接收者原程序，不宣称通用阻塞队列 API 或载荷完整性"})
    if rhino_stack_coverage:
        for item in progress:
            if item["name"] == "Rhino RAM 生命周期":
                item["missing"] = "原镜像保留；新观察镜像已另补启动退役、idle 与普通 IRQ 栈水位。观察器影响和跨系统同时 live 整机范围仍未闭合，未加入评分"
        progress.append({"name":"Rhino 启动 / idle / 普通 IRQ 栈补测",
            "state":"三次完整原 PH4；删除前原生栈水位、当前 idle 水位及调度器启动前 IRQ 染色核查通过；全部原栈容量保留",
            "missing":"染色触达水位不是精确同时 live 峰值，不覆盖 NMI/debug/ROM 栈，不累加各栈历史峰值；整机 RAM 正在测、未加入评分"})
    if riot_stack_coverage:
        progress.append({"name":"RIOT idle / 普通 IRQ 栈补测",
            "state":"原生地址标记法；三次完整原 PH4；启动前全栈填充验证、main 退出后的当前 idle 和普通 IRQ 水位均核对通过，原栈容量不改",
            "missing":"不累加历史水位；仍缺跨系统同时 live 整机范围及观察器影响闭合，整机 RAM 正在测、未加入评分"})
    if zephyr_stack_coverage:
        progress.append({"name":"Zephyr idle / 普通 IRQ 栈补测",
            "state":"三次完整原 PH4；沿用原生填充，核对首次使用前全栈标记和 main 退出后当前 idle/普通 IRQ 水位，原容量保留",
            "missing":"观察器影响、统一工作规模和同时 live 整机范围仍未闭合，整机 RAM 正在测、未加入评分"})
    if (EVIDENCE/"esp32-ram-scope-v1.json").exists():
        from audit_esp32_ram_scope import audit as audit_ram_scope
        ram_scope = audit_ram_scope()
        if ram_scope != read_json("esp32-ram-scope-v1.json"):
            raise ValueError("Unified native RAM address/allocator accounting differs")
        ram_scope = {"evidence":"artifacts/reports/esp32-ram-scope-v1.json",**ram_scope}
    message_ram = None
    observer_pairs = None
    pairs_name = "esp32-message-observer-pairs-b1-v1"
    if (EVIDENCE/pairs_name/"audit.json").exists():
        from run_esp32_message_observer_pairs import audit as audit_observer_pairs
        observer_pairs = audit_observer_pairs(EVIDENCE/pairs_name)
        if observer_pairs != read_json(pairs_name+"/audit.json"):
            raise ValueError("Paired observer impact differs from source-bound replay")
        independent = replay(EVIDENCE/pairs_name)
        if independent["independent_resets"] != 30 or independent["cells"] != [
                {k:c[k] for k in ("os", "pairs", "median_ratio", "ratio_range")}
                for c in observer_pairs["cells"]]:
            raise ValueError("Paired observer impact differs in separate arithmetic replay")
        observer_pairs = {"evidence":"artifacts/reports/"+pairs_name+"/audit.json",**observer_pairs}
    if (EVIDENCE/"esp32-message-ram-lifetimes-cohort-v1.json").exists():
        from audit_esp32_message_ram_cohort import audit as audit_message_ram
        message_ram = audit_message_ram()
        if message_ram != read_json("esp32-message-ram-lifetimes-cohort-v1.json"):
            raise ValueError("Matched original message RAM evidence differs")
        message_ram = {"evidence":"artifacts/reports/esp32-message-ram-lifetimes-cohort-v1.json",**message_ram}
        progress.append({"name":"三 OS 同原消息任务 RAM 生命周期",
            "state":"FreeRTOS、Zephyr、NuttX 各五次独立复位；原始事件、配置、ELF/BIN、栈归属和完整固件恢复核查通过",
            "missing":("" if observer_pairs else "观察开销成对实验、")+"早期启动及未管理范围、精确同时 live 栈仍待闭合；整机 RAM 正在测，不计分"})
        finite=message_ram.get("followup_validation",{}).get("finite_task_lifecycles",[])
        complete=[r for r in finite if r["status"]=="complete"]
        if complete:
            progress.append({"name":"受控三系统有限任务生命周期验证",
                "state":"、".join(r["os"] for r in complete)+"：各五次独立复位，共 "+str(sum(r["completed_lifetimes"] for r in complete))+" 个有限周期；核对原生退出、join/回收与地址复用",
                "missing":"这是测量工具验证，不是原测试峰值；静态预留不因退出而扣除。整机 RAM 仍正在测，不计分"})
        inventory=message_ram.get("followup_validation",{}).get("native_memory_inventory",{})
        if inventory.get("status")=="complete":
            progress.append({"name":"FreeRTOS 原生内存区域核对",
                "state":"已测固件的原生区域、完整保留表与全部六个堆池在五轮原始记录中一致；复用旧采集",
                "missing":"堆池清单已闭合；ROM/cache/RTC 实际占用、早期启动和连续同时刻栈峰值仍需证据。整机 RAM 仍正在测，不计分"})
    if observer_pairs:
        progress.append({"name":"同消息 RAM 观察扰动成对实验",
            "state":"三 OS 各五对，共 30 次独立复位；轮换 OS 与 A/B 顺序，原计数、观察事件和完整 Flash 恢复通过重放",
            "missing":"报告完整观察镜像效应，含代码布局；不等于孤立 hook 成本、零扰动或无观察器 RAM 峰值"})
    if b1_kernel_energy:
        energy_labels = {"preemptive_scheduling":"抢占调度","synchronization_processing":"信号量",
            "interrupt_processing":"IRQ 处理","interrupt_preemption_processing":"IRQ 抢占"}
        completed = {r["case"] for r in b1_kernel_energy}
        pending = [label for case,label in energy_labels.items() if case not in completed]
        progress.append({"name":"B1 内核原负载同步能耗",
            "state":"已完成 "+str(len(completed))+" / 4 项，每项三系统、三轮交错共九次独立复位；复用原固件，不替换旧性能成绩",
            "missing":"仍待同板同步采集："+"、".join(pending) if pending else "保留仪表校准、转换延迟和配置边界；不合成通用 OS 能效总分"})
    address_pairs = None
    address_pairs_name = "esp32-nuttx-address-observer-pairs-b1-v1"
    if (EVIDENCE/address_pairs_name/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        address_pairs = pairs_audit(EVIDENCE/address_pairs_name)
        if address_pairs != read_json(address_pairs_name+"/audit.json"):
            raise ValueError("Address observer paired source/records differ")
        independent = replay(EVIDENCE/address_pairs_name)
        if independent["cells"] != [{k:c[k] for k in ("os","pairs","median_ratio","ratio_range")}
                for c in address_pairs["cells"]]:
            raise ValueError("Independent address observer paired count replay differs")
        address_pairs = {"evidence":"artifacts/reports/"+address_pairs_name+"/audit.json",**address_pairs}
    allocation_addresses = None
    address_name = "esp32-nuttx-message-identities-b1-v1"
    address_build = EVIDENCE/"esp32-nuttx-message-identities-v1"
    if (EVIDENCE/address_name/"audit.json").is_file():
        from run_esp32_nuttx_message_lifetimes import audit as address_audit
        allocation_addresses = address_audit(EVIDENCE/address_name,address_build)
        if json.loads(json.dumps(allocation_addresses)) != read_json(address_name+"/audit.json"):
            raise ValueError("Native allocation address evidence differs")
        independent = replay(EVIDENCE/address_name,prepared=address_build)
        for left,right in zip(allocation_addresses["runs"],independent["cells"][0]["runs"],strict=True):
            live = {int(k):v for k,v in left["allocation_identity_replay"]["live"].items()}
            if live != right["live"] or left["native_heap_peak_bytes"] != right["native_heap_peak_bytes"] or \
                    left["original_message"]["original_window_totals"] != right["original_counts"]:
                raise ValueError("Independent allocation address/count replay differs")
        allocation_addresses = {"evidence":"artifacts/reports/"+address_name+"/audit.json",**allocation_addresses}
        progress.append({"name":"NuttX 原消息任务分配地址生命周期",
            "state":"新增五次独立复位；每轮 50 条分配/扩缩容/释放地址转换、48 个最终存活块，原生块遍历与独立重放一致",
            "missing":("" if address_pairs else "新地址观察镜像的成对开销、")+
                "早期启动/未管理范围、精确同时 live 栈；完整整机 RAM 仍正在测，不计分"})
    stack_pairs = None
    stack_pairs_name = "esp32-zephyr-stack-observer-pairs-b1-v1"
    if (EVIDENCE/stack_pairs_name/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        stack_pairs = pairs_audit(EVIDENCE/stack_pairs_name)
        independent = replay(EVIDENCE/stack_pairs_name)
        if stack_pairs != read_json(stack_pairs_name+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in stack_pairs["cells"]]:
            raise ValueError("New Zephyr stack observer paired source/count replay differs")
        stack_pairs = {"evidence":"artifacts/reports/"+stack_pairs_name+"/audit.json",**stack_pairs}
    message_stack = None
    stack_name = "esp32-zephyr-message-stack-b1-v1"
    if (EVIDENCE/stack_name/"audit.json").is_file():
        from run_esp32_zephyr_message_lifetimes import audit as stack_audit
        from replay_esp32_message_stack import replay as stack_replay
        source = EVIDENCE/"esp32-zephyr-message-stack-v1"
        message_stack = stack_audit(EVIDENCE/stack_name,source)
        if message_stack != read_json(stack_name+"/audit.json"):
            raise ValueError("Zephyr same-message native stack evidence differs")
        independent = stack_replay(EVIDENCE/stack_name,source)
        for left,right in zip(message_stack["runs"],independent["runs"],strict=True):
            if any(left["native_stack_observations"][k] != right[k] for k in ("irq","tasks")) or \
                    left["original_message"]["original_window_totals"] != right["original_counts"] or \
                    left["native_heap_peak_bytes"] != right["native_heap_peak_bytes"]:
                raise ValueError("Separate native stack/heap/count replay differs")
        message_stack = {"evidence":"artifacts/reports/"+stack_name+"/audit.json",**message_stack}
        progress.append({"name":"Zephyr 同消息任务的普通 IRQ 与当前线程栈水位",
            "state":"原配置五次独立复位，原生初始 IRQ 染色、四个保留任务及当前报告线程均已观测；独立字节/计数重放通过",
            "missing":"历史触及水位不等于同时 live 用量；继承启动栈峰值/ROM 范围仍未闭合"+
                ("；该新镜像的五对扰动另已测" if stack_pairs else "；新观察版本的成对扰动仍待测")})
    freertos_stack_pairs = None
    freertos_pairs_name = "esp32-freertos-stack-observer-pairs-b1-v1"
    if (EVIDENCE/freertos_pairs_name/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        freertos_stack_pairs = pairs_audit(EVIDENCE/freertos_pairs_name)
        independent = replay(EVIDENCE/freertos_pairs_name)
        if freertos_stack_pairs != read_json(freertos_pairs_name+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in freertos_stack_pairs["cells"]]:
            raise ValueError("New FreeRTOS stack observer paired evidence differs")
        freertos_stack_pairs = {"evidence":"artifacts/reports/"+freertos_pairs_name+"/audit.json",**freertos_stack_pairs}
    freertos_message_stack = None
    freertos_stack_name = "esp32-freertos-message-stack-b1-v1"
    if (EVIDENCE/freertos_stack_name/"audit.json").is_file():
        from run_esp32_tm_ram_lifetimes import audit as freertos_stack_audit
        from replay_esp32_freertos_message import replay as freertos_stack_replay
        from audit_esp32_freertos_stack_coverage import vector_binding
        source = EVIDENCE/"esp32-freertos-message-stack-v1"
        freertos_message_stack = freertos_stack_audit(EVIDENCE/freertos_stack_name,source)
        if freertos_message_stack != read_json(freertos_stack_name+"/audit.json"):
            raise ValueError("FreeRTOS same-message IRQ observation differs")
        independent = freertos_stack_replay(EVIDENCE/freertos_stack_name,source)
        for left,right in zip(freertos_message_stack["runs"],independent["runs"],strict=True):
            if any(left[k] != right[k] for k in ("heap_peak_bytes","heap_final_bytes","live_tasks","ordinary_irq_stack")) or \
                    left["original_message"]["original_window_totals"] != right["original_counts"]:
                raise ValueError("Separate FreeRTOS native heap/task/IRQ replay differs")
        vector = vector_binding(source)
        if vector != read_json("esp32-freertos-message-irq-vector-v1.json"):
            raise ValueError("FreeRTOS native interrupted-task frame/IRQ switch binding differs")
        freertos_message_stack = {"evidence":"artifacts/reports/"+freertos_stack_name+"/audit.json",
            "irq_vector_binding":vector,**freertos_message_stack}
        progress.append({"name":"FreeRTOS 同消息任务普通 IRQ 与五任务原生水位",
            "state":"同原配置五次独立复位、分配器自检、五任务/堆块/IRQ 染色及独立重放通过；192 B 上下文帧在任务栈的边界另经实际 ELF 核对",
            "missing":"历史触及水位不能覆盖未写帧或同时 live 字节；早期/未管理范围仍待闭合"+
                ("；新镜像五对扰动已另测" if freertos_stack_pairs else "；版本专属成对扰动仍待完成")})
    freertos_message_startup = None
    freertos_startup_pairs = None
    startup_capture = "esp32-freertos-message-startup-b1-v1"
    startup_pairs_capture = "esp32-freertos-startup-observer-pairs-b1-v1"
    if (EVIDENCE/startup_capture/"audit.json").is_file():
        from run_esp32_tm_ram_lifetimes import audit as startup_audit
        from replay_esp32_freertos_message import replay as startup_replay
        source = EVIDENCE/"esp32-freertos-message-startup-v1"
        freertos_message_startup = startup_audit(EVIDENCE/startup_capture,source)
        independent = startup_replay(EVIDENCE/startup_capture,source)
        if freertos_message_startup != read_json(startup_capture+"/audit.json"):
            raise ValueError("Application startup source/heap handoff evidence differs")
        for left,right in zip(freertos_message_startup["runs"],independent["runs"],strict=True):
            if any(left[k] != right[k] for k in ("heap_peak_bytes","live_tasks","ordinary_irq_stack","application_startup_stack")):
                raise ValueError("Independent application startup/task replay differs")
        freertos_message_startup = {"evidence":"artifacts/reports/"+startup_capture+"/audit.json",**freertos_message_startup}
        progress.append({"name":"FreeRTOS 应用入口至启动堆交还的栈水位",
            "state":"五次独立复位，入口标记区逐字核验、main 原生栈上的堆交接及独立字节重放通过",
            "missing":"入口之前的 bootloader/ROM、64 B 未染色保护区、未写栈帧及精确同时 live 内存仍不包含；不计分"})
    if (EVIDENCE/startup_pairs_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        freertos_startup_pairs = pairs_audit(EVIDENCE/startup_pairs_capture)
        independent = replay(EVIDENCE/startup_pairs_capture)
        if freertos_startup_pairs != read_json(startup_pairs_capture+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in freertos_startup_pairs["cells"]]:
            raise ValueError("Application startup image paired replay differs")
        freertos_startup_pairs = {"evidence":"artifacts/reports/"+startup_pairs_capture+"/audit.json",**freertos_startup_pairs}
    freertos_tick_stacks = None
    freertos_tick_pairs = None
    tick_capture = "esp32-freertos-message-tick-stacks-b1-v1"
    tick_pairs_capture = "esp32-freertos-tick-observer-pairs-b1-v1"
    if (EVIDENCE/tick_capture/"audit.json").is_file():
        from run_esp32_tm_ram_lifetimes import audit as tick_audit
        from replay_esp32_freertos_message import replay as tick_replay
        source = EVIDENCE/"esp32-freertos-message-tick-stacks-v1"
        freertos_tick_stacks = tick_audit(EVIDENCE/tick_capture,source)
        independent = tick_replay(EVIDENCE/tick_capture,source)
        if freertos_tick_stacks != read_json(tick_capture+"/audit.json"):
            raise ValueError("Native tick snapshot source/raw evidence differs")
        for left,right in zip(freertos_tick_stacks["runs"],independent["runs"],strict=True):
            if any(left[k] != right[k] for k in ("native_tick_stack_snapshots","heap_peak_bytes",
                    "live_tasks","ordinary_irq_stack","application_startup_stack")) or \
                    left["original_message"]["original_window_totals"] != right["original_counts"]:
                raise ValueError("Independent simultaneous saved-SP/heap replay differs")
        freertos_tick_stacks = {"evidence":"artifacts/reports/"+tick_capture+"/audit.json",**freertos_tick_stacks}
        progress.append({"name":"FreeRTOS 原生 tick 同时栈指针与堆事件",
            "state":"五次独立复位，100 Hz 原生 tick 上的五任务保存 SP、IRQ SP 与分配事件逐条重放一致",
            "missing":"采样可能遗漏 tick 之间的峰值，保留跨度包含观察器及原生上下文；不是精确 live 字节或整机 RAM 峰值，不计分"})
    if (EVIDENCE/tick_pairs_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        freertos_tick_pairs = pairs_audit(EVIDENCE/tick_pairs_capture)
        independent = replay(EVIDENCE/tick_pairs_capture)
        if freertos_tick_pairs != read_json(tick_pairs_capture+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in freertos_tick_pairs["cells"]]:
            raise ValueError("Native tick observer paired replay differs")
        freertos_tick_pairs = {"evidence":"artifacts/reports/"+tick_pairs_capture+"/audit.json",**freertos_tick_pairs}
    zephyr_tick_stacks = None
    zephyr_tick_pairs = None
    ztick_capture = "esp32-zephyr-message-tick-stacks-b1-v1"
    ztick_pairs_capture = "esp32-zephyr-tick-observer-pairs-b1-v1"
    if (EVIDENCE/ztick_capture/"audit.json").is_file():
        from run_esp32_zephyr_message_lifetimes import audit as ztick_audit
        from replay_esp32_message_stack import replay as ztick_replay
        source = EVIDENCE/"esp32-zephyr-message-tick-stacks-v3"
        zephyr_tick_stacks = ztick_audit(EVIDENCE/ztick_capture,source)
        independent = ztick_replay(EVIDENCE/ztick_capture,source)
        if zephyr_tick_stacks != read_json(ztick_capture+"/audit.json"):
            raise ValueError("Zephyr native IRQ-return snapshot evidence differs")
        for left,right in zip(zephyr_tick_stacks["runs"],independent["runs"],strict=True):
            if left["native_tick_stack_snapshots"] != right["native_tick_stack_snapshots"] or \
                    left["native_heap_peak_bytes"] != right["native_heap_peak_bytes"] or \
                    left["original_message"]["original_window_totals"] != right["original_counts"]:
                raise ValueError("Independent Zephyr simultaneous pointer/heap replay differs")
        zephyr_tick_stacks = {"evidence":"artifacts/reports/"+ztick_capture+"/audit.json",**zephyr_tick_stacks}
        progress.append({"name":"Zephyr 原生 tick 的同时栈现场与堆事件",
            "state":"五次独立复位，原生 IRQ 返回句柄、四任务保存现场和堆序号重放一致",
            "missing":"采样可能遗漏 tick 间峰值，包含观察器和原生上下文预留；不等于整机 live 峰值，不计分"})
    if (EVIDENCE/ztick_pairs_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        zephyr_tick_pairs = pairs_audit(EVIDENCE/ztick_pairs_capture)
        independent = replay(EVIDENCE/ztick_pairs_capture)
        if zephyr_tick_pairs != read_json(ztick_pairs_capture+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in zephyr_tick_pairs["cells"]]:
            raise ValueError("Zephyr native tick paired replay differs")
        zephyr_tick_pairs = {"evidence":"artifacts/reports/"+ztick_pairs_capture+"/audit.json",**zephyr_tick_pairs}
    nuttx_tick_stacks = None
    nuttx_tick_pairs = None
    ntick_capture = "esp32-nuttx-message-tick-stacks-b1-v2"
    ntick_pairs_capture = "esp32-nuttx-tick-observer-pairs-b1-v1"
    if (EVIDENCE/ntick_capture/"audit.json").is_file():
        from run_esp32_nuttx_message_lifetimes import audit as ntick_audit
        source = EVIDENCE/"esp32-nuttx-message-tick-stacks-v2"
        nuttx_tick_stacks = json.loads(json.dumps(ntick_audit(EVIDENCE/ntick_capture,source)))
        independent = replay(EVIDENCE/ntick_capture,prepared=source)
        if nuttx_tick_stacks != read_json(ntick_capture+"/audit.json"):
            raise ValueError("NuttX native timer-entry snapshot evidence differs")
        for left,right in zip(nuttx_tick_stacks["runs"],independent["cells"][0]["runs"],strict=True):
            if left['native_tick_stack_snapshots'] != right['native_tick_stack_snapshots'] or \
                    left['native_heap_peak_bytes'] != right['native_heap_peak_bytes'] or \
                    left['original_message']['original_window_totals'] != right['original_counts']:
                raise ValueError("Independent NuttX native context/heap replay differs")
        nuttx_tick_stacks = {"evidence":"artifacts/reports/"+ntick_capture+"/audit.json",**nuttx_tick_stacks}
        progress.append({"name":"NuttX 原生 tick 的任务/同栈 IRQ 现场",
            "state":"五次独立复位，完整首轮复用后续采四轮；五任务有效边界、寄存器与堆序号重放一致",
            "missing":"采样遗漏的 tick 间峰值、启动前与未管理范围仍未闭合；整机 RAM 不计分"})
    if (EVIDENCE/ntick_pairs_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        nuttx_tick_pairs = pairs_audit(EVIDENCE/ntick_pairs_capture)
        independent = replay(EVIDENCE/ntick_pairs_capture)
        if nuttx_tick_pairs != read_json(ntick_pairs_capture+"/audit.json") or independent["cells"] != [
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in nuttx_tick_pairs["cells"]]:
            raise ValueError("NuttX native tick observer pair evidence differs")
        nuttx_tick_pairs = {"evidence":"artifacts/reports/"+ntick_pairs_capture+"/audit.json",**nuttx_tick_pairs}
    nuttx_tick_control = None
    control_capture = "esp32-nuttx-tick-control-b1-v1"
    if (EVIDENCE/control_capture/"audit.json").is_file():
        from run_esp32_nuttx_tick_control import audit as control_audit
        from replay_esp32_nuttx_tick_control import replay as control_replay
        source=EVIDENCE/"esp32-nuttx-message-tick-control-v1"
        nuttx_tick_control=control_audit(EVIDENCE/control_capture,source)
        if nuttx_tick_control!=read_json(control_capture+"/audit.json") or nuttx_tick_control!=control_replay(EVIDENCE/control_capture,source):
            raise ValueError("Same-image tick-control raw replay differs")
        nuttx_tick_control={"evidence":"artifacts/reports/"+control_capture+"/audit.json",**nuttx_tick_control}
    nuttx_controlled_stacks = None
    nuttx_controlled_pairs = None
    controlled_capture="esp32-nuttx-message-tick-control-census-b1-v1"
    controlled_pairs_capture="esp32-nuttx-tick-control-observer-pairs-b1-v1"
    if (EVIDENCE/controlled_capture/"audit.json").is_file():
        from run_esp32_nuttx_message_lifetimes import audit as controlled_audit
        source=EVIDENCE/"esp32-nuttx-message-tick-control-v1"
        nuttx_controlled_stacks=json.loads(json.dumps(controlled_audit(EVIDENCE/controlled_capture,source)))
        independent=replay(EVIDENCE/controlled_capture,source)['cells'][0]['runs']
        if nuttx_controlled_stacks!=read_json(controlled_capture+"/audit.json") or any(
                a['native_tick_stack_snapshots']!=b['native_tick_stack_snapshots'] or
                a['native_tick_probe_cost']!=b['native_tick_probe_cost'] or
                a['native_heap_peak_bytes']!=b['native_heap_peak_bytes'] or
                a['original_message']['original_window_totals']!=b['original_counts']
                for a,b in zip(nuttx_controlled_stacks['runs'],independent,strict=True)):
            raise ValueError("NuttX default-call controlled-image replay differs")
        nuttx_controlled_stacks={"evidence":"artifacts/reports/"+controlled_capture+"/audit.json",**nuttx_controlled_stacks}
        progress.append({"name":"NuttX 新观察镜像的原调用五轮复测",
            "state":"原消息、无参数调用、五次独立复位；栈现场/堆事件/包装器周期双解析一致",
            "missing":"采样跨度不是全生命周期 live 峰值，整机 RAM 仍不计分"})
    if (EVIDENCE/controlled_pairs_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        nuttx_controlled_pairs=pairs_audit(EVIDENCE/controlled_pairs_capture)
        if nuttx_controlled_pairs!=read_json(controlled_pairs_capture+"/audit.json") or replay(
                EVIDENCE/controlled_pairs_capture)['cells']!=[
                    {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in nuttx_controlled_pairs['cells']]:
            raise ValueError("NuttX controlled-image baseline pair replay differs")
        nuttx_controlled_pairs={"evidence":"artifacts/reports/"+controlled_pairs_capture+"/audit.json",**nuttx_controlled_pairs}
    nuttx_message_startup = None
    nuttx_startup_pairs = None
    nuttx_startup_capture = "esp32-nuttx-message-startup-b1-v1"
    nuttx_startup_pair_capture = "esp32-nuttx-startup-observer-pairs-b1-v1"
    if (EVIDENCE/nuttx_startup_capture/"audit.json").is_file():
        from run_esp32_nuttx_message_lifetimes import audit as nuttx_startup_audit
        source=EVIDENCE/"esp32-nuttx-message-startup-v5"
        nuttx_message_startup=json.loads(json.dumps(nuttx_startup_audit(EVIDENCE/nuttx_startup_capture,source)))
        independent=replay(EVIDENCE/nuttx_startup_capture,prepared=source)
        if nuttx_message_startup!=read_json(nuttx_startup_capture+"/audit.json"):
            raise ValueError("Native idle startup source/switch observation differs")
        for left,right in zip(nuttx_message_startup["runs"],independent["cells"][0]["runs"],strict=True):
            if left["application_startup_stack"]!=right["application_startup_stack"] or \
                    left["native_heap_peak_bytes"]!=right["native_heap_peak_bytes"] or \
                    left["original_message"]["original_window_totals"]!=right["original_counts"]:
                raise ValueError("Independent native idle startup/count replay differs")
        nuttx_message_startup={"evidence":"artifacts/reports/"+nuttx_startup_capture+"/audit.json",**nuttx_message_startup}
        progress.append({"name":"NuttX 应用入口、切栈及原生重新染色前 idle 水位",
            "state":"五轮原消息、独立分配器自检、32 B 原入口帧和 idle 首次使用前染色验证通过；分配地址/堆统计及独立字节重放一致",
            "missing":"入口前 ROM/bootloader、未写帧、未管理范围与精确同时 live 用量仍不覆盖；不计分"})
    if (EVIDENCE/nuttx_startup_pair_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        nuttx_startup_pairs=pairs_audit(EVIDENCE/nuttx_startup_pair_capture)
        independent=replay(EVIDENCE/nuttx_startup_pair_capture)
        if nuttx_startup_pairs!=read_json(nuttx_startup_pair_capture+"/audit.json") or independent["cells"]!=[
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in nuttx_startup_pairs["cells"]]:
            raise ValueError("Native idle startup image paired replay differs")
        nuttx_startup_pairs={"evidence":"artifacts/reports/"+nuttx_startup_pair_capture+"/audit.json",**nuttx_startup_pairs}
    zephyr_message_startup = None
    zephyr_startup_pairs = None
    zephyr_startup_capture = "esp32-zephyr-message-startup-b1-v1"
    zephyr_startup_pair_capture = "esp32-zephyr-startup-observer-pairs-b1-v1"
    if (EVIDENCE/zephyr_startup_capture/"audit.json").is_file():
        from run_esp32_zephyr_message_lifetimes import audit as zephyr_startup_audit
        from replay_esp32_message_stack import replay as stack_replay
        source=EVIDENCE/"esp32-zephyr-message-startup-v2"
        zephyr_message_startup=zephyr_startup_audit(EVIDENCE/zephyr_startup_capture,source)
        independent=stack_replay(EVIDENCE/zephyr_startup_capture,source)
        if zephyr_message_startup!=read_json(zephyr_startup_capture+"/audit.json"):
            raise ValueError("Zephyr startup source or state observation differs")
        for left,right in zip(zephyr_message_startup["runs"],independent["runs"],strict=True):
            if left["application_startup_stack"]!=right["application_startup_stack"] or \
                    left["native_heap_peak_bytes"]!=right["native_heap_peak_bytes"] or \
                    left["original_message"]["original_window_totals"]!=right["original_counts"]:
                raise ValueError("Independent Zephyr startup/count replay differs")
        zephyr_message_startup={"evidence":"artifacts/reports/"+zephyr_startup_capture+"/audit.json",**zephyr_message_startup}
        progress.append({"name":"Zephyr 应用入口至首个原生 main 上下文",
            "state":"五次独立复位和单独分配器验证；ROM 栈保留界、入口逐字染色验证及主线程读取已核对",
            "missing":"64 B 未标记区、入口前 ROM、未写帧和同时 live 用量仍不覆盖；不计分"})
    if (EVIDENCE/zephyr_startup_pair_capture/"audit.json").is_file():
        from run_esp32_message_observer_pairs import audit as pairs_audit
        zephyr_startup_pairs=pairs_audit(EVIDENCE/zephyr_startup_pair_capture)
        independent=replay(EVIDENCE/zephyr_startup_pair_capture)
        if zephyr_startup_pairs!=read_json(zephyr_startup_pair_capture+"/audit.json") or independent["cells"]!=[
                {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in zephyr_startup_pairs["cells"]]:
            raise ValueError("Zephyr startup image paired replay differs")
        zephyr_startup_pairs={"evidence":"artifacts/reports/"+zephyr_startup_pair_capture+"/audit.json",**zephyr_startup_pairs}
    boot_stage = None
    boot_stage_name = "esp32-boot-stage-b1-v1"
    if (EVIDENCE/boot_stage_name/"audit.json").is_file():
        from audit_esp32_bootloader_ram import audit as boot_stage_audit
        boot_stage = boot_stage_audit(EVIDENCE/boot_stage_name, EVIDENCE/"esp32-boot-stage-build-v3")
        if boot_stage != read_json(boot_stage_name+"/audit.json"):
            raise ValueError("Boot-stage source/image/raw-byte replay differs")
        boot_stage = {"evidence":"artifacts/reports/"+boot_stage_name+"/audit.json", **boot_stage}
        progress.append({"name":"FreeRTOS 第二阶段启动栈",
            "state":"五次独立复位；原应用二进制未改；启动入口和加载结束两阶段水位、机器码及独立原字节重放通过",
            "missing":"ROM 首阶段、最终跳转、未写栈帧和精确同时 live 内存仍需补齐；不计分"})
    continuous_memory = None
    continuous_pairs = None
    step_name = "esp32-message-steps-b1-v5"
    step_audit_name = step_name + "-audit.json"
    if (EVIDENCE/step_audit_name).is_file():
        from audit_esp32_message_steps import audit as continuous_audit
        from replay_esp32_message_steps import replay as continuous_replay
        from audit_esp32_runtime_reservations import audit as coverage_audit
        from replay_esp32_runtime_reservations import replay as coverage_replay
        prepared = EVIDENCE/"esp32-message-steps-build-v5"
        observed = continuous_audit(prepared, EVIDENCE/step_name)
        separate = continuous_replay(EVIDENCE/step_name)
        if json.loads(json.dumps(observed)) != read_json(step_audit_name) or any(a["continuous_stack"] != b["continuous_stack"]
                for a, b in zip(observed["runs"], separate["runs"], strict=True)):
            raise ValueError("Continuous context source and separate byte replay differ")
        coverage_name = "esp32-message-runtime-coverage-v1.json"
        coverage = coverage_audit(prepared, EVIDENCE/step_name, EVIDENCE/step_audit_name)
        if json.loads(json.dumps(coverage)) != read_json(coverage_name):
            raise ValueError("Continuous image runtime ownership differs")
        coverage_replay(prepared, EVIDENCE/step_name, EVIDENCE/coverage_name)
        selected_runs = [r for r in observed["runs"] if not r["validation"]]
        continuous_memory = {"evidence":"artifacts/reports/"+step_audit_name,
            "independent_resets":observed["independent_resets"],
            "observations_per_reset":[r["continuous_stack"]["summary"]["total"] for r in selected_runs],
            "unclassified_per_reset":[r["continuous_stack"]["summary"]["unknown"] for r in selected_runs],
            "static_sram_bytes":coverage["static_sram_bytes"],
            "heap_peak_bytes":[r["native"]["heap_peak_bytes"] for r in selected_runs],
            "native_heap_capacity_bytes":coverage["runs"][0]["observed_native_capacity_bytes_not_occupancy"],
            "fixed_reservations_bytes":coverage["fixed_reservations_outside_static_and_heap_bytes"],
            "outside_allocator_layout_bytes":sum(r["bytes"] for r in coverage["outside_compiled_layout"]),
            "whole_live_ram_peak_bytes":None,"ranking_eligible":False,"paired_count_change_pct":None}
        pair_name = "esp32-message-steps-observer-pairs-b1-v1"
        if (EVIDENCE/pair_name/"audit.json").is_file():
            from run_esp32_message_observer_pairs import audit as continuous_pairs_audit
            continuous_pairs = continuous_pairs_audit(EVIDENCE/pair_name)
            independent = replay(EVIDENCE/pair_name)
            if continuous_pairs != read_json(pair_name+"/audit.json") or independent["cells"] != [
                    {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in continuous_pairs["cells"]]:
                raise ValueError("Continuous observer paired replay differs")
            continuous_memory["paired_count_change_pct"] = (continuous_pairs["cells"][0]["median_ratio"]-1)*100
        progress.append({"name":"FreeRTOS 原消息连续栈与运行地址覆盖",
            "state":"五次复位的任务／普通 IRQ 连续观察、分配代际及六堆池地址集合均通过；复用原记录核对固定保留与 RTC 布局边界",
            "missing":"更早启动与固定保留区的 live 用量仍需闭合；逐指令观察有明显扰动，不能替代正常性能或完整 RAM 峰值"})
    boundary_memory = None
    boundary_name = "esp32-message-boundary-b1-v3"
    if (EVIDENCE/(boundary_name + "-audit.json")).is_file():
        from measure_esp32_boot_handoff_ram import audit as boundary_audit
        from replay_esp32_message_boundaries import replay as boundary_replay
        observed = boundary_audit(EVIDENCE/boundary_name, EVIDENCE/"esp32-message-boundary-build-v5")
        separate = boundary_replay(EVIDENCE/boundary_name)
        if json.loads(json.dumps(observed)) != read_json(boundary_name + "-audit.json") or any(
                a["boundary_stack"] != b["boundary_stack"] for a, b in zip(
                    [observed["application"]["separate_validation"]] + observed["application"]["runs"], separate["runs"], strict=True)):
            raise ValueError("Compiler-boundary source and independent raw-byte replay differ")
        boundary_memory = {"evidence":"artifacts/reports/" + boundary_name + "-audit.json",
            "independent_resets":5, "separate_validation_resets":1,
            "static_sram_bytes":observed["build"]["application"]["static_sram_bytes"],
            "whole_live_ram_peak_bytes":None, "ranking_eligible":False, "paired_count_change_pct":None}
        pair_name = "esp32-boundary-observer-pairs-b1-v1"
        if (EVIDENCE/pair_name/"audit.json").is_file():
            from run_esp32_message_observer_pairs import audit as boundary_pairs_audit
            paired = boundary_pairs_audit(EVIDENCE/pair_name)
            independent = replay(EVIDENCE/pair_name)
            if paired != read_json(pair_name + "/audit.json") or independent["cells"] != [
                    {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in paired["cells"]]:
                raise ValueError("Boundary observer paired replay differs")
            boundary_memory["paired_count_change_pct"] = (paired["cells"][0]["median_ratio"] - 1) * 100
        progress.append({"name":"FreeRTOS 函数边界 RAM 观察器实板复测",
            "state":"五次原负载复位及一次创建／退出／回收验证；任务代际、IRQ、分配事件及独立原字节重放通过",
            "missing":"观察开销及未覆盖的内联、汇编、ROM 与早期启动范围仍须闭合；完整 RAM 正在测、不计分"})
    native_memory = None
    native_audit_name = "esp32-native-sp-audit-v1"
    if (EVIDENCE/native_audit_name/"main.json").is_file():
        from measure_esp32_boot_handoff_ram import audit as native_audit
        from replay_esp32_native_sp import replay as native_replay
        observed = native_audit(EVIDENCE/"esp32-message-native-sp-b1-v1", EVIDENCE/"esp32-message-native-sp-build-v1")
        separate = native_replay(EVIDENCE/"esp32-message-native-sp-b1-v1")
        if json.loads(json.dumps(observed)) != read_json(native_audit_name+"/main.json") or \
                separate != read_json(native_audit_name+"/independent.json") or any(
                    a["native_sp"] != b["native_sp"] for a, b in zip(
                        [observed["application"]["separate_validation"]]+observed["application"]["runs"], separate["runs"], strict=True)):
            raise ValueError("Native assembly SP source and raw-byte replay differ")
        summaries = [r["native_sp"]["summary"] for r in separate["runs"] if not r["validation"]]
        validation = separate["runs"][0]["native_sp"]["summary"]
        native_memory = {"evidence":"artifacts/reports/"+native_audit_name+"/main.json",
            "independent_resets":5, "separate_validation_resets":1,
            "observations_per_reset":[s["total"] for s in summaries],
            "observed_joint_stack_bytes":[s["joint_peak"] for s in summaries],
            "validation_generations":validation["generations"], "validation_retired":validation["retired"],
            "unclassified_per_reset":[s["unknown"] for s in summaries],
            "whole_live_ram_peak_bytes":None, "ranking_eligible":False, "new_board_runs":0}
        pair_name = "esp32-native-sp-observer-pairs-b1-v2"
        if (EVIDENCE/pair_name/"audit.json").is_file():
            from run_esp32_message_observer_pairs import audit as native_pairs_audit
            paired = native_pairs_audit(EVIDENCE/pair_name)
            independent = replay(EVIDENCE/pair_name)
            if paired != read_json(pair_name + "/audit.json") or independent["cells"] != [
                    {k: c[k] for k in ("os", "pairs", "median_ratio", "ratio_range")} for c in paired["cells"]]:
                raise ValueError("Native-only assembly observer paired replay differs")
            cell = paired["cells"][0]
            native_memory.update(paired_count_change_pct=(cell["median_ratio"]-1)*100,
                paired_count_range_pct=[(v-1)*100 for v in cell["ratio_range"]],
                paired_resets=paired["independent_resets"], paired_evidence="artifacts/reports/"+pair_name+"/audit.json")
        progress.append({"name":"FreeRTOS 原生汇编 SP 边界核验",
            "state":"复用五轮原消息负载和一次生命周期验证；五处原生任务／IRQ 边界、机器码及独立原字节重放通过",
            "missing":"尚非连续全指令／ROM 观测；完整 RAM 仍正在测、不计分"})
    combined_memory = None
    combined_name = "esp32-combined-stacks-audit-v1.json"
    if (EVIDENCE/combined_name).is_file():
        from audit_esp32_combined_stacks import audit as combined_audit
        combined_memory = combined_audit(EVIDENCE/"esp32-message-native-sp-combined-b1-v1",
                                         EVIDENCE/"esp32-message-native-sp-combined-build-v1")
        if combined_memory != read_json(combined_name):
            raise ValueError("Combined stack identities or independent raw-byte replay differ")
        combined_memory = {"evidence":"artifacts/reports/"+combined_name, **combined_memory,
                           "paired_count_change_pct":None, "paired_count_range_pct":None}
        pairs_name = "esp32-combined-stack-observer-pairs-b1-v1"
        if (EVIDENCE/pairs_name/"audit.json").is_file():
            from run_esp32_message_observer_pairs import audit as pairs_audit
            from replay_esp32_followup import replay as pairs_replay
            paired = pairs_audit(EVIDENCE/pairs_name)
            independent = pairs_replay(EVIDENCE/pairs_name)
            if paired != read_json(pairs_name+"/audit.json") or independent["cells"] != [
                    {k:c[k] for k in ("os","pairs","median_ratio","ratio_range")} for c in paired["cells"]]:
                raise ValueError("Combined observer paired replay differs")
            combined_memory.update(paired_count_change_pct=(paired["cells"][0]["median_ratio"]-1)*100,
                paired_count_range_pct=[(v-1)*100 for v in paired["cells"][0]["ratio_range"]],
                pairs_evidence="artifacts/reports/"+pairs_name+"/audit.json")
        progress.append({"name":"FreeRTOS 同镜像 C／汇编栈观察",
            "state":"五轮原消息和一次有限生命周期验证通过；两探针任务代际、物理存储和原字节独立重放一致",
            "missing":"不同观测时刻不叠加；内联／ROM／早期及未管理范围仍未闭合，完整 RAM 正在测、不计分"})
    compact_ram = None
    compact_name = "esp32-freertos-compact-ram-b1-v2"
    if (EVIDENCE/compact_name/"audit.json").is_file():
        from run_esp32_tm_ram_lifetimes import audit as compact_audit
        from replay_esp32_freertos_message import history
        from replay_esp32_followup import raw_rows
        compact_ram = compact_audit(EVIDENCE/compact_name, EVIDENCE/"esp32-freertos-compact-ram-build-v2")
        if compact_ram != read_json(compact_name+"/audit.json"):
            raise ValueError("Compact RAM source replay differs")
        for i, result in enumerate(compact_ram["runs"], 1):
            separate = history([r["line"] for r in raw_rows(EVIDENCE/compact_name/"captures"/f"reset{i}.jsonl")])
            if any(result[k] != separate[k] for k in ("events", "heap_peak_bytes", "heap_final_bytes", "live_tasks")):
                raise ValueError("Independent compact RAM replay differs")
        compact_ram = {"evidence":"artifacts/reports/"+compact_name+"/audit.json", **compact_ram}
        progress.append({"name":"FreeRTOS 轻量完整事件追踪",
            "state":"五次独立复位；完整原消息、分配事件和任务所有权重放；另有有限任务回收校验",
            "missing":"启动交接与未写栈帧尚未闭合为精确整机 live 峰值；不计分"})
    startup_scope = None
    startup_name = "esp32-message-startup-cohort-v1.json"
    if (EVIDENCE/startup_name).is_file():
        from audit_esp32_message_startup import audit as startup_audit
        startup_scope = startup_audit()
        if startup_scope != read_json(startup_name):
            raise ValueError("Compiled startup/provider boundary evidence differs")
        startup_scope = {"evidence":"artifacts/reports/"+startup_name,**startup_scope}
        progress.append({"name":"三 OS 启动与原生堆区范围审计",
            "state":"FreeRTOS 六堆区与五轮启动栈转交事件闭合；Zephyr PRE_KERNEL_1 堆初始化表及三类静态栈已绑定实际 ELF；NuttX 启动路径另已核对",
            "missing":("三个限定启动窗口已分别补测，端点不同不排名；未标记区、未写帧、入口前 ROM/cache 和精确同时 live 用量仍不覆盖"
                if all(x is not None for x in (freertos_message_startup,nuttx_message_startup,zephyr_message_startup)) else
                "后续限定窗口补测另列；ROM/cache 用量及精确同时 live 栈仍未测。本项为旧字节边界审计，不产生 RAM 分数")})
    common_udp = None
    udp_name = "esp32-common-original-udp-b1-v3"
    if (EVIDENCE/udp_name/"audit.json").is_file():
        from run_esp32_common_tcp import audit as common_network_audit
        common_udp = common_network_audit(EVIDENCE/udp_name,protocol="udp")
        if common_udp != read_json(udp_name+"/audit.json"):
            raise ValueError("Common original UDP source/receiver evidence differs")
        independent = replay(EVIDENCE/udp_name)
        if independent["cells"] != [{k:c[k] for k in
                ("system","values_mbit_s","median_mbit_s","range_mbit_s","independent_resets")}
                for c in common_udp["cells"]]:
            raise ValueError("Common UDP independent receiver replay differs")
        common_udp = {"evidence":"artifacts/reports/"+udp_name+"/audit.json",**common_udp}
    progress.append({"name":"共同原 zperf UDP 同步发送与原接收统计",
        "state":("三 OS 五轮交错共 15 次合格复位，报文序列/FIN/整数 CSV 及独立重放通过" if common_udp else
                 "1024 B、60 s、10000 kbps 参数和原发送核心已冻结；整组合格采集尚未完成"),
        "missing":"原生 sleep、网络/RF 和内存配置单列；请求参数相同不保证实际注入流量相同，不能作为等流量丢包或网络容量排名"})
    common_tcp = None
    common_udp_receiver = None
    receiver_name = "esp32-common-original-udp-receiver-b1-v6"
    if (EVIDENCE/receiver_name/"audit.json").is_file():
        from run_esp32_common_udp_receiver import audit as receiver_audit
        common_udp_receiver = receiver_audit(EVIDENCE/receiver_name)
        if common_udp_receiver != read_json(receiver_name+"/audit.json"):
            raise ValueError("Common original UDP receiver evidence differs")
        independent = replay(EVIDENCE/receiver_name, EVIDENCE)
        if independent["cells"] != [{k:c[k] for k in
                ("system","values_mbit_s","median_mbit_s","range_mbit_s","independent_resets")}
                for c in common_udp_receiver["cells"]]:
            raise ValueError("Common UDP receiver independent sequence/CSV replay differs")
        common_udp_receiver = {"evidence":"artifacts/reports/"+receiver_name+"/audit.json",**common_udp_receiver}
    source_path_diagnosis = None
    source_path_name = "esp32-common-udp-source-path-b1-v1"
    if (EVIDENCE/source_path_name/"audit.json").is_file():
        from run_esp32_common_udp_receiver import source_path_diagnostic
        source_path_diagnosis = source_path_diagnostic(EVIDENCE/source_path_name)
        if source_path_diagnosis != read_json(source_path_name+"/audit.json"):
            raise ValueError("Host source-queue diagnostic differs")
        source_path_diagnosis = {"evidence":"artifacts/reports/"+source_path_name+"/audit.json",**source_path_diagnosis}
    source_queue_control_result = None
    queue_control_name = "esp32-common-udp-source-queue-control-b1-v2"
    if (EVIDENCE/queue_control_name/"audit.json").is_file():
        from run_esp32_common_udp_receiver import source_queue_control
        source_queue_control_result = source_queue_control(EVIDENCE/queue_control_name)
        if source_queue_control_result != read_json(queue_control_name+"/audit.json"):
            raise ValueError("Controlled host source-queue comparison differs")
        source_queue_control_result = {"evidence":"artifacts/reports/"+queue_control_name+"/audit.json",**source_queue_control_result}
    progress.append({"name":"共同原 UDP 接收核心与主机固定负载",
        "state":("三 OS 各五次独立复位，实际提供序列、返回统计、双端 CSV 及独立重放已核对" if common_udp_receiver else
                 "Zephyr 原负载发送队列对照通过，73243 包完整；三 OS 五轮统一条件采集待完成" if source_queue_control_result else
                 "主机 fq_codel 丢包与捕获缺包计数一致；已完成源路径诊断，完整五轮采集尚未通过" if source_path_diagnosis else
                 "三 OS 原接收/会话核心已构建；已补输出适配和计时对照，完整五轮采集尚未通过"),
        "missing":("原接收计数省略启动首包，FIN 不计入数据；原 lost 不推算完整会话丢包率，原抖动仅诊断" if common_udp_receiver else
            "按已验证的统一发送队列完成三 OS 共十五次新采集；队列配置、完整提供序列和恢复均逐轮核对，旧队列单轮不拼接" if source_queue_control_result else
            "先验证可恢复的主机发送队列对照，再按统一源条件完成三 OS 共十五次采集；不降低原负载或扣减原接收丢包" if source_path_diagnosis else
            "先核查原 iPerf -w 发送缓冲选项与实际提供序列，再补三 OS 共十五次采集；当前没有这组通信成绩")})
    receiver_clock_control = None
    clock_name = "esp32-common-original-udp-receiver-b1-v4"
    if (EVIDENCE/clock_name/"audit.json").is_file():
        from run_esp32_common_udp_receiver import clock_diagnostic
        receiver_clock_control = clock_diagnostic(EVIDENCE/clock_name,periodic=True)
        if receiver_clock_control != read_json(clock_name+"/audit.json"):
            raise ValueError("Original UDP receiver clock-control diagnostic differs")
        receiver_clock_control = {"evidence":"artifacts/reports/"+clock_name+"/audit.json",**receiver_clock_control}
    common_name = "esp32-common-original-tcp-b1-v1"
    if (EVIDENCE/common_name/"audit.json").is_file():
        from run_esp32_common_tcp import audit as common_tcp_audit
        common_tcp = common_tcp_audit(EVIDENCE/common_name)
        if common_tcp != read_json(common_name+"/audit.json"):
            raise ValueError("Common original TCP source/receiver evidence differs")
        independent = replay(EVIDENCE/common_name)
        if independent["cells"] != [{k:c[k] for k in
                ("system","values_mbit_s","median_mbit_s","range_mbit_s","independent_resets")}
                for c in common_tcp["cells"]]:
            raise ValueError("Common TCP independent receiver replay differs")
        common_tcp = {"evidence":"artifacts/reports/"+common_name+"/audit.json",**common_tcp}
        progress.append({"name":"共同原 zperf TCP 发送核心",
            "state":"三 OS 同原同步发送核心、16384 B、60 s；五轮交错共 15 次独立复位，双端整数计数及完整恢复通过",
            "missing":"原生网络栈、无线栈、调度和预留内存仍为各自配置；"+
                ("共同 UDP 原测试另组报告" if common_udp else "共同 UDP 负载/发送节奏/接收序列尚待完成整组采集")})
    observer_static_ownership = None
    ownership_name = "esp32-message-observer-ownership-v1.json"
    if (EVIDENCE/ownership_name).is_file():
        from audit_esp32_ram_scope import observer_ownership
        observer_static_ownership = observer_ownership()
        if observer_static_ownership != read_json(ownership_name):
            raise ValueError("Observer input-section attribution differs")
        observer_static_ownership = {"evidence":"artifacts/reports/"+ownership_name,**observer_static_ownership}
    message_address_coverage = None
    coverage_name = "esp32-message-address-coverage-v1.json"
    if (EVIDENCE/coverage_name).is_file():
        from audit_esp32_ram_scope import message_coverage
        message_address_coverage = message_coverage()
        if message_address_coverage != read_json(coverage_name):
            raise ValueError("Measured-message physical address coverage differs")
        message_address_coverage = {"evidence":"artifacts/reports/"+coverage_name,**message_address_coverage}
    message_tick_coverage = None
    tick_coverage_name = ("esp32-message-tick-coverage-v2.json" if
        (EVIDENCE/"esp32-message-tick-coverage-v2.json").is_file() else "esp32-message-tick-coverage-v1.json")
    if (EVIDENCE/tick_coverage_name).is_file():
        from audit_esp32_ram_scope import tick_coverage
        message_tick_coverage = tick_coverage(tick_coverage_name.endswith('v2.json'))
        if message_tick_coverage != read_json(tick_coverage_name):
            raise ValueError("Native-tick message image address coverage differs")
        message_tick_coverage = {"evidence":"artifacts/reports/"+tick_coverage_name,**message_tick_coverage}
    allocated_reservations = None
    reservation_report = EVIDENCE/'esp32-freertos-allocated-reservations-v1.json'
    if reservation_report.exists():
        from audit_esp32_allocated_reservations import audit as reservation_audit, summary
        checked = reservation_audit(ROOT)
        if checked != json.loads(reservation_report.read_text()):
            raise ValueError('Startup reservation ownership replay differs')
        allocated_reservations = {**summary(checked),
            'evidence':'artifacts/reports/'+reservation_report.name, 'sha256':sha(reservation_report)}
    startup_cohort = None
    startup_cohort_report = EVIDENCE/'esp32-startup-reservation-cohort-v1.json'
    if startup_cohort_report.exists():
        from audit_esp32_allocated_reservations import cohort_audit, cohort_summary
        checked = cohort_audit(ROOT)
        if checked != json.loads(startup_cohort_report.read_text()):
            raise ValueError('Three-system startup reservation cohort differs')
        startup_cohort = {**cohort_summary(checked),
            'evidence':'artifacts/reports/'+startup_cohort_report.name,'sha256':sha(startup_cohort_report)}
    native_network_groups = []
    nuttx_compact_ram = None
    compact_ram_report = EVIDENCE/'esp32-nuttx-compact-allocated-v1.json'
    if compact_ram_report.exists():
        from audit_esp32_allocated_reservations import compact_nuttx_audit, compact_nuttx_summary
        checked = compact_nuttx_audit(ROOT)
        if checked != json.loads(compact_ram_report.read_text()):
            raise ValueError('Compact NuttX RAM differs from native source/raw replay')
        nuttx_compact_ram = {**compact_nuttx_summary(checked),
            'evidence':'artifacts/reports/'+compact_ram_report.name,'sha256':sha(compact_ram_report)}
    allocated_bookkeeping = None
    bookkeeping_report = EVIDENCE/'esp32-allocated-bookkeeping-v1.json'
    if bookkeeping_report.exists():
        from audit_esp32_allocated_reservations import bookkeeping_audit, bookkeeping_summary
        checked = bookkeeping_audit(ROOT)
        if checked != json.loads(bookkeeping_report.read_text()):
            raise ValueError('Allocated software bookkeeping replay differs')
        allocated_bookkeeping = {**bookkeeping_summary(checked),
            'evidence':'artifacts/reports/'+bookkeeping_report.name,'sha256':sha(bookkeeping_report)}
    loader_coverage = []
    zephyr_ownership_pairs = None
    ownership_name='esp32-zephyr-ownership-observer-pairs-b1-v2'
    if (EVIDENCE/ownership_name/'audit.json').is_file():
        from run_esp32_message_observer_pairs import audit as ownership_audit
        checked=ownership_audit(EVIDENCE/ownership_name)
        independent=replay(EVIDENCE/ownership_name)
        if checked!=read_json(ownership_name+'/audit.json') or independent['cells']!=[
                {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in checked['cells']]:
            raise ValueError('Zephyr entry-vector observer paired source/count replay differs')
        zephyr_ownership_pairs={'evidence':'artifacts/reports/'+ownership_name+'/audit.json',**checked}
    nuttx_loader_pairs = None
    nuttx_pair_name='esp32-nuttx-compact-loader-observer-pairs-b1-v1'
    if (EVIDENCE/nuttx_pair_name/'audit.json').is_file():
        from run_esp32_message_observer_pairs import audit as nuttx_pair_audit
        checked=nuttx_pair_audit(EVIDENCE/nuttx_pair_name)
        separate=replay(EVIDENCE/nuttx_pair_name)
        if checked!=read_json(nuttx_pair_name+'/audit.json') or separate['cells']!=[
                {k:c[k] for k in ('os','pairs','median_ratio','ratio_range')} for c in checked['cells']]:
            raise ValueError('NuttX compact matched-loader source/count replay differs')
        nuttx_loader_pairs={'evidence':'artifacts/reports/'+nuttx_pair_name+'/audit.json',**checked}
    energy_gain_scenario = None
    gain_report=EVIDENCE/'esp32-energy-gain-scenario-v1.json'
    if gain_report.is_file():
        from audit_esp32_energy_gain_scenario import audit as gain_audit, summary as gain_summary
        checked=gain_audit(ROOT)
        if checked!=read_json(gain_report.name):
            raise ValueError('Energy gain scenario differs from retained raw replay')
        energy_gain_scenario={**gain_summary(checked),'evidence':'artifacts/reports/'+gain_report.name,'sha256':sha(gain_report)}
    allocated_lifecycle = None
    allocated_capacity = None
    if (EVIDENCE/'esp32-active-rom-allocated-capacity-v1.json').is_file():
        from esp32_allocated_capacity_publication import summary as capacity_summary
        allocated_capacity=capacity_summary(ROOT)
    lifecycle_report = EVIDENCE/'esp32-allocated-lifecycle-v1.json'
    if lifecycle_report.is_file():
        from audit_esp32_allocated_lifecycle import audit as lifecycle_audit, summary as lifecycle_summary
        checked = lifecycle_audit(ROOT)
        if checked != read_json(lifecycle_report.name):
            raise ValueError('RAM allocated-capacity model differs from source/raw replay')
        allocated_lifecycle = {**lifecycle_summary(checked),
            'evidence':'artifacts/reports/'+lifecycle_report.name,'sha256':sha(lifecycle_report)}
    zephyr_loader_report = EVIDENCE/'esp32-zephyr-loader-coverage-v1.json'
    if zephyr_loader_report.is_file():
        from audit_esp32_zephyr_loader import audit as zephyr_loader_audit
        checked = zephyr_loader_audit(ROOT)
        if checked != read_json(zephyr_loader_report.name):
            raise ValueError('Zephyr native simple-loader coverage changed')
        loader_coverage.append({'os':'Zephyr', 'reused_resets':checked['reused_resets'],
            'new_resets':0, 'software_peak_bytes':checked['runs'][0]['software_peak_bytes'],
            'loader_already_in_static_bytes':checked['simple_loader_already_in_static_bytes'],
            'state':'ROM 进入同一镜像后，已覆盖简单启动器与原消息任务；加载器不重复计数',
            'evidence':'artifacts/reports/'+zephyr_loader_report.name,'sha256':sha(zephyr_loader_report)})
    nuttx_loader_folder = EVIDENCE/'esp32-nuttx-observed-loader-b1-v1'
    if (nuttx_loader_folder/'audit.json').is_file():
        from measure_esp32_nuttx_bootloader import audit as nuttx_loader_audit
        checked = nuttx_loader_audit(ROOT,nuttx_loader_folder)
        if checked != read_json(nuttx_loader_folder.name+'/audit.json'):
            raise ValueError('NuttX diagnostic loader intervention changed')
        loader_coverage.append({'os':'NuttX', 'reused_resets':0,
            'new_resets':checked['independent_resets'],
            'validation_resets':checked['separate_validation_resets'],
            'software_peak_bytes':checked['runs'][0]['software_peak_bytes'],
            'loader_static_bytes':checked['bootloader_static_bytes'],
            'state':'仅替换诊断启动器，应用与配置不变；原生分配归属与旧五轮一致',
            'evidence':'artifacts/reports/'+nuttx_loader_folder.name+'/audit.json',
            'sha256':sha(nuttx_loader_folder/'audit.json')})
    rhino_bootstrap_reclamation = None
    reclamation_name = "esp32-rhino-message-boot-reclamation-v1.json"
    if (EVIDENCE/reclamation_name).is_file():
        from audit_esp32_rhino_message_reclamation import audit as reclamation_audit
        rhino_bootstrap_reclamation = reclamation_audit()
        if rhino_bootstrap_reclamation != read_json(reclamation_name):
            raise ValueError("Rhino original-message bootstrap contrast differs")
        rhino_bootstrap_reclamation = {"evidence":"artifacts/reports/"+reclamation_name,**rhino_bootstrap_reclamation}
        progress.append({"name":"Rhino 原消息任务的启动回收条件",
            "state":"原 GCC5 配置五轮复现 8872 B 差异；启动线程自然回收后另五轮终点一致，实际栈/控制块与原生释放记录闭合",
            "missing":"本项为启动条件诊断，不是无观察器 RAM 或 GCC13 主组成绩；整机 RAM 仍正在测、不计分"})
    from run_esp32_native_network_b1 import audit as audit_native_network
    for system in ("Rhino", "RIOT"):
        prefix = "esp32-native-network-" + system.lower() + "-b1-"
        name = prefix + ("v2" if (EVIDENCE/(prefix+"v2")/"audit.json").exists() else "v1")
        if (EVIDENCE/name/"audit.json").exists():
            result = audit_native_network(EVIDENCE/name)
            if result != read_json(name+"/audit.json"):
                raise ValueError("B1 native network source/packet replay differs")
            native_network_groups.append({"evidence":"artifacts/reports/"+name+"/audit.json",**result})
    return {"schema": "iot-os-publication-view-v1", "rows": rows, "candidates": candidates,
            "measurement_through": max([read_json(name+"/campaign.json")["completed_utc"][:10]
                for name,present in ((common_name,common_tcp),(udp_name,common_udp),
                                     (receiver_name,common_udp_receiver),(clock_name,receiver_clock_control),
                                     (source_path_name,source_path_diagnosis),
                                     ("esp32-message-steps-observer-pairs-b1-v1",continuous_pairs),
                                     (queue_control_name,source_queue_control_result),
                                     (address_name,allocation_addresses),(address_pairs_name,address_pairs),
                                     (stack_name,message_stack),(stack_pairs_name,stack_pairs),
                                     (freertos_stack_name,freertos_message_stack),(freertos_pairs_name,freertos_stack_pairs),
                                     (tick_capture,freertos_tick_stacks),(tick_pairs_capture,freertos_tick_pairs),
                                     (ztick_capture,zephyr_tick_stacks),(ztick_pairs_capture,zephyr_tick_pairs),
                                     (ntick_capture,nuttx_tick_stacks),(ntick_pairs_capture,nuttx_tick_pairs),
                                     (control_capture,nuttx_tick_control),(controlled_capture,nuttx_controlled_stacks),
                                     (controlled_pairs_capture,nuttx_controlled_pairs)) if present],
                default=followup["date"] if followup else "2026-10-19"),
            "native_network_groups": native_network_groups, "common_original_tcp": common_tcp,
            "common_original_udp": common_udp, "common_original_udp_receiver": common_udp_receiver,
            "udp_receiver_clock_control": receiver_clock_control,
            "udp_source_path_diagnostic": source_path_diagnosis,
            "udp_source_queue_control": source_queue_control_result,
            "nuttx_allocation_addresses": allocation_addresses,
            "nuttx_address_observer_pairs": address_pairs,
            "message_startup_scope": startup_scope,
            "freertos_message_startup": freertos_message_startup,
            "freertos_boot_stage": boot_stage,
            "freertos_allocated_reservations": allocated_reservations,
            "startup_reservation_cohort": startup_cohort,
            "allocated_software_bookkeeping": allocated_bookkeeping,
            "nuttx_compact_ram": nuttx_compact_ram,
            "loader_coverage": loader_coverage,
            "allocated_lifecycle": allocated_lifecycle,
            "allocated_capacity": allocated_capacity,
            "zephyr_ownership_pairs": zephyr_ownership_pairs,
            "nuttx_loader_pairs": nuttx_loader_pairs,
            "energy_gain_scenario": energy_gain_scenario,
            "freertos_continuous_memory": continuous_memory,
            "freertos_boundary_memory": boundary_memory,
            "freertos_native_sp_memory": native_memory,
            "freertos_combined_stacks": combined_memory,
            "freertos_startup_observer_pairs": freertos_startup_pairs,
            "freertos_tick_stacks": freertos_tick_stacks,
            "freertos_tick_observer_pairs": freertos_tick_pairs,
            "zephyr_tick_stacks": zephyr_tick_stacks,
            "zephyr_tick_observer_pairs": zephyr_tick_pairs,
            "nuttx_tick_stacks": nuttx_tick_stacks,
            "nuttx_tick_observer_pairs": nuttx_tick_pairs,
            "nuttx_tick_control": nuttx_tick_control,
            "nuttx_controlled_tick_stacks": nuttx_controlled_stacks,
            "nuttx_controlled_tick_observer_pairs": nuttx_controlled_pairs,
            "nuttx_message_startup": nuttx_message_startup,
            "zephyr_message_startup": zephyr_message_startup,
            "zephyr_startup_observer_pairs": zephyr_startup_pairs,
            "nuttx_startup_observer_pairs": nuttx_startup_pairs,
            "freertos_compact_ram": compact_ram,
            "zephyr_message_stack": message_stack,
            "zephyr_stack_observer_pairs": stack_pairs,
            "freertos_message_stack": freertos_message_stack,
            "freertos_stack_observer_pairs": freertos_stack_pairs,
            "main_cohort": list(PRIMARY), "main_cases": list(protocol["case_orders"]),
            "b1_message": message, "b1_kernel": kernel, "latency_comparison": latency,
            "isr_comparison": isr,
            "native_alignment": alignment, "native_suite": native_suite, "ram_lifecycle": lifecycle, "controlled_network": network,
            "freertos_ram_lifecycle": freertos_lifecycle,
            "zephyr_ram_lifecycle": zephyr_lifecycle,
            "riot_ram_lifecycle": riot_lifecycle,
            "rhino_ram_lifecycle": rhino_lifecycle,
            "rhino_stack_coverage": rhino_stack_coverage,
            "freertos_stack_coverage": freertos_stack_coverage,
            "riot_stack_coverage": riot_stack_coverage,
            "zephyr_stack_coverage": zephyr_stack_coverage,
            "ram_scope": ram_scope,
            "message_ram_lifecycle": message_ram,
            "observer_static_ownership": observer_static_ownership,
            "message_address_coverage": message_address_coverage,
            "message_tick_coverage": message_tick_coverage,
            "rhino_bootstrap_reclamation": rhino_bootstrap_reclamation,
            "message_observer_pairs": observer_pairs,
            "b1_energy": b1_energy,
            "b1_kernel_energy": b1_kernel_energy,
            "native_riot_message": native_riot_message,
            "nuttx_riot_message": nuttx_riot_message,
            "rhino_riot_message": rhino_riot_message,
            "controlled_udp": udp_network, "native_irq_semantics": irq_semantics,
            "implementation_progress": progress, "historical_data_modified": False}


def script_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
                      sort_keys=True).replace("<", "\\u003c")


def render(data):
    from audit_esp32_composite_policy import review
    from standardize_esp32_benchmark import standardize

    template = (ROOT / "tools/templates/esp32_benchmark.html").read_text(encoding="utf-8")
    payload = script_json(data)
    if any(template.count(slot) != 1 for slot in ("__BENCHMARK_DATA__", "__SCORE_REVIEW__", "__PROTOCOL_DATA__", "__FOLLOWUP_DATA__", "__PUBLICATION_VIEW__", "__CATEGORY_SCORES__", "__CATEGORY_SCOPE__")):
        raise ValueError("ambiguous embedded dataset slot")
    policy = review(data)
    rows = ''.join('<tr><td>{}</td><td>{:.2f}</td><td>{:.2f}</td><td>{:.2f}</td><td>{:.2f}</td></tr>'.format(
        row['os'], row['components']['throughput'], row['components']['realtime'], row['components']['energy'], row['total'])
        for row in policy['draft_equal_weight_scores'])
    table = '<div class="table-wrap"><table id="score-draft"><thead><tr><th>旧板三配置组</th><th>吞吐</th><th>实时负载</th><th>能耗</th><th>等权草案总分</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
    protocol_data, followup = standardize(data), followup_data()
    encode = script_json
    view = publication_view(data, protocol_data, followup)
    mainboard_path=EVIDENCE/'esp32-unified-mainboard-v1.json'
    if mainboard_path.is_file():
        from esp32_unified_mainboard_results import audit as mainboard_audit
        from esp32_mainboard_figure import svg,html_summary,publication_summary
        checked=mainboard_audit()
        if checked!=read_json(mainboard_path.name):
            raise ValueError('Five-system mainboard source/raw replay differs')
        view['unified_mainboard']=publication_summary(checked)
        chart=svg(checked)+html_summary(checked)
        scope='五系统四类分项均已完成同口径核验，综合分按冻结的等权几何平均计算。RAM 为各系统原消息任务固定观察镜像的完整声明生命周期峰值分配占用，含观察器；实际栈使用另列。不同类别使用其对应镜像，不将 RAM 观察镜像的能耗或性能冒充原应用结果。'
    else:
        from esp32_category_scores import from_view,svg
        view['category_scores']=from_view(view)
        chart=svg(view['category_scores'])
        scope='RAM 斜线柱比较 F1／Z1／N1 固定观察镜像的峰值分配占用，包含观察器，采用参考占用／本项占用 × 100；不代表无观察器 OS 内存排名。三个系统在各类别使用其对应测试镜像。下方同时列 RIOT、AliOS／Rhino 的已测原生配置：内核和配对能量保留实测值，通信各用原测试单位，整机 RAM 继续正在测。两者未套入上方控制组评分；各类别不设加权总分。'
    from iotos_evolution import baseline_inventory
    view["generative_benchmark"] = baseline_inventory(data, view)
    return template.replace("__CATEGORY_SCORES__", chart).replace("__CATEGORY_SCOPE__",scope).replace("__BENCHMARK_DATA__", payload).replace("__SCORE_REVIEW__", table).replace("__PROTOCOL_DATA__", encode(protocol_data)).replace("__FOLLOWUP_DATA__", encode(followup)).replace("__PUBLICATION_VIEW__", encode(view))


def validate(data):
    if data["schema"] != "iot-os-benchmark-report-v1" or data["new_board_boots"] or data["new_measurements"] or \
            data["new_metric_created"] or data["composite_score"] is not None or len(data["support"]) != 12 or data["sources"] != SOURCES:
        raise ValueError("publication identity or evidence scope differs")
    for record in data["inputs"]:
        path = (ROOT / record["path"]).resolve()
        if not path.is_relative_to(ROOT) or sha(path) != record["sha256"]:
            raise ValueError("publication snapshot source changed: " + record["path"])
    for row in data["rows"]:
        if row["os"] not in OS_NAMES or stats(row["values"])["median"] != row["median"] or \
                stats(row["values"])["range"] != row["range"]:
            raise ValueError("publication repetition statistics differ")
    energy = read_json("powerz-thread-metric-energy-20261009-corrected/summary.json")
    corrected = read_json("esp32-public-extensions-v1.json")["separate_alios_original_tm_irq_vector_corrected"]["cells"]
    sources = {(r["os"], r["case"]): (r["runs"], "powerz-thread-metric-energy-20261009-corrected/summary.json")
               for r in energy["cells"]}
    sources.update({(r["os"], r["case"]): (r["energy_runs"], "esp32-public-extensions-v1.json:separate_alios_original_tm_irq_vector_corrected")
                    for r in corrected})
    fields = {"每原操作整板能耗": "energy_per_original_count_uj", "整板输入平均功率": "steady_average_power_w"}
    expected = {(os, case, metric) for os, case in sources for metric in fields}
    for row in (r for r in data["rows"] if r["section"] == "energy"):
        identity = row["os"], row["extra"]["workload"], row["metric"]
        if identity not in expected:
            raise ValueError("missing or duplicate energy identity")
        expected.remove(identity)
        runs, evidence = sources[identity[:2]]
        if row["evidence"] != evidence or row["values"] != [r[fields[row["metric"]]] for r in runs]:
            raise ValueError("energy evidence does not reproduce published values")
    if expected:
        raise ValueError("energy publication is incomplete")
    ledger = data["gap_ledger"]
    if set(ledger) != {"path", "sha256"} or ledger["path"] != "ESP32_BENCHMARK_GAPS.md" or \
            ledger["sha256"] != sha(ROOT / ledger["path"]):
        raise ValueError("gap ledger identity differs from the canonical source")
    if any(r["measured"] or r["board_boots"] for r in data["pending_builds"]):
        raise ValueError("unmeasured build acquired a board result")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, help="Render an already audited snapshot without rerunning source audits")
    args = parser.parse_args()
    data = json.loads(args.snapshot.read_text(encoding="utf-8")) if args.snapshot else assemble()
    validate(data)
    payload = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    html = ROOT / "benchmark_esp32.html"
    rendered = render(data)
    for destination, content in ((OUTPUT, payload), (html, rendered)):
        temporary = destination.with_name(destination.name + ".tmp")
        try:
            temporary.write_text(content, encoding="utf-8")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    print(f"Published {len(data['rows'])} historical rows and separate audited B1 results; rendering acquires no board data")


if __name__ == "__main__":
    main()
