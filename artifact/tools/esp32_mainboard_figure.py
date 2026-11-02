#!/usr/bin/env python3
"""Draw all five B1 configurations only from the complete unified evidence result."""
import argparse
from html import escape
import json
import math
from pathlib import Path

from audit_esp32_unified_mainboard import overall_scores
from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
SYSTEMS=('FreeRTOS','Zephyr','NuttX','RIOT','AliOS-Rhino')
COLORS=('#16786c','#b75b25','#526cc1','#b63849','#59656a')
HATCHES=('', '//', '\\\\', '..', 'xx')
GROUPS=(('kernel','内核性能','Kernel\nthroughput'),('network','UDP 接收吞吐','Fixed-load UDP\nreception'),
    ('energy','消息任务能效','Message energy\nefficiency'),('ram','观察镜像 RAM 指数','Inverse RAM index\n(observer-inclusive)'),
    ('overall','综合分','Overall'))


def chart_view(data):
    if data.get('audit')!='pass' or data.get('schema')!='esp32-unified-mainboard-v1' or \
            data.get('board_mac')!='34:98:7a:a2:85:28' or not data.get('all_mandatory_categories_qualified') or \
            data.get('qualified_systems')!=list(SYSTEMS):
        raise ValueError('A complete qualified five-system mainboard result is required')
    categories=data['categories']
    if [c['id'] for c in categories]!=[g[0] for g in GROUPS[:-1]] or \
            any(c['weight']!=.25 for c in categories):
        raise ValueError('Figure categories differ from the frozen equal-weight rule')
    rows=data['rows'];totals=overall_scores(rows);by_os={r['os']:r for r in rows}
    for os,row in by_os.items():
        if not row.get('ram_observer_included') or not math.isclose(row['overall_score'],totals[os],rel_tol=1e-12):
            raise ValueError('Figure total or RAM observation boundary differs')
        rank=1+sum(v>totals[os] and not math.isclose(v,totals[os],rel_tol=1e-10) for v in totals.values())
        if row['rank']!=rank:
            raise ValueError('Figure rank differs from the recomputed composite')
    groups=[]
    for key,zh,en in GROUPS:
        field='overall_score' if key=='overall' else key+'_index'
        groups.append({'id':key,'label':zh,'english_label':en,'cells':[
            {'os':os,'score':by_os[os][field]} for os in SYSTEMS]})
    return {'systems':list(SYSTEMS),'groups':groups,'rows':[by_os[s] for s in SYSTEMS],
        'baseline':'FreeRTOS','reference_score':100,'ram_observer_included':True,
        'overall_weights':{c['id']:c['weight'] for c in categories}}


def publication_summary(data):
    view=chart_view(data)
    messages={r['os']:r for r in data['kernel_energy_raw_cells'] if r['case']=='message_processing'}
    if set(messages)!=set(SYSTEMS):
        raise ValueError('All five paired original-message energy values are required')
    rows=[]
    for r in view['rows']:
        rows.append({k:r[k] for k in ('os','rank','overall_score','kernel_index','network_index',
            'energy_index','ram_index','network_mbit_s','peak_allocated_ram_bytes')})
        rows[-1].update(network_range_mbit_s=[min(r['network_reset_values_mbit_s']),max(r['network_reset_values_mbit_s'])],
            ram_range_bytes=[min(r['ram_reset_values_bytes']),max(r['ram_reset_values_bytes'])],
            energy_uj_per_original_count=messages[r['os']]['median_energy_uj_per_count'])
    return {'schema':data['schema'],'board_mac':data['board_mac'],'rows':rows,
        'category_weights':view['overall_weights'],'weight_sensitivity':data['weight_sensitivity'],
        'category_relationships':data['category_relationships'],'ram_observer_included':True,
        'evidence':'artifacts/reports/esp32-unified-mainboard-v1.json'}


def html_summary(data):
    view=publication_summary(data);rows=sorted(view['rows'],key=lambda r:r['rank'])
    columns=('kernel_index','network_index','energy_index','ram_index','overall_score')
    table=['<div class="table-wrap"><table id="unified-mainboard"><thead><tr><th>OS</th>',
        '<th>内核性能</th><th>通信吞吐</th><th>消息任务能效</th><th>峰值分配 RAM</th>',
        '<th>综合分</th><th>名次</th></tr></thead><tbody>']
    for r in rows:
        table.append('<tr><td>%s</td>'%escape('AliOS/Rhino' if r['os']=='AliOS-Rhino' else r['os']))
        table.extend('<td>%.2f</td>'%r[c] for c in columns)
        table.append('<td>%d</td></tr>'%r['rank'])
    table.append('</tbody></table></div><p class="table-foot">同一 B1 板、240 MHz、单核。'
        '各分项以 FreeRTOS = 100 固定归一化；四类各占 25%，综合分取几何平均。'
        '原生调度、tick、SDK 和库是被测配置的一部分；RAM 包含固定观察器。</p>')
    table.append('<details><summary>原始指标与权重敏感性</summary><div class="table-wrap"><table>'
        '<thead><tr><th>OS</th><th>UDP 接收 / Mbit/s</th><th>消息能量 / μJ·原计数</th>'
        '<th>峰值分配 RAM / B</th><th>权重变化下名次范围</th></tr></thead><tbody>')
    ranges=view['weight_sensitivity']['rank_ranges']
    for r in rows:
        table.append('<tr><td>%s</td><td>%.3f<span class="subline">%.3f–%.3f</span></td>'
            '<td>%.4f</td><td>%s<span class="subline">%s–%s</span></td><td>%d–%d</td></tr>'%
            (escape(r['os']),r['network_mbit_s'],*r['network_range_mbit_s'],r['energy_uj_per_original_count'],
             format(r['peak_allocated_ram_bytes'],',.0f'),*(format(v,',.0f') for v in r['ram_range_bytes']),*ranges[r['os']]))
    rel=view['category_relationships']
    table.append('</tbody></table></div><p class="table-foot">网络及 RAM 为各五次独立冷启动的中位数与 min–max；'
        '内核与配对能耗各原测试每系统三次独立启动。'
        '敏感性采用预定的 %d 组权重，不是测量置信区间。'
        '五配置内核／能效分项相关系数 r = %.3f；消息吞吐／能效 r = %.3f，'
        '能效包含吞吐因素，不能当作独立证据。<a href="%s">统一原始指标及核验记录</a></p></details>'%
        (view['weight_sensitivity']['weight_profiles'],rel['kernel_energy_index_pearson_r'],
         rel['message_rate_efficiency_pearson_r'],escape(view['evidence'])))
    return ''.join(table)


def svg(data):
    view=chart_view(data);left,right,top,bottom=68,1140,64,330
    ymax=50*math.ceil(max(100,max(c['score'] for g in view['groups'] for c in g['cells']))*1.18/50)
    scale=lambda value:bottom-value/ymax*(bottom-top)
    step=max(50,50*math.ceil(ymax/400))
    parts=['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1160 430" role="img" '
        'aria-label="ESP32 B1 五系统统一分项与综合评分"><style>text{font:13px system-ui,sans-serif;fill:#263437}</style>',
        '<rect width="1160" height="430" fill="white"/>']
    for i,os in enumerate(SYSTEMS):
        name='AliOS/Rhino' if os=='AliOS-Rhino' else os;x=left+i*205
        parts.append('<rect x="%d" y="15" width="16" height="14" fill="%s"/>'
            '<text x="%d" y="27">%s</text>'%(x,COLORS[i],x+24,name))
    for tick in range(0,int(ymax)+1,step):
        y=scale(tick)
        parts.append('<path d="M%d %.2fH%d" stroke="#dfe5e4"/>'
            '<text x="%d" y="%.2f" text-anchor="end">%d</text>'%(left,y,right,left-10,y+5,tick))
    parts.append('<path d="M%d %.2fH%d" stroke="#5f6a6d" stroke-dasharray="5 4"/>'%(left,scale(100),right))
    width=(right-left)/len(view['groups'])
    for i,group in enumerate(view['groups']):
        center=left+(i+.5)*width
        for j,cell in enumerate(group['cells']):
            x=center-81+j*34;y=scale(cell['score']);label=escape(cell['os'])
            parts.append('<rect data-os="%s" data-category="%s" x="%.2f" y="%.2f" width="26" height="%.2f" fill="%s">'
                '<title>%s | %s: %.3f (FreeRTOS = 100)</title></rect>'%
                (label,group['id'],x,y,bottom-y,COLORS[j],label,escape(group['label']),cell['score']))
            parts.append('<text x="%.2f" y="%.2f" text-anchor="middle" style="font-size:11px">%.1f</text>'%
                (x+13,y-6,cell['score']))
        parts.append('<text x="%.2f" y="355" text-anchor="middle">%s</text>'%(center,escape(group['label'])))
    parts.append('<text x="68" y="391" style="font-size:12px">FreeRTOS = 100；越高越好；综合分为四类分项各占 25% 的几何平均。</text>')
    parts.append('<text x="68" y="414" style="font-size:12px">* RAM 为原消息测试固定观察镜像的峰值分配占用，包含测量观察器；实际栈使用另列。</text></svg>')
    return ''.join(parts)


def plot(data,output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    view=chart_view(data)
    plt.rcParams.update({'font.family':'DejaVu Serif','font.size':9,'pdf.fonttype':42})
    fig,ax=plt.subplots(figsize=(7,2.9))
    maximum=max(c['score'] for g in view['groups'] for c in g['cells'])
    ymax=50*math.ceil(max(100,maximum)*1.18/50)
    for j,os in enumerate(SYSTEMS):
        scores=[g['cells'][j]['score'] for g in view['groups']]
        ax.bar([i+(j-2)*.16 for i in range(5)],scores,.135,color=COLORS[j],
            hatch=HATCHES[j],edgecolor='white',linewidth=.35,
            label='AliOS/Rhino' if os=='AliOS-Rhino' else os,zorder=3)
    ax.set_ylim(0,ymax);ax.set_ylabel('Reference index')
    ax.axvspan(3.55,4.45,color='#eef0f0',zorder=0)
    ax.axvline(3.5,color='#b6bcbc',lw=.7,zorder=1)
    ax.set_xticks(range(5));ax.set_xticklabels([g['english_label'] for g in view['groups']])
    ax.axhline(100,color='#666666',lw=.8,ls='--',zorder=2)
    ax.grid(axis='y',color='#e2e6e5',lw=.6,zorder=0)
    ax.spines['top'].set_visible(False);ax.spines['right'].set_visible(False)
    ax.legend(frameon=False,ncol=5,loc='lower left',bbox_to_anchor=(0,1.02),fontsize=8.5,
        columnspacing=1,handlelength=1.7)
    fig.subplots_adjust(left=.09,right=.99,top=.83,bottom=.24)
    fig.text(.09,.025,'FreeRTOS = 100. Overall: equal-weight configuration-bundle aggregate; RAM includes observers.',fontsize=8)
    fig.savefig(str(output),metadata={'CreationDate':None,'ModDate':None});plt.close(fig)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('svg','plot'));parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--receipt',type=Path)
    args=parser.parse_args()
    if ROOT!=Path('/home/reviewer/esp32-pilot/audit-workspace') or args.output.exists():
        parser.error('Replay and stage a fresh evidence-bound figure on leon')
    from esp32_unified_mainboard_results import audit
    data=json.loads(args.input.read_text())
    if data!=audit():raise ValueError('Figure input does not match the complete raw/source replay')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.mode=='svg':args.output.write_text(svg(data),encoding='utf-8')
    else:plot(data,args.output)
    if args.receipt:
        with args.receipt.open('x') as f:json.dump({'audit':'pass','renderer_sha256':sha(Path(__file__)),
            'input_sha256':sha(args.input),'figure_sha256':sha(args.output),'view':chart_view(data)},f,indent=2);f.write('\n')
