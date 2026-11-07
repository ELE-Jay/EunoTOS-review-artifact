"""Declared measurement targets, not a decomposition of measured OS costs."""
import copy

HYBRID = 'Contiki-NG + ESP-IDF/FreeRTOS'


def deployment_scope(rows):
    profiles = []
    for row in rows:
        name = row['os']
        kernel = 'Zephyr' if name.startswith('Zephyr') else 'Rhino' if name == 'AliOS Things' else name
        hosted = name == HYBRID
        network = {'FreeRTOS': 'ESP-IDF lwIP on FreeRTOS', 'Rhino': 'AliOS lwIP on Rhino',
                   'RIOT': 'RIOT socket and network port', 'NuttX': 'NuttX network stack',
                   'Zephyr': 'Zephyr network stack'}.get(kernel)
        if not hosted and network is None:
            raise ValueError('Unreviewed deployment identity: ' + name)
        label = ('Contiki-NG + FreeRTOS' if hosted else
                 'Zephyr (direct prompting)' if name == 'Zephyr C2-1 (Qwen)' else name)
        profiles.append({'configuration': name, 'display_name': label,
            'runtime_build': row.get('runtime_build'), 'observer_build': row.get('observer_build'),
            'host_kernel': 'FreeRTOS' if hosted else None,
            'task_dispatch': 'Contiki process queue on a FreeRTOS event-loop task' if hosted else kernel + ' native task and queue services',
            'communication': 'IDF lwIP and FreeRTOS networking, ingress queue, Contiki checksum worker and reply path' if hosted else network + ', application worker and complete UDP transaction',
            'energy': 'Whole B1 input during the marked phase, including radio, runtime and host where present; not an isolated kernel energy measurement',
            'ram': 'Whole declared instrumented deployment allocation peak, including the host where present; not standalone kernel RAM',
            'task_boundary': 'Submission to verified completion, including copy and queue waiting; excludes earlier release and ingress waiting',
            'component_costs_separately_measured': False})
    return {'schema': 'eunobench-deployment-attribution-v1', 'comparison_unit': 'deployed_configuration',
            'native_os_capability_ranking': False, 'profiles': profiles}


def require_deployment_scope(data, requested_unit='deployed_configuration'):
    """Shared admission for the actual figure, table and public summary replay."""
    if requested_unit != 'deployed_configuration':
        raise ValueError('These measurements do not qualify an isolated native-OS ranking')
    rows = data.get('rows', data.get('score_rows', []))
    expected = deployment_scope(rows)
    if data.get('comparison_scope') != expected:
        raise ValueError('Missing or changed deployment attribution; host services must not be relabeled as native OS capability')
    return copy.deepcopy(expected)
