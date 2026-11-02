#!/usr/bin/env python3
"""Collect the original Rhino iPerf or RIOT UDP test on B1 with Wi-Fi recovery."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MAC = "34:98:7a:a2:85:28"
BSSID = "34:98:7a:a2:85:29"
DEVICE = "wlxa41a3ad16459"
REFERENCES = {"Rhino": "alios-iperf-original-v10", "RIOT": "riot-benchmark-udp-original-v2"}
CASES = {"Rhino": ("tcp_tx", "tcp_rx", "udp_tx", "udp_rx"),
         "RIOT": ("default", "payload1024-interval1000")}
IMAGES = ("application.elf", "application.bin", "bootloader.bin", "partitions.bin")
QUEUE_PROFILE = "mq-four-pfifo-10240-v1"
NEIGHBOR_PROFILE = "fixed-b1-ipv4-neighbor-v1"
FQ_OPTIONS = {"limit":10240,"flows":1024,"quantum":1514,"target":4999,
              "interval":99999,"memory_limit":33554432,"ecn":True}


def queue_rows(raw):
    # This host's older tc emits {limit 10240p} for pfifo even with -j.
    normalized=re.sub(r'("options"\s*:\s*)\{limit (\d+)p\}',r'\1{"limit":\2}',raw)
    return json.loads(normalized)


def queue_config(raw):
    """Validate this host's four queues, ignoring kernel-assigned object handles."""
    rows = queue_rows(raw)
    roots = [r for r in rows if r.get("root")]
    leaves = [r for r in rows if "parent" in r]
    if len(rows)!=5 or len(roots)!=1 or roots[0]["kind"]!="mq" or roots[0].get("options")!={} or \
            roots[0].get("handle") not in ("0:","1:") or len(leaves)!=4:
        raise ValueError("Unexpected source TX queue topology")
    major="" if roots[0]["handle"]=="0:" else "1"
    if {r["parent"] for r in leaves}!={major+p for p in (":1",":2",":3",":4")}:
        raise ValueError("Source TX queue parents differ from their root")
    result = {}
    for row in leaves:
        kind, options = row["kind"], row.get("options")
        if not ((kind=="fq_codel" and options==FQ_OPTIONS) or
                (kind=="pfifo" and options=={"limit":10240})):
            raise ValueError("Unexpected source TX queue options")
        result[":"+row["parent"].split(":")[1]] = kind
    return result


def source_queue(state_path, run, *, restore=False):
    state = json.loads(state_path.read_text())
    if state.get("source_queue_profile")!=QUEUE_PROFILE or state.get("device")!=DEVICE or \
            queue_config(state["source_queue_original"]["output"])!={p:"fq_codel" for p in (":1",":2",":3",":4")} or \
            next(r["handle"] for r in queue_rows(state["source_queue_original"]["output"]) if r.get("root"))!="0:":
        raise ValueError("Source queue recovery state differs from the frozen host profile")
    actions = []
    before = run(["tc","-j","-d","qdisc","show","dev",DEVICE])
    current = queue_config(before["output"])
    # Persist recovery intent before the first privileged mutation.
    if not restore:
        state["source_queue_restore_pending"] = True
        save(state_path,state)
    def mutate(arguments):
        result=run(arguments,True,False)
        actions.append(result)
        if result["returncode"]:
            save(state_path.with_name("source-queue-failure.json"),{"restoring":restore,"before":before,"actions":actions})
            raise RuntimeError("Source queue mutation failed: "+result["output"])
    root=next(r["handle"] for r in queue_rows(before["output"]) if r.get("root"))
    if restore:
        if root=="1:":
            mutate(["tc","qdisc","del","dev",DEVICE,"root"])
    else:
        if root=="0:":
            # The implicit mq root cannot be addressed as parent :1. Give it a handle first.
            mutate(["tc","qdisc","replace","dev",DEVICE,"root","handle","1:","mq"])
            current=queue_config(run(["tc","-j","-d","qdisc","show","dev",DEVICE])["output"])
        for parent in sorted(current):
            if current[parent]!="pfifo":
                mutate(["tc","qdisc","replace","dev",DEVICE,"parent","1"+parent,"pfifo","limit","10240"])
    after = run(["tc","-j","-d","qdisc","show","dev",DEVICE])
    if not restore:
        save(state_path.with_name("source-queue-applied.json"),{"before":before,"actions":actions,"after":after})
    desired = "fq_codel" if restore else "pfifo"
    if queue_config(after["output"])!={p:desired for p in current}:
        raise RuntimeError("Source TX queue configuration did not reach its declared state")
    if next(r["handle"] for r in queue_rows(after["output"]) if r.get("root"))!=("0:" if restore else "1:"):
        raise RuntimeError("Source TX queue root handle not restored/installed")
    if restore:
        state["source_queue_restore_pending"] = False
        save(state_path,state)
    return {"profile":QUEUE_PROFILE,"restored":restore,"before":before,"actions":actions,"after":after,
            "scope":"queue configuration restored; kernel handles and historical counters are not restored"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_neighbor(state_path, run, *, restore=False,peer_mac=None):
    address=BSSID if peer_mac is None else peer_mac
    if address not in (MAC,BSSID):
        raise ValueError('Undeclared B1 native peer address')
    state = json.loads(state_path.read_text())
    if state.get("device")!=DEVICE or state.get("source_queue_profile")!=QUEUE_PROFILE:
        raise ValueError("Fixed peer requires the controlled B1 host path")
    query=["ip","neigh","show","to","192.168.4.1","dev",DEVICE]
    before=run(query)
    if restore:
        if state.get("source_neighbor_profile")!=NEIGHBOR_PROFILE or not state.get("source_neighbor_restore_pending"):
            raise ValueError("No owned permanent peer entry to restore")
        action=run(["ip","neigh","del","192.168.4.1","dev",DEVICE],True,False)
        if action["returncode"] and "No such file" not in action["output"]:
            raise RuntimeError("Fixed peer removal failed: "+action["output"])
    else:
        if "PERMANENT" in before["output"] or state.get("source_neighbor_restore_pending"):
            raise ValueError("Refusing to replace a pre-existing permanent peer")
        link=run(["iw","dev",DEVICE,"link"])
        if "Connected to "+BSSID+" (on "+DEVICE+")" not in link["output"]:
            raise ValueError("Fixed peer MAC does not match the actual B1 AP")
        if peer_mac is not None and ('lladdr '+address) not in before['output']:
            raise ValueError('Native IPv4 neighbor differs from the declared interface MAC')
        state.update(source_neighbor_profile=NEIGHBOR_PROFILE,source_neighbor_restore_pending=True)
        save(state_path,state)
        action=run(["ip","neigh","replace","192.168.4.1","lladdr",address,"nud","permanent","dev",DEVICE],True)
    after=run(query)
    if restore:
        if "PERMANENT" in after["output"]:
            raise RuntimeError("Permanent peer survived restoration")
        state["source_neighbor_restore_pending"]=False
        save(state_path,state)
    elif after["output"].split()!=["192.168.4.1","lladdr",address,"PERMANENT"]:
        raise RuntimeError("Permanent peer did not reach its declared state")
    return {"profile":NEIGHBOR_PROFILE,"restored":restore,"before":before,"action":action,"after":after,
        "scope":"Host ARP mapping only; native receiver, payload, send rate and original counters unchanged"}


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def link_local(mac):
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        raise ValueError("Invalid AP MAC")
    octets = bytearray.fromhex(mac.replace(":", ""))
    octets[0] ^= 2
    eui = bytes(octets[:3]) + b"\xff\xfe" + bytes(octets[3:])
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fe80::")) | int.from_bytes(eui, "big")))


def active_uuid(run):
    rows = run(["nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active"])["output"].splitlines()
    return [line.rsplit(":", 1)[0] for line in rows if line.rsplit(":", 1)[-1] == DEVICE]


def recover(state_path):
    """Run by systemd as root, independently of SSH and the acquisition process."""
    state = json.loads(state_path.read_text())
    save(state_path.with_name("wifi-timeout.json"), {"utc": datetime.now(timezone.utc).isoformat()})
    actions = []
    for arguments in (["nmcli", "radio", "wifi", "on"],
                      ["nmcli", "device", "set", DEVICE, "autoconnect", state["autoconnect"]],
                      ["nmcli", "--wait", "40", "connection", "up", "uuid", state["restore_uuid"], "ifname", DEVICE],
                      ["iw", "dev", DEVICE, "set", "power_save", state["power_save"]]):
        try:
            result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=55)
            actions.append({"arguments": arguments, "returncode": result.returncode, "output": result.stdout})
        except subprocess.TimeoutExpired:
            actions.append({"arguments": arguments, "returncode": 124, "output": "Recovery command timed out"})
    save(state_path.with_name("wifi-recovery.json"), {"actions": actions})
    if state.get("source_queue_restore_pending") or state.get("source_neighbor_restore_pending"):
        def root_run(arguments, privileged=False, check=True):
            value = subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=55)
            if check and value.returncode:
                raise RuntimeError("Queue recovery failed: "+value.stdout)
            return {"arguments":arguments,"returncode":value.returncode,"output":value.stdout}
        if state.get("source_neighbor_restore_pending"):
            save(state_path.with_name("source-neighbor-timeout-recovery.json"),source_neighbor(state_path,root_run,restore=True))
        if state.get("source_queue_restore_pending"):
            save(state_path.with_name("source-queue-timeout-recovery.json"),source_queue(state_path,root_run,restore=True))
    if any(row["returncode"] for row in actions):
        raise RuntimeError("Timed Wi-Fi recovery failed; see wifi-recovery.json")


@contextmanager
def peer_link(output, run, system, restore_uuid, *, source_queue_profile=None):
    if not re.fullmatch(r"[0-9a-f-]{36}", restore_uuid) or active_uuid(run) != [restore_uuid]:
        raise ValueError("Explicit original Wi-Fi UUID must match the active management connection")
    connection = "iotosbench-native-b1-" + system.lower()
    names = run(["nmcli", "-t", "-f", "NAME", "connection", "show"])["output"].splitlines()
    if connection in names:
        raise ValueError("Temporary connection already exists; refusing to replace it")
    auto = run(["nmcli", "-g", "GENERAL.AUTOCONNECT", "device", "show", DEVICE])["output"].strip()
    if auto not in ("yes", "no"):
        raise ValueError("Original device autoconnect setting is unknown")
    power_save = run(["iw", "dev", DEVICE, "get", "power_save"])["output"].strip().rsplit(" ", 1)[-1]
    if power_save not in ("on", "off"):
        raise ValueError("Original Wi-Fi power-save setting is unknown")
    unit = "iotosbench-recover-" + output.name
    state = output / "wifi-restore-state.json"
    original = {"restore_uuid": restore_uuid, "autoconnect": auto, "device": DEVICE,
                "power_save": power_save, "unit": unit}
    if source_queue_profile is not None:
        if source_queue_profile!=QUEUE_PROFILE or system!="Common":
            raise ValueError("Unsupported controlled source queue profile")
        snapshot = run(["tc","-j","-d","qdisc","show","dev",DEVICE])
        if set(queue_config(snapshot["output"]).values())!={"fq_codel"} or \
                next(r["handle"] for r in queue_rows(snapshot["output"]) if r.get("root"))!="0:":
            raise ValueError("Expected the original native host queue before collection")
        original.update(source_queue_profile=QUEUE_PROFILE,source_queue_original=snapshot,
                        source_queue_restore_pending=False)
    save(state, original)
    actions, created = [], False
    command = ["systemd-run", "--unit=" + unit, "--on-active=" + ("45m" if system=="Common" else "30m" if system == "Rhino" else "16m"),
               sys.executable, str(Path(__file__).resolve()), "recover", "--output", str(output)]
    actions.append(run(command, True))
    if run(["systemctl", "is-active", unit + ".timer"])["output"].strip() != "active":
        raise ValueError("Independent Wi-Fi recovery timer is not active")
    save(output / "wifi-guard-armed.json", {"unit": unit, "command": command, "active_before_switch": True})
    try:
        actions.append(run(["nmcli", "device", "set", DEVICE, "autoconnect", "no"], True))
        addresses = (["ipv4.method", "disabled", "ipv6.method", "manual", "ipv6.addresses", "fd00:dead:beef::1/64",
                      "ipv6.never-default", "yes"] if system == "RIOT" else
                     ["ipv4.method", "manual", "ipv4.addresses", "192.168.4.2/24", "ipv4.never-default", "yes", "ipv6.method", "ignore"])
        actions.append(run(["nmcli", "connection", "add", "type", "wifi", "ifname", DEVICE,
            "con-name", connection, "ssid", "ESP32-bench-55dc", "connection.autoconnect", "no",
            "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", "benchmark-only-55dc",
            "802-11-wireless.bssid", BSSID, "802-11-wireless.powersave", "2",
            "802-11-wireless.band", "bg", "802-11-wireless.channel", "1", *addresses], True))
        created = True
        actions.append(run(["iw", "dev", DEVICE, "set", "power_save", "off"], True))
        yield connection
    finally:
        neighbor_restored = True
        if json.loads(state.read_text()).get("source_neighbor_restore_pending"):
            try:
                save(output/"source-neighbor-restoration.json",source_neighbor(state,run,restore=True))
            except Exception as error:
                neighbor_restored = False
                save(output/"source-neighbor-restoration.json",{"error":repr(error),"restored":False})
        if created:
            actions.append(run(["nmcli", "connection", "delete", connection], True, False))
        actions.append(run(["nmcli", "radio", "wifi", "on"], True, False))
        actions.append(run(["nmcli", "device", "set", DEVICE, "autoconnect", auto], True, False))
        actions.append(run(["nmcli", "--wait", "40", "connection", "up", "uuid", restore_uuid, "ifname", DEVICE], True, False))
        restored = active_uuid(run) == [restore_uuid]
        actions.append(run(["iw", "dev", DEVICE, "set", "power_save", power_save], True, False))
        queue_restored = True
        if source_queue_profile is not None:
            try:
                save(output/"source-queue-restoration.json",source_queue(state,run,restore=True))
            except Exception as error:
                queue_restored = False
                save(output/"source-queue-restoration.json",{"error":repr(error),"restored":False})
        if restored and queue_restored and neighbor_restored:
            actions.append(run(["systemctl", "stop", unit + ".timer"], True, False))
        save(output / "host-after.json", {"management_wifi_restored": restored, "actions": actions,
            **({"source_queue_restored":queue_restored,"source_neighbor_restored":neighbor_restored} if source_queue_profile else {}),
            "addresses": run(["ip", "-j", "address"]), "routes": run(["ip", "-j", "route"])})
        if not restored or not queue_restored or not neighbor_restored:
            raise RuntimeError("Management Wi-Fi or source queue not restored; independent recovery timer remains armed")


def riot_resume(parent):
    from audit_esp32_followup import envelope
    from audit_esp32_riot_udp_original import capture
    value = envelope(parent)
    if value["system"] != "RIOT" or value["board_mac"] != MAC or value.get("parent"):
        raise ValueError("Unexpected RIOT parent")
    host = json.loads((parent/"host-after.json").read_text())
    if not host["management_wifi_restored"] or any(r["returncode"] for r in host["actions"]):
        raise ValueError("Parent management network restoration is incomplete")
    failed = []
    for i in (1,2,3):
        for case in CASES["RIOT"]:
            try:
                capture(parent/("run%d" % i)/case, case, board_bssid=BSSID)
            except ValueError as error:
                if str(error) != "original echo/header response differs":
                    raise
                failed.append([i,case])
    if failed != [[2,"payload1024-interval1000"]]:
        raise ValueError("Resume selection differs from retained packet-evidence failure")
    return {"directory":parent.name, "campaign_sha256":sha(parent/"campaign.json"),
            "selected":failed, "reason":"one original echo header sequence does not close; all five other windows retained"}


def collect(root, output, system, restore_uuid, port, resume_parent=None):
    from run_esp32_followup import Board
    import run_esp32_iperf_original as native
    os.environ["LC_ALL"] = "C"
    if not os.environ.get("BENCHMARK_SSH_PASSWORD") or not Path(port).is_char_device():
        raise ValueError("Missing in-memory sudo credential or UART")
    if shutil.disk_usage(root).free < 100 * 1024 ** 2:
        raise ValueError("Insufficient backup/capture space")
    source = root / "downloads" / REFERENCES[system]
    parent = riot_resume(resume_parent) if resume_parent is not None else None
    if parent is not None and system != "RIOT":
        raise ValueError("Only the frozen RIOT packet-evidence interruption can resume")
    with (root / "tm-sync-power.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True, exist_ok=False)
        build = output / "build"
        build.mkdir()
        for name in IMAGES:
            shutil.copyfile(source / name, build / name)
        proof = json.loads((source / "readiness.json").read_text())
        proof.pop("remaining", None)
        if proof["audit"] != "pass" or sha(build / "application.bin") != proof["image_sha256"]:
            raise ValueError("Native candidate differs from the source-qualified image")
        peer = (source / "iperf-host" if system == "Rhino" else source / "host-source/bin/benchmark_server")
        save(output / "source-proof.json", {"reference": REFERENCES[system], "readiness": proof,
            "images": {name: sha(build / name) for name in IMAGES}, "peer_sha256": sha(peer)})
        shutil.copyfile(peer, output / "peer-executable")
        shutil.copyfile(__file__, output / "runner.py")
        shutil.copyfile(Path(Board.backup.__code__.co_filename), output / "board-driver.py")
        shutil.copyfile(native.__file__, output / "run_esp32_iperf_original.py")
        save(output / "host-before.json", {"addresses": native.run(["ip", "-j", "address"]),
            "routes": native.run(["ip", "-j", "route"]), "active_uuid": active_uuid(native.run)})
        native.SERIAL_PORT = port
        native.SSID, native.PASSWORD = "ESP32-bench-55dc", "benchmark-only-55dc"
        report = {"mode": "native-network-b1", "system": system, "board_mac": MAC,
            "started_utc": datetime.now(timezone.utc).isoformat(), "status": "incomplete",
            "seconds_per_case": 60, "resets_per_case": 3, "cases": list(CASES[system]),
            "original_flash_restored": False, "old_cohort_modified": False,
            "energy_measured": False, "external_independent_replication": False}
        if parent is not None:
            report["parent"] = parent
        board = Board(root, output, MAC, port)
        firewall_added = False
        try:
            board.backup()
            try:
                with peer_link(output, native.run, system, restore_uuid) as connection:
                    native.CONNECTION = connection
                    if system == "RIOT":
                        import run_esp32_riot_udp_original as riot
                        riot.CONNECTION, riot.DEVICE = connection, DEVICE
                        shutil.copyfile(riot.__file__, output / "run_esp32_riot_udp_original.py")
                        firewall = native.run(["ip6tables", "-C", "INPUT", *riot.FIREWALL_RULE], True, False)
                        if firewall["returncode"] == 1:
                            native.run(["ip6tables", "-I", "INPUT", "1", *riot.FIREWALL_RULE], True)
                            firewall_added = True
                        elif firewall["returncode"]:
                            raise RuntimeError("Cannot inspect the scoped IPv6 input rule")
                    for index in (1, 2, 3):
                        selected = [case for case in CASES[system] if parent is None or [index,case] in parent["selected"]]
                        if not selected:
                            continue
                        folder = output / ("run%d" % index)
                        folder.mkdir()
                        pairs = board.flash(folder, build)
                        for case in selected:
                            if (output / "wifi-timeout.json").exists():
                                raise TimeoutError("Independent Wi-Fi recovery deadline elapsed")
                            if system == "Rhino":
                                native.trial(folder / case, case, 60, "alios", str(peer), controlled_peer=True)
                            else:
                                riot.trial(folder / case, case, 60, board_bssid=BSSID, port_name=port)
                            print(system, index, case, "captured; audit pending", flush=True)
                        board.verify(pairs, folder / "verify-after.log")
                report["status"] = "collection_complete_audit_pending"
            finally:
                try:
                    if firewall_added:
                        save(output / "firewall-cleanup.json", native.run(
                            ["ip6tables", "-D", "INPUT", *riot.FIREWALL_RULE], True, False))
                finally:
                    board.restore()
                    report["original_flash_restored"] = True
                if sha(peer) != sha(output / "peer-executable"):
                    raise ValueError("Original host peer changed during acquisition")
        except BaseException as error:
            report["error"] = repr(error)
            raise
        finally:
            report["completed_utc"] = datetime.now(timezone.utc).isoformat()
            report["files"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}
            save(output / "campaign.json", report)


def audit(output, reports=None):
    from audit_esp32_followup import envelope, verified
    from audit_esp32_alios_iperf_readiness import audit as rhino_ready
    from audit_esp32_riot_udp_readiness import audit as riot_ready
    from audit_esp32_alios_iperf_original import capture as rhino_capture
    from audit_esp32_riot_udp_original import capture as riot_capture
    import statistics
    campaign = envelope(output)
    system = campaign["system"]
    if (campaign["mode"] != "native-network-b1" or campaign["board_mac"] != MAC or
            campaign["seconds_per_case"] != 60 or campaign["resets_per_case"] != 3 or
            campaign["cases"] != list(CASES[system]) or (output / "wifi-timeout.json").exists()):
        raise ValueError("Wrong native campaign identity, protocol or completed-window boundary")
    parent = None
    if campaign.get("parent"):
        parent = output.parent / campaign["parent"]["directory"]
        if campaign["parent"] != riot_resume(parent):
            raise ValueError("Retained parent or fixed replacement selection changed")
    reports = reports or Path(__file__).resolve().parents[1] / "artifacts/reports"
    reference = reports / REFERENCES[system]
    admission = rhino_ready(reference) if system == "Rhino" else riot_ready(reference, reports / "riot-network-dependencies-v1")
    admission.pop("remaining", None)
    peer = reference / ("iperf-host" if system == "Rhino" else "host-source/bin/benchmark_server")
    expected = {"reference": REFERENCES[system], "readiness": admission,
        "images": {name: sha(reference / name) for name in IMAGES}, "peer_sha256": sha(peer)}
    if (json.loads((output / "source-proof.json").read_text()) != expected or
            sha(output / "peer-executable") != expected["peer_sha256"] or any(
            sha(output / "build" / name) != value for name, value in expected["images"].items())):
        raise ValueError("Native original source/image/peer binding changed")
    host = json.loads((output / "host-after.json").read_text())
    if not host["management_wifi_restored"] or not json.loads((output / "wifi-guard-armed.json").read_text())["active_before_switch"]:
        raise ValueError("Wi-Fi recovery not armed before acquisition or not completed")
    state = json.loads((output / "wifi-restore-state.json").read_text())
    if any(row["returncode"] for row in host["actions"]) or not any(
            row["arguments"] == ["systemctl", "stop", state["unit"] + ".timer"] for row in host["actions"]):
        raise ValueError("Temporary Wi-Fi cleanup or recovery-timer cancellation failed")
    cases, times = {}, []
    for case in CASES[system]:
        runs = []
        for index in (1, 2, 3):
            origin = parent if parent is not None and [index,case] not in campaign["parent"]["selected"] else output
            verified(origin / ("run%d" % index), output / "build", MAC)
            folder = origin / ("run%d" % index) / case
            result = (rhino_capture(folder, case, board_bssid=BSSID) if system == "Rhino" else
                      riot_capture(folder, case, board_bssid=BSSID))
            runs.append(result)
            times.append(tuple(datetime.fromisoformat(result[k]) for k in
                               (("start_utc", "end_utc") if system == "Rhino" else ("first_utc", "last_utc"))))
        cases[case] = {"runs": runs, "independent_resets": 3}
        if system == "Rhino":
            values = [row["receiver_decimal_mbit_s"] for row in runs]
            cases[case].update(values=values, median_receiver_decimal_mbit_s=statistics.median(values))
    times.sort()
    if any(a[1] >= b[0] for a, b in zip(times, times[1:])):
        raise ValueError("Independent physical windows overlap")
    return {"audit": "pass", "system": system, "board_mac": MAC, "cases": cases,
        "independent_resets": 3 * len(CASES[system]), "original_flash_restored": True,
        "management_wifi_restored": True, "ranking_eligible": False, "new_metrics": False,
        **({"retained_failed_resets":1,"new_physical_resets":1,"parent":campaign["parent"]} if parent is not None else {})}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "audit", "recover"))
    parser.add_argument("--root", type=Path, default=Path.home() / "esp32-pilot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--system", choices=tuple(REFERENCES))
    parser.add_argument("--restore-uuid")
    parser.add_argument("--resume-parent", type=Path)
    parser.add_argument("--reports", type=Path, help="Pinned original build/dependency archive directory for audit")
    parser.add_argument("--port", default="/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0")
    args = parser.parse_args()
    if args.mode == "recover":
        recover(args.output / "wifi-restore-state.json")
    elif args.mode == "audit":
        result = audit(args.output, args.reports)
        save(args.output / "audit.json", result)
        print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))
    elif not args.system or not args.restore_uuid:
        parser.error("A native system and the explicit original Wi-Fi UUID are required")
    else:
        collect(args.root, args.output, args.system, args.restore_uuid, args.port, args.resume_parent)
