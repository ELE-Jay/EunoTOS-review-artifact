#!/usr/bin/env python3
"""Run native iPerf programs; retain both endpoints and restore Wi-Fi."""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import shutil
import socket
import errno
import subprocess
import threading
import time
from datetime import datetime, timezone

ROOT = Path.home() / "esp32-pilot"
DEVICE = "wlxa41a3ad16459"
CONNECTION = "esp32-benchmark-temporary"
SSID = "ESP32-bench-55dc"
PASSWORD = "benchmark-only-55dc"
SERIAL_PORT = os.environ.get("ESP32_SERIAL_PORT", "/dev/ttyUSB0")


def utc():
    return datetime.now(timezone.utc).isoformat()


def run(arguments, privileged=False, check=True):
    command = ["sudo", "-S", "-p", "", *arguments] if privileged else arguments
    result = subprocess.run(command, input=(os.environ["BENCHMARK_SSH_PASSWORD"] + "\n")
                            if privileged else None, universal_newlines=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    if check and result.returncode:
        raise RuntimeError((arguments, result.stdout))
    return {"arguments": arguments, "returncode": result.returncode, "output": result.stdout, "utc": utc()}


def network_commands(case, seconds, profile, endpoint, payload=None):
    udp, tx = case.startswith("udp"), case.endswith("tx")
    arguments = [endpoint, "-B", "192.168.4.2", "-i", "3", "-f", "m"]
    arguments += ["-s"] if tx else ["-c", "192.168.4.1", "-t", str(seconds + 3 if profile == "nuttx" else seconds)]
    if udp:
        arguments += ["-u"]
        if profile == "nuttx":
            arguments += ["-l", "1472"]
        if not tx:
            arguments += ["-b", "10000000"]
            if profile in ("idf", "alios"):
                arguments += ["-l", "1470"]
    board = f"iperf {'-c 192.168.4.2' if tx else '-s'} -i 3 -t {seconds}"
    if udp:
        board += " -u"
        if tx and profile == "idf":
            board += " -b 10 -l 1470"
    if profile == "alios":
        board = f"iperf {'-c 192.168.4.2' if tx else '-s'} -i"
        if tx:
            board += f" -t {seconds}"
        if udp:
            board += " -u"
            if tx:
                board += " -b 10m -l 1470"
    if payload is not None:
        if profile not in ("idf", "nuttx") or payload != (1472 if udp else 16384):
            raise ValueError("Controlled native payload must match the fixed NuttX original")
        if "-l" in arguments:
            arguments[arguments.index("-l") + 1] = str(payload)
        else:
            arguments += ["-l", str(payload)]
        if profile == "idf" and tx:
            board = re.sub(r" -l \d+", "", board) + " -l " + str(payload)
    return arguments, board


def fixed_udp_arguments(endpoint, amount, send_buffer_bytes=None):
    if type(amount) is not int or not 1024 <= amount < 0x80000000:
        raise ValueError("Original iPerf fixed-byte UDP amount must be positive and fit the original header")
    arguments=[str(endpoint), "-B", "192.168.4.2", "-i", "3", "-f", "m", "-c", "192.168.4.1",
               "-u", "-b", "10000000", "-l", "1024", "-n", str(amount)]
    if send_buffer_bytes is not None:
        if type(send_buffer_bytes) is not int or send_buffer_bytes!=212992:
            raise ValueError("Use the frozen unprivileged original sender-buffer request")
        arguments += ["-w",str(send_buffer_bytes)]
    return arguments


def udp_source_path_snapshot(actions,phase):
    for arguments in (["tc","-s","qdisc","show","dev",DEVICE],
                      ["ip","-s","-j","link","show","dev",DEVICE],
                      ["ip","-s","neigh","show","dev",DEVICE],
                      ["cat","/proc/net/snmp"]):
        actions.append({"host_udp_path":phase,**run(arguments)})


def peer_port_ready(address="192.168.4.2", port=5001, timeout=75, *, udp=False):
    started = time.monotonic()
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as probe:
                probe.bind((address, port))
            return {"peer_port_ready": True, "address": address, "port": port,
                    "wait_seconds": time.monotonic() - started, "utc": utc(),
                    **({"protocol": "udp"} if udp else {})}
        except OSError as error:
            if error.errno != errno.EADDRINUSE or time.monotonic() - started >= timeout:
                raise
            time.sleep(min(.5, max(0, timeout - (time.monotonic() - started))))


def peer_listener_ready(process, log, timeout=8, *, udp=False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None or re.search(r"bind failed|listen failed|Address already in use", log.read_text(), re.I):
            raise RuntimeError("Original peer listener failed before the board client started")
        state = run(["ss", "-lun" if udp else "-ltn", "sport", "=", ":5001"])
        if re.search(r"\b192\.168\.4\.2:5001\s", state["output"]):
            return {"peer_listener_ready": True, "utc": utc(), "state": state}
        time.sleep(.1)
    raise RuntimeError("Original peer listener was not ready")


def controlled_ap_ready(actions, timeout=40):
    started = time.monotonic()
    while True:
        actions.append(run(["nmcli", "device", "wifi", "rescan", "ifname", DEVICE, "ssid", SSID], True, False))
        time.sleep(5)
        result = run(["nmcli", "--terse", "--escape", "no", "--fields", "BSSID,SSID,CHAN,SECURITY",
                      "device", "wifi", "list", "ifname", DEVICE, "--rescan", "no"])
        actions.append(result)
        target = "34:98:7a:a2:85:29:" + SSID + ":1:"
        if any(line.lower().startswith(target.lower()) and "WPA2" in line for line in result["output"].splitlines()):
            actions.append({"controlled_ap_ready": True, "wait_seconds": time.monotonic() - started, "utc": utc()})
            return
        if time.monotonic() - started >= timeout:
            raise RuntimeError("Target B1 channel-1 WPA2 AP was not discovered before the workload")
        time.sleep(5)


def controlled_connection(actions):
    controlled_ap_ready(actions)
    for attempt in (1, 2):
        result = run(["nmcli", "--wait", "35", "connection", "up", CONNECTION,
                      "ifname", DEVICE, "ap", "34:98:7a:a2:85:29"], True, False)
        actions.append(result)
        if result["returncode"] == 0:
            actions.append({"controlled_connection_ready": True, "attempt": attempt, "utc": utc()})
            return result
        actions.append(run(["nmcli", "-f", "GENERAL.STATE,GENERAL.REASON", "device", "show", DEVICE], False, False))
        actions.append(run(["journalctl", "-u", "NetworkManager", "-n", "60", "--no-pager"], False, False))
        actions.append(run(["nmcli", "device", "disconnect", DEVICE], True, False))
        if attempt == 1:
            time.sleep(5)
    raise RuntimeError("Controlled WPA connection failed twice before any workload: " + result["output"])


def trial(directory, case, seconds, profile="idf", endpoint="iperf", payload=None, *, controlled_peer=False,
          board_command=None, completion_token=None, host_csv=False, host_compat=False, receiver_payload=None,
          fixed_udp_bytes=None, fixed_udp_send_buffer=None, host_udp_path_diagnostics=False,
          source_queue_state=None, fixed_peer_neighbor=False, diagnostic_warmup=False, source_warmup=False,
          fixed_peer_mac=None):
    import serial
    if fixed_udp_bytes is not None and (case!="udp_rx" or not controlled_peer or
            board_command!="zperf_udp_receiver" or completion_token!="ORIGINAL_ZPERF_RX CLOSED status=0" or payload is not None):
        raise ValueError("Fixed-byte sender requires the source-qualified common original UDP receiver")
    if fixed_udp_send_buffer is not None and fixed_udp_bytes is None:
        raise ValueError("Explicit send buffer is only defined for the fixed-byte original UDP sender")
    if host_udp_path_diagnostics and fixed_udp_bytes is None:
        raise ValueError("Source-path diagnosis requires the fixed-byte original UDP sender")
    if source_queue_state is not None and (fixed_udp_bytes is None or not host_udp_path_diagnostics):
        raise ValueError("Controlled source queue requires the fixed UDP load and endpoint observations")
    if fixed_peer_neighbor and source_queue_state is None:
        raise ValueError("Fixed peer mapping requires recoverable controlled source state")
    if (diagnostic_warmup or source_warmup) and not fixed_peer_neighbor:
        raise ValueError("Source warmup diagnosis requires the fixed original receiver")
    if receiver_payload is not None and (not controlled_peer or board_command is None or case!="udp_tx" or
            type(receiver_payload) is not int or not 36<=receiver_payload<=16384):
        raise ValueError("Explicit original-core UDP receiver payload requires the controlled TX adapter")
    directory.mkdir()
    actions = []
    started = time.monotonic()
    stop = threading.Event()
    host = None
    sink = None
    packet = None
    packet_sink = None
    packet_command = None
    neighbor = None
    neighbor_sink = None
    peer_pinned = False
    reader_errors = []
    lines = []
    with serial.Serial(SERIAL_PORT, 115200, timeout=0.2) as port, \
            (directory / "uart.jsonl").open("w") as output, (directory / "uart.raw").open("wb") as raw_output:
        def reader():
            try:
                while not stop.is_set():
                    raw = port.readline()
                    if raw:
                        raw_output.write(raw)
                        raw_output.flush()
                        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                        lines.append(line)
                        output.write(json.dumps({"elapsed_s": time.monotonic() - started,
                                                 "utc": utc(), "line": line, "raw_bytes": len(raw),
                                                 "raw_sha256": hashlib.sha256(raw).hexdigest()}) + "\n")
                        output.flush()
            except Exception as error:
                reader_errors.append(str(error))

        def send(command):
            actions.append({"board_command": command, "utc": utc(), "elapsed_s": time.monotonic() - started})
            message=(command + ("\r\n" if profile in ("alios", "rhino-common") else "\n")).encode()
            if profile == "zephyr":
                for byte in message:
                    port.write(bytes([byte]))
                    time.sleep(.005)
            else:
                port.write(message)
            port.flush()

        if fixed_peer_neighbor:
            port.dtr = False
            port.rts = True
            time.sleep(.25)
            port.reset_input_buffer()
            actions.append({"uart_reset_framing":"EN held, prior UART bytes flushed before recorder start", "utc":utc()})
        thread = threading.Thread(target=reader)
        thread.start()
        try:
            actions.append(run(["nmcli", "connection", "down", CONNECTION], True, False))
            actions.append({"hardware_reset": "EN via RTS; DTR low", "utc": utc()})
            if not fixed_peer_neighbor:
                port.dtr = False
                port.rts = True
                time.sleep(0.25)
            port.rts = False
            time.sleep(4)
            if profile == "nuttx":
                if not any("NuttShell (NSH)" in line for line in lines):
                    raise RuntimeError("native NuttX boot missing")
                send("uname -a")
                time.sleep(0.5)
                send("ifconfig")
                time.sleep(0.5)
                send(f"wapi psk wlan0 {PASSWORD} 3")
                time.sleep(0.5)
                send(f"wapi essid wlan0 {SSID} 1")
                time.sleep(0.5)
                send("wapi show wlan0")
            elif profile in ("riot-common", "rhino-common"):
                system = "RIOT" if profile == "riot-common" else "AliOS-Rhino"
                expected = "COMMON_NETWORK " + system + " IPv4=192.168.4.1 receiver_core=original-zperf clock_resolution_us=10000"
                if lines.count(expected) != 1:
                    raise RuntimeError("native common receiver AP boot missing")
                conditions="COMMON_NETWORK_CONDITIONS cpu_hz=240000000 cores=1 tick_hz="+(
                    "0" if profile=="riot-common" else "100")
                if lines.count(conditions)!=1:
                    raise RuntimeError("Native common receiver actual clock/core profile differs")
                send("")
            elif profile == "alios":
                if lines.count("Native AliOS lwIP iPerf ready: AP 192.168.4.1 channel 1") != 1:
                    raise RuntimeError("native AliOS AP boot missing")
                send("iperf -d 4")
            elif profile == "zephyr":
                if not any("Booting Zephyr OS build 3.7.0" in line for line in lines):
                    raise RuntimeError("native Zephyr boot missing")
                send("")
                time.sleep(.5)
                send(f"wifi ap enable -s {SSID} -p {PASSWORD} -k 1 -c 1")
            else:
                send("")
                time.sleep(0.5)
                send(f"ap {SSID} {PASSWORD}")
            time.sleep(2)
            if profile == "nuttx":
                actions.append(run(["nmcli", "device", "wifi", "rescan", "ifname", DEVICE], True, False))
                time.sleep(3)
                actions.append(run(["nmcli", "-f", "IN-USE,SSID,MODE,CHAN,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", DEVICE]))
            if controlled_peer:
                connection = controlled_connection(actions)
            else:
                connection = run(["nmcli", "--wait", "35", "connection", "up", CONNECTION], True, False)
                actions.append(connection)
            if connection["returncode"]:
                raise RuntimeError(connection["output"])
            actions.append(run(["ip", "-j", "address", "show", "dev", DEVICE]))
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            actions.append(run(["ping", "-I", DEVICE, "-c", "3", "-W", "2", "192.168.4.1"]))
            if source_queue_state is not None:
                from run_esp32_native_network_b1 import source_queue
                actions.append({"host_udp_queue":source_queue(source_queue_state,run)})
            if fixed_peer_neighbor:
                from run_esp32_native_network_b1 import source_neighbor
                actions.append({"host_udp_neighbor":source_neighbor(source_queue_state,run,peer_mac=fixed_peer_mac)})
                peer_pinned = True
            if diagnostic_warmup or source_warmup:
                actions.append({"diagnostic_udp_source_warmup" if diagnostic_warmup else "host_udp_source_warmup":{
                    "before_link":run(["iw","dev",DEVICE,"link"]),
                    "traffic":run(["ping","-n","-I",DEVICE,"-i","0.01","-c","1000","-s","1024","-W","2","192.168.4.1"],True,False),
                    "after_link":run(["iw","dev",DEVICE,"link"]),
                    "scope":"Pre-session link diagnosis only, not original workload or mainboard evidence" if diagnostic_warmup else
                        "Frozen shared preconditioning; excluded from original UDP workload and statistic window"}})
                if source_warmup and actions[-1]['host_udp_source_warmup']['traffic']['returncode']:
                    raise RuntimeError('Required source preconditioning failed; original workload not started')
                time.sleep(1)
            if profile == "alios" or receiver_payload is not None or fixed_udp_bytes is not None:
                packet_sink = (directory / "pcap.log").open("w")
                packet_command = ["tcpdump", "-Z", "leon", "-U", "-n", "-i", DEVICE, "-s", "96",
                                  "-w", str(directory / "network.pcap"), "host", "192.168.4.1", "and", "port", "5001"]
                actions.append({"packet_command": packet_command, "utc": utc()})
                packet = subprocess.Popen(["sudo", "-S", "-p", "", *packet_command], stdin=subprocess.PIPE,
                                          stdout=packet_sink, stderr=subprocess.STDOUT, universal_newlines=True)
                packet.stdin.write(os.environ["BENCHMARK_SSH_PASSWORD"] + "\n")
                packet.stdin.close()
                time.sleep(1)
                if packet.poll() is not None or "listening on" not in (directory / "pcap.log").read_text():
                    raise RuntimeError("packet capture did not start")
            udp = case.startswith("udp")
            tx = case.endswith("tx")
            arguments, board = network_commands(case, seconds, profile, endpoint, payload)
            if fixed_udp_bytes is not None:
                arguments = fixed_udp_arguments(endpoint, fixed_udp_bytes, fixed_udp_send_buffer)
            if receiver_payload is not None:
                if "-l" in arguments: arguments[arguments.index("-l")+1]=str(receiver_payload)
                else: arguments += ["-l",str(receiver_payload)]
            if board_command is not None:
                board = board_command
            if host_csv:
                arguments += ["-y","C"]
            if host_compat:
                arguments += ["-C"]
            if controlled_peer:
                actions.append(peer_port_ready(udp=udp))
            sink = (directory / "host.log").open("w")
            if not tx:
                send(board)
                if fixed_udp_bytes is not None:
                    deadline=time.monotonic()+8
                    while not any("ORIGINAL_ZPERF_RX READY target=" in line for line in lines):
                        if time.monotonic()>=deadline:
                            raise RuntimeError("common original receiver did not bind before the host sender")
                        time.sleep(.1)
                else:
                    time.sleep(1)
            if host_udp_path_diagnostics:
                neighbor_sink = (directory / "neighbors.log").open("w")
                command = ["ip", "-ts", "monitor", "neigh", "dev", DEVICE]
                neighbor = subprocess.Popen(command, stdout=neighbor_sink, stderr=subprocess.STDOUT)
                actions.append({"host_neighbor_monitor": command, "pid": neighbor.pid, "utc": utc()})
                udp_source_path_snapshot(actions,"before_sender")
            actions.append({"host_command": arguments, "utc": utc(), "elapsed_s": time.monotonic() - started})
            host = subprocess.Popen(arguments, stdout=sink, stderr=subprocess.STDOUT)
            if fixed_udp_send_buffer is not None:
                for attempt in range(10):
                    state=run(["ss","-u","-a","-n","-m","-p","src","192.168.4.2","sport","=",":5001"])
                    actions.append({"original_sender_socket_state":state,"host_pid":host.pid,"utc":utc()})
                    if state["returncode"]==0 and re.search(r"\bpid="+str(host.pid)+r"\b",state["output"]) and \
                            re.search(r"\btb"+str(2*fixed_udp_send_buffer)+r"\b",state["output"]):
                        break
                    time.sleep(.05)
                else:
                    raise RuntimeError("Original host sender buffer was not observed at the frozen Linux size")
            if tx:
                if controlled_peer:
                    actions.append(peer_listener_ready(host, directory / "host.log", udp=udp))
                else:
                    time.sleep(0.5)
                send(board)
            measurement_started = time.monotonic()
            deadline = measurement_started + seconds + (25 if fixed_udp_bytes is not None else 15)
            while time.monotonic() < deadline:
                if any(re.search(r"fatal error|Guru Meditation|ESP_ERROR_CHECK failed|CPU.*exception", line, re.I) for line in lines):
                    raise RuntimeError("native fault observed; incomplete capture retained")
                completed = any(re.search(rf"\b0-\s*{seconds} sec\s+\d+\.\d+ Mbits/sec", line) for line in lines)
                if profile == "nuttx":
                    completed = any(float(match[1]) >= seconds for line in lines if
                                    (match := re.search(r"\b0\.00-\s*(\d+\.\d+) sec\s+\d+ Bytes\s+[\d.]+ Mbits/sec", line)))
                if profile == "alios":
                    title = ("UDP" if udp else "TCP") + (" Client" if tx else " Server")
                    completed = "[Total]" + title + " Bandwidth:" in "".join(lines)
                if completion_token is not None:
                    completed = any(completion_token in line for line in lines)
                if completed:
                    break
                if reader_errors:
                    raise RuntimeError(reader_errors)
                time.sleep(0.25)
            else:
                raise RuntimeError("original board aggregate did not complete")
            if not tx:
                try:
                    host.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    # The native UDP receivers do not return iPerf2 final statistics.
                    if not udp:
                        raise
                if fixed_udp_bytes is not None and host.poll()!=0:
                    raise RuntimeError("Original fixed-byte UDP sender did not complete successfully")
            elif controlled_peer and not udp and not host_csv:
                # Native TCP teardown may finish after the board's final report.
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not re.search(
                        r"\[\s*\d+\]\s+0\.0-\s*(?:59|6\d)\.\d+ sec", (directory / "host.log").read_text()):
                    time.sleep(.25)
            time.sleep(5 if host_csv else 1)
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            actions.append({"capture_complete": True, "utc": utc()})
        finally:
            if host is not None:
                if host.poll() is None:
                    host.send_signal(signal.SIGINT)
                    try:
                        host.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        host.kill()
                        host.wait()
                actions.append({"host_returncode": host.returncode, "utc": utc()})
                if host_udp_path_diagnostics:
                    udp_source_path_snapshot(actions,"after_sender")
            if neighbor is not None:
                if neighbor.poll() is None:
                    neighbor.send_signal(signal.SIGINT)
                neighbor.wait(timeout=5)
                actions.append({"host_neighbor_returncode": neighbor.returncode, "utc": utc()})
            if neighbor_sink:
                neighbor_sink.close()
            if peer_pinned:
                actions.append({"host_udp_neighbor":source_neighbor(source_queue_state,run,restore=True)})
            if sink:
                sink.close()
            if packet is not None:
                if packet.poll() is None:
                    candidates = run(["ps", "-C", "tcpdump", "-o", "pid=,args="], check=False)["output"].splitlines()
                    children = [int(line.split(maxsplit=1)[0]) for line in candidates
                                if line.split(maxsplit=1)[1].split() == packet_command]
                    if len(children) != 1:
                        raise RuntimeError("cannot identify the owned packet capture process")
                    actions.append(run(["kill", "-INT", str(children[0])], True))
                    packet.wait(timeout=5)
                actions.append({"packet_returncode": packet.returncode, "utc": utc()})
            if packet_sink:
                packet_sink.close()
            stop.set()
            thread.join(timeout=2)
            (directory / "actions.json").write_text(json.dumps(actions, indent=2) + "\n")
    if reader_errors:
        raise RuntimeError(reader_errors)
    print(f"{case} {directory.name}: original aggregate captured; audit pending", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", nargs="+", default=["tcp_tx", "tcp_rx", "udp_tx", "udp_rx"],
                        choices=["tcp_tx", "tcp_rx", "udp_tx", "udp_rx"])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--capture-subdirectory", default="")
    parser.add_argument("--profile", choices=["idf", "nuttx", "alios"], default="idf")
    parser.add_argument("--flash", action="store_true")
    parser.add_argument("--native-image", default="nuttx-iperf-original-v5")
    args = parser.parse_args()
    if args.seconds % (10 if args.profile == "alios" else 3) or args.seconds <= 3 or args.repeats < 1:
        raise ValueError("positive integral original reporting intervals required")
    if not re.fullmatch(r"(nuttx|alios)-iperf-original-v\d+", args.native_image):
        raise ValueError("native image name must identify an immutable version")
    if args.profile != "idf" and not args.native_image.startswith(args.profile + "-"):
        raise ValueError("native image must match the selected OS")
    if args.profile == "alios" and args.flash:
        raise ValueError("use the native AliOS installation probe to preserve its three-segment witness")
    image_directory = ROOT / ("downloads/" + args.native_image if args.profile != "idf" else "downloads/iperf-original-v1")
    directory = image_directory
    if args.capture_subdirectory:
        if Path(args.capture_subdirectory).name != args.capture_subdirectory:
            raise ValueError("capture subdirectory must be one relative name")
        directory = directory / args.capture_subdirectory
        directory.mkdir(exist_ok=True)
    with (ROOT / "tm-sync-power.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = run(["nmcli", "-t", "-f", "WIFI", "radio"])
        if initial["output"].strip() not in ("disabled", "已禁用"):
            raise RuntimeError("refuse to replace an existing enabled Wi-Fi session")
        if CONNECTION in run(["nmcli", "-t", "-f", "NAME", "connection"])["output"].splitlines():
            raise RuntimeError("temporary connection already exists")
        endpoint = "iperf"
        if args.profile in ("nuttx", "alios"):
            endpoint = str(image_directory / "iperf-host")
            if not Path(endpoint).exists():
                shutil.copy2(ROOT / "downloads/zperf-original-v3/iperf-host", endpoint)
                shutil.copytree(ROOT / "downloads/zperf-dependencies-v1", image_directory / "host-dependencies")
            if args.flash:
                if (image_directory / "flash.log").exists():
                    raise ValueError("do not overwrite installation evidence")
                check = run(["bash", "-c", 'cd "$1" && sha256sum -c image.sha256', "manifest", str(image_directory)])
                (image_directory / "image-check.log").write_text(check["output"])
                os.environ["PYTHONPATH"] = str(ROOT / "python-nuttx/lib/python3.8/site-packages") + ":" + str(ROOT / "esptool-4.8.1")
                flash = run([str(ROOT / "zephyr-v3.7.0-work/pyenv/bin/python"), "-m", "esptool", "--chip", "esp32",
                             "--port", "/dev/ttyUSB0", "--baud", "460800", "write_flash", "--flash_mode", "dio",
                             "--flash_freq", "40m", "--flash_size", "4MB", "0x1000", str(image_directory / "bootloader-esp32.bin"),
                             "0x8000", str(image_directory / "partition-table-esp32.bin"), "0x10000", str(image_directory / "nuttx.bin")], check=False)
                (image_directory / "flash.log").write_text(flash["output"])
                if flash["returncode"]:
                    raise RuntimeError("native installation failed; witness retained")
            elif not (image_directory / "flash.log").exists():
                raise ValueError("native cohort needs --flash and a preserved installation witness")
        shutil.copy2(__file__, directory / "runner.py")
        (directory / "host-before.json").write_text(json.dumps({"radio": initial,
            "addresses": run(["ip", "-j", "address"]), "routes": run(["ip", "-j", "route"]),
            "iperf": run([endpoint, "--version"], check=False),
            "processes": run(["ps", "-eo", "pid,ppid,pcpu,stat,comm"])}, indent=2) + "\n")
        try:
            run(["nmcli", "radio", "wifi", "on"], True)
            run(["nmcli", "connection", "add", "type", "wifi", "ifname", DEVICE,
                 "con-name", CONNECTION, "ssid", SSID, "connection.autoconnect", "no",
                 "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", PASSWORD,
                 "ipv4.method", "manual", "ipv4.addresses", "192.168.4.2/24",
                 "ipv4.never-default", "yes", "ipv6.method", "ignore"], True)
            for reset in range(1, args.repeats + 1):
                for case in args.cases:
                    trial(directory / f"{case}-reset{reset}", case, args.seconds, args.profile, endpoint)
        finally:
            cleanup = [run(["nmcli", "connection", "delete", CONNECTION], True, False),
                       run(["nmcli", "radio", "wifi", "off"], True, False)]
            (directory / "host-after.json").write_text(json.dumps({"cleanup": cleanup,
                "radio": run(["nmcli", "radio"]), "addresses": run(["ip", "-j", "address"]),
                "routes": run(["ip", "-j", "route"])}, indent=2) + "\n")


if __name__ == "__main__":
    main()
