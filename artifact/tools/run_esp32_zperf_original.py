#!/usr/bin/env python3
"""Capture the unchanged Zephyr zperf sample and its documented iPerf 2.0.5 peer."""
import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

import serial
from run_esp32_iperf_original import ROOT, DEVICE, CONNECTION, SSID, PASSWORD, run, utc, peer_port_ready, peer_listener_ready, SERIAL_PORT, controlled_connection

VERSION = os.environ.get("ESP32_ZPERF_VERSION", "v3")
if not VERSION.startswith("v") or not VERSION[1:].isdigit():
    raise ValueError("invalid evidence version")
OUTPUT = ROOT / ("downloads/zperf-original-" + VERSION)


def trial(directory, case, seconds, probe=False, *, controlled_peer=False, payload=1024, host_csv=False, host_compat=False):
    if type(payload) is not int or not 1 <= payload <= 16384 or type(host_csv) is not bool:
        raise ValueError("Invalid original tool payload/output options")
    directory.mkdir()
    actions, lines, errors = [], [], []
    stop = threading.Event()
    started = time.monotonic()
    host = sink = packet_capture = packet_log = None
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
                        output.write(json.dumps({"utc": utc(), "elapsed_s": time.monotonic() - started,
                                                 "line": line, "raw_bytes": len(raw),
                                                 "raw_sha256": hashlib.sha256(raw).hexdigest()}) + "\n")
                        output.flush()
            except Exception as error:
                errors.append(str(error))

        def send(command):
            actions.append({"board_command": command, "utc": utc(), "elapsed_s": time.monotonic() - started})
            # Pace shell input so the board's IRQ-driven UART RX does not overrun.
            for byte in (command + "\n").encode():
                port.write(bytes([byte]))
                time.sleep(0.005)
            port.flush()

        def wait_for(token, timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if any(token in line for line in lines):
                    return
                if errors:
                    raise RuntimeError(errors)
                time.sleep(0.2)
            raise RuntimeError("board did not report " + token)

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            actions.append(run(["nmcli", "connection", "down", CONNECTION], True, False))
            actions.append({"hardware_reset": "EN via RTS; DTR low", "utc": utc()})
            port.dtr = False
            port.rts = True
            time.sleep(0.25)
            port.rts = False
            wait_for("Booting Zephyr OS build 3.7.0", 40)
            time.sleep(3)
            send("")
            time.sleep(0.5)
            send(f"wifi ap enable -s {SSID} -p {PASSWORD} -k 1 -c 1")
            wait_for("AP mode enable requested", 15)
            if controlled_peer:
                controlled_connection(actions)
            else:
                actions.append(run(["nmcli", "--wait", "35", "connection", "up", CONNECTION], True))
            actions.append(run(["ip", "-j", "address", "show", "dev", DEVICE]))
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            send("net iface")
            time.sleep(0.5)
            send("zperf version")
            time.sleep(0.5)
            actions.append(run(["ping", "-I", DEVICE, "-c", "3", "-W", "2", "192.168.4.1"]))
            if probe:
                actions.append({"probe_only": True, "utc": utc()})
                return
            protocol, direction = case.split("_")
            tx = direction == "tx"
            if controlled_peer:
                actions.append(peer_port_ready(udp=protocol == "udp"))
            if protocol == "udp":
                packet_log = (directory / "pcap.log").open("w")
                packet_command = ["tcpdump", "-Z", "leon", "-U", "-n", "-i", DEVICE,
                                  "-s", "96", "-w", str(directory / "udp.pcap"), "udp", "port", "5001"]
                actions.append({"packet_capture_command": packet_command, "utc": utc()})
                packet_capture = subprocess.Popen(["sudo", "-S", "-p", "", *packet_command],
                    stdin=subprocess.PIPE, stdout=packet_log, stderr=subprocess.STDOUT)
                packet_capture.stdin.write((os.environ["BENCHMARK_SSH_PASSWORD"] + "\n").encode())
                packet_capture.stdin.close()
                time.sleep(1)
                if packet_capture.poll() is not None or "listening on" not in (directory / "pcap.log").read_text():
                    raise RuntimeError("independent packet capture failed to start")
            arguments = [str(OUTPUT / "iperf-host"), "-B", "192.168.4.2", "-i", "3", "-f", "m"]
            arguments += ["-s"] if tx else ["-c", "192.168.4.1", "-t", str(seconds)]
            if protocol == "udp":
                arguments += ["-u", "-l", str(payload)]
                if not tx:
                    arguments += ["-b", "10000000"]
            if protocol == "tcp" and payload != 1024:
                arguments += ["-l",str(payload)]
            if host_csv:
                arguments += ["-y","C"]
            if host_compat:
                arguments += ["-C"]
            if tx:
                board = f"zperf {protocol} upload 192.168.4.2 5001 {seconds} {payload}"
                if protocol == "udp":
                    board += " 10000000"
            else:
                board = f"zperf {protocol} download 5001"
                send(board)
                wait_for(f"{protocol.upper()} server started on port 5001", 5)
            sink = (directory / "host.log").open("w")
            actions.append({"host_command": arguments, "utc": utc(), "elapsed_s": time.monotonic() - started})
            host = subprocess.Popen(arguments, stdout=sink, stderr=subprocess.STDOUT)
            if tx:
                if controlled_peer:
                    actions.append(peer_listener_ready(host, directory / "host.log", udp=protocol == "udp"))
                else:
                    time.sleep(0.5)
                send(board)
            token = "Upload completed!" if tx else ("End of session!" if protocol == "udp" else "TCP session ended")
            wait_for(token, seconds + 20)
            time.sleep(5 if host_csv else 2)
            if not tx:
                host.wait(timeout=10)
                if host.returncode:
                    raise RuntimeError("original host client failed")
            if any("LAST PACKET NOT RECEIVED" in line for line in lines):
                raise RuntimeError("native receiver final statistics missing")
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            actions.append({"capture_complete": True, "utc": utc()})
        finally:
            if host:
                if host.poll() is None:
                    host.send_signal(signal.SIGINT)
                    try:
                        host.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        host.kill()
                        host.wait()
                actions.append({"host_returncode": host.returncode, "utc": utc()})
            if sink:
                sink.close()
            if packet_capture:
                if packet_capture.poll() is None:
                    processes = run(["ps", "-C", "tcpdump", "-o", "pid=,args="])["output"].splitlines()
                    children = [int(line.split(maxsplit=1)[0]) for line in processes
                                if line.split(maxsplit=1)[1].split() == packet_command]
                    if len(children) != 1:
                        raise RuntimeError("cannot identify the owned packet capture process")
                    run(["kill", "-INT", str(children[0])], True)
                    try:
                        packet_capture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        raise RuntimeError("owned packet capture did not close cleanly")
                actions.append({"packet_capture_returncode": packet_capture.returncode, "utc": utc()})
            if packet_log:
                packet_log.close()
            stop.set()
            thread.join(timeout=2)
            (directory / "actions.json").write_text(json.dumps(actions, indent=2) + "\n")
    if errors:
        raise RuntimeError(errors)
    print(f"{case}: {directory.name} captured; independent audit pending", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--flash", action="store_true")
    parser.add_argument("--cases", nargs="+", choices=["udp_tx", "udp_rx", "tcp_tx", "tcp_rx"],
                        default=["udp_tx", "udp_rx"])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--capture-subdirectory", default="")
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 6 or args.seconds % 3:
        raise ValueError("positive original report intervals required")
    name = args.capture_subdirectory or ("probe-v1" if args.probe else "captures-v1")
    if Path(name).name != name:
        raise ValueError("capture subdirectory must be one relative name")
    directory = OUTPUT / name
    directory.mkdir()
    with (ROOT / "tm-sync-power.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = run(["nmcli", "-t", "-f", "WIFI", "radio"])
        if initial["output"].strip() not in ("disabled", "已禁用"):
            raise RuntimeError("refuse to replace an existing enabled Wi-Fi session")
        if CONNECTION in run(["nmcli", "-t", "-f", "NAME", "connection"])["output"].splitlines():
            raise RuntimeError("temporary connection already exists")
        if args.flash:
            if (OUTPUT / "flash.log").exists():
                raise ValueError("do not overwrite an existing installation witness")
            run(["bash", "-c", 'cd "$1" && sha256sum -c image.sha256', "manifest", str(OUTPUT)])
            os.environ["PYTHONPATH"] = str(ROOT / "python-nuttx/lib/python3.8/site-packages") + \
                ":" + str(ROOT / "esptool-4.8.1")
            flash = run([str(ROOT / "zephyr-v3.7.0-work/pyenv/bin/python"), "-m", "esptool",
                         "--chip", "esp32", "--port", "/dev/ttyUSB0", "--baud", "460800",
                         "write_flash", "--flash_mode", "dio", "--flash_freq", "40m",
                         "--flash_size", "4MB", "0x1000", str(OUTPUT / "zephyr.bin")], check=False)
            (OUTPUT / "flash.log").write_text(flash["output"])
            if flash["returncode"]:
                raise RuntimeError("installation failed; retained flash.log")
        (directory / "host-before.json").write_text(json.dumps({"radio": initial,
            "addresses": run(["ip", "-j", "address"]), "routes": run(["ip", "-j", "route"]),
            "iperf": run([str(OUTPUT / "iperf-host"), "--version"], check=False)}, indent=2) + "\n")
        try:
            run(["nmcli", "radio", "wifi", "on"], True)
            run(["nmcli", "connection", "add", "type", "wifi", "ifname", DEVICE,
                 "con-name", CONNECTION, "ssid", SSID, "connection.autoconnect", "no",
                 "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", PASSWORD,
                 "ipv4.method", "manual", "ipv4.addresses", "192.168.4.2/24",
                 "ipv4.never-default", "yes", "ipv6.method", "ignore"], True)
            if args.probe:
                trial(directory / "boot", "udp_tx", args.seconds, True)
            else:
                for reset in range(1, args.repeats + 1):
                    for case in args.cases:
                        trial(directory / f"{case}-reset{reset}", case, args.seconds)
        finally:
            cleanup = [run(["nmcli", "connection", "delete", CONNECTION], True, False),
                       run(["nmcli", "radio", "wifi", "off"], True, False)]
            (directory / "host-after.json").write_text(json.dumps({"cleanup": cleanup,
                "radio": run(["nmcli", "radio"]), "addresses": run(["ip", "-j", "address"]),
                "routes": run(["ip", "-j", "route"])}, indent=2) + "\n")


if __name__ == "__main__":
    main()
