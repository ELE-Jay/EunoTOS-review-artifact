#!/usr/bin/env python3
"""Capture the original RIOT IPv6 UDP client/peer; restore the temporary host link."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess
import threading
import time

import serial
from run_esp32_iperf_original import ROOT, DEVICE, CONNECTION, SSID, PASSWORD, run, utc

IMAGE = ROOT / "downloads/riot-benchmark-udp-original-v2"
HOST = "fd00:dead:beef::1"
BOARD = "fd00:dead:beef::2"
PROFILES = {"default": [], "payload1024-interval1000": ["-i", "1000", "-s", "1024"]}
FIREWALL_RULE = ["-i", DEVICE, "-s", BOARD + "/128", "-d", HOST + "/128", "-p", "udp",
                 "--sport", "12345", "--dport", "12345", "-m", "comment",
                 "--comment", "esp32-riot-udp-original", "-j", "ACCEPT"]


def trial(directory, profile, seconds, *, board_bssid="84:1f:e8:8f:55:dd", port_name="/dev/ttyUSB0"):
    from run_esp32_native_network_b1 import link_local
    address = link_local(board_bssid)
    directory.mkdir()
    started = time.monotonic()
    actions, threads, processes, streams, errors, lines, peer_lines = [], [], [], [], [], [], []
    stop = threading.Event()

    def record(name, read):
        pending = b""
        try:
            with (directory / (name + ".raw")).open("wb") as raw, (directory / (name + ".jsonl")).open("w") as output:
                while not stop.is_set():
                    chunk = read()
                    if not chunk:
                        continue
                    raw.write(chunk)
                    raw.flush()
                    pending += chunk
                    while b"\n" in pending:
                        chunk, pending = pending.split(b"\n", 1)
                        chunk += b"\n"
                        line = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
                        if name == "uart":
                            lines.append(line)
                        else:
                            peer_lines.append(line)
                        output.write(json.dumps({"utc": utc(), "elapsed_s": time.monotonic() - started, "line": line,
                                                 "raw_bytes": len(chunk),
                                                 "raw_sha256": hashlib.sha256(chunk).hexdigest()}) + "\n")
                        output.flush()
                if pending:
                    output.write(json.dumps({"utc": utc(), "elapsed_s": time.monotonic() - started,
                                             "line": pending.decode("utf-8", errors="replace").rstrip("\r"),
                                             "raw_bytes": len(pending),
                                             "raw_sha256": hashlib.sha256(pending).hexdigest()}) + "\n")
        except Exception as error:
            errors.append(str(error))

    with serial.Serial(port_name, 115200, timeout=0.2) as port:
        def send(command):
            actions.append({"board_command": command, "utc": utc(), "elapsed_s": time.monotonic() - started})
            port.write((command + "\n").encode())
            port.flush()

        def launch_reader(name, read):
            thread = threading.Thread(target=record, args=(name, read))
            thread.start()
            threads.append(thread)

        launch_reader("uart", lambda: port.read(4096))
        master = None
        try:
            actions.append(run(["nmcli", "connection", "down", CONNECTION], True, False))
            actions.append({"hardware_reset": "EN via RTS; DTR low", "utc": utc()})
            port.dtr = False
            port.rts = True
            time.sleep(0.25)
            port.rts = False
            time.sleep(4)
            if not any("RIOT UDP stress-test application" in line for line in lines):
                raise RuntimeError("native RIOT UDP boot missing")
            send("ifconfig 8 add " + BOARD + "/64")
            time.sleep(1)
            send("ifconfig 8 add " + address + "/64")
            time.sleep(0.5)
            send("nib prefix add 8 fd00:dead:beef::/64")
            time.sleep(0.5)
            send("ifconfig")
            actions.append(run(["nmcli", "device", "wifi", "rescan", "ifname", DEVICE], True, False))
            time.sleep(3)
            connected = run(["nmcli", "--wait", "35", "connection", "up", CONNECTION], True, False)
            actions.append(connected)
            if connected["returncode"]:
                raise RuntimeError(connected["output"])
            actions.append(run(["ip", "-j", "address", "show", "dev", DEVICE]))
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            packet_log = (directory / "pcap.log").open("w")
            streams.append(packet_log)
            packet_command = ["tcpdump", "-Z", "leon", "-U", "-n", "-i", DEVICE, "-s", "96",
                              "-w", str(directory / "udp.pcap"), "ip6", "and", "(", "icmp6", "or", "udp", "port", "12345", ")"]
            actions.append({"packet_command": packet_command, "utc": utc()})
            packet = subprocess.Popen(["sudo", "-S", "-p", "", *packet_command], stdin=subprocess.PIPE,
                                      stdout=packet_log, stderr=subprocess.STDOUT, universal_newlines=True)
            packet.stdin.write(os.environ["BENCHMARK_SSH_PASSWORD"] + "\n")
            packet.stdin.close()
            processes.append(("packet", packet))
            time.sleep(1)
            if packet.poll() is not None or "listening on" not in (directory / "pcap.log").read_text():
                raise RuntimeError("packet capture did not start")
            ping = run(["ping", "-6", "-I", DEVICE, "-c", "3", "-W", "2", BOARD], check=False)
            actions.append(ping)
            neighbor = run(["ip", "-6", "neighbor", "show", "dev", DEVICE])
            actions.append(neighbor)
            send("ifconfig")
            time.sleep(0.5)
            send("nib neigh show")
            time.sleep(0.5)
            # The unmodified native application does not link gnrc_icmpv6_echo.
            if BOARD + " lladdr " + board_bssid + " REACHABLE" not in neighbor["output"]:
                raise RuntimeError("native IPv6 neighbor discovery failed")
            arguments = [str(IMAGE / "host-source/bin/benchmark_server"), *PROFILES[profile], HOST, "12345"]
            master, slave = pty.openpty()
            actions.append({"host_command": arguments, "stdout_mode": "PTY, original terminal buffering", "utc": utc()})
            peer = subprocess.Popen(arguments, stdout=slave, stderr=slave)
            os.close(slave)
            processes.append(("peer", peer))

            def read_peer():
                return os.read(master, 4096) if select.select([master], [], [], 0.2)[0] else b""

            launch_reader("host", read_peer)
            time.sleep(0.5)
            send("bench_udp start " + HOST + " 12345")
            measurement_started = time.monotonic()
            while time.monotonic() - measurement_started < seconds:
                if errors or peer.poll() is not None or packet.poll() is not None:
                    raise RuntimeError(("capture process stopped", errors))
                if time.monotonic() - measurement_started > 10 and not any("b/s" in line and BOARD in line for line in peer_lines):
                    raise RuntimeError("original UDP peer handshake/traffic absent")
                time.sleep(0.25)
            send("bench_udp stop")
            time.sleep(3)
            send("ifconfig")
            time.sleep(0.5)
            send("ps")
            time.sleep(0.5)
            actions.append(run(["iw", "dev", DEVICE, "link"]))
            actions.append({"capture_complete": True, "requested_seconds": seconds, "utc": utc()})
        finally:
            # Drain both observers before stopping the peer, avoiding a PTY EIO treated as acquisition failure.
            stop.set()
            for thread in threads:
                thread.join(timeout=3)
            for name, process in reversed(processes):
                if process.poll() is None:
                    if name == "packet":
                        candidates = run(["ps", "-C", "tcpdump", "-o", "pid=,args="], check=False)["output"].splitlines()
                        children = [int(line.split(maxsplit=1)[0]) for line in candidates
                                    if line.split(maxsplit=1)[1].split() == packet_command]
                        if len(children) != 1:
                            raise RuntimeError("cannot identify the owned packet capture process")
                        actions.append(run(["kill", "-INT", str(children[0])], True))
                    else:
                        process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if name == "packet":
                            raise RuntimeError("owned packet capture did not close cleanly")
                        process.kill()
                        process.wait()
                actions.append({"process": name, "returncode": process.returncode, "utc": utc()})
            if master is not None:
                os.close(master)
            for stream in streams:
                stream.close()
            (directory / "actions.json").write_text(json.dumps(actions, indent=2) + "\n")
    if errors:
        raise RuntimeError(errors)
    print(f"{directory.name}: original RIOT UDP records captured; audit pending", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--cohort", default="captures-v1")
    args = parser.parse_args()
    if args.repeats < 1 or args.seconds < 10 or not re.fullmatch(r"[a-z0-9-]+", args.cohort):
        raise ValueError("invalid capture parameters")
    directory = IMAGE / args.cohort
    directory.mkdir()
    with (ROOT / "tm-sync-power.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = run(["nmcli", "-t", "-f", "WIFI", "radio"])
        initial_rule = run(["ip6tables", "-C", "INPUT", *FIREWALL_RULE], True, False)
        if initial["output"].strip() not in ("disabled", "已禁用") or \
                initial_rule["returncode"] != 1 or \
                CONNECTION in run(["nmcli", "-t", "-f", "NAME", "connection"])["output"].splitlines():
            raise RuntimeError("refuse to replace an existing Wi-Fi session/connection")
        shutil.copy2(__file__, directory / "runner.py")
        (directory / "host-before.json").write_text(json.dumps({"radio": initial, "scoped_firewall_rule": initial_rule,
            "addresses": run(["ip", "-j", "address"]), "routes": run(["ip", "-j", "route"]),
            "processes": run(["ps", "-eo", "pid,ppid,pcpu,stat,comm"])}, indent=2) + "\n")
        try:
            setup = run(["ip6tables", "-I", "INPUT", "1", *FIREWALL_RULE], True)
            (directory / "firewall-setup.json").write_text(json.dumps(setup, indent=2) + "\n")
            run(["nmcli", "radio", "wifi", "on"], True)
            run(["nmcli", "connection", "add", "type", "wifi", "ifname", DEVICE, "con-name", CONNECTION,
                 "ssid", SSID, "connection.autoconnect", "no", "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", PASSWORD,
                 "ipv4.method", "disabled", "ipv6.method", "manual", "ipv6.addresses", HOST + "/64",
                 "ipv6.never-default", "yes"], True)
            for reset in range(1, args.repeats + 1):
                for profile in args.profiles:
                    trial(directory / f"{profile}-reset{reset}", profile, args.seconds)
        finally:
            cleanup = [run(["ip6tables", "-D", "INPUT", *FIREWALL_RULE], True, False),
                       run(["nmcli", "connection", "delete", CONNECTION], True, False),
                       run(["nmcli", "radio", "wifi", "off"], True, False)]
            (directory / "host-after.json").write_text(json.dumps({"cleanup": cleanup,
                "scoped_firewall_rule": run(["ip6tables", "-C", "INPUT", *FIREWALL_RULE], True, False),
                "radio": run(["nmcli", "radio"]), "addresses": run(["ip", "-j", "address"]),
                "routes": run(["ip", "-j", "route"]), "processes": run(["ps", "-eo", "pid,ppid,pcpu,stat,comm"])}, indent=2) + "\n")


if __name__ == "__main__":
    main()
