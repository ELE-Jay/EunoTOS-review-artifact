#!/usr/bin/env python3
"""Capture KM003C branch power and optional ESP32 UART on one host clock.

Read-only protocol: Linux drivers/hwmon/powerz.c (0c 00 02 00, bulk 01/81).
No PD, voltage-selection, or firmware-update commands are sent.
"""

import argparse
import csv
import json
import math
import struct
import time
from datetime import datetime, timezone
from pathlib import Path


def decode_packet(packet):
    if len(packet) < 48 or len(packet) > 64:
        raise ValueError("unexpected POWER-Z sensor packet length")
    voltage = struct.unpack_from("<I", packet, 8)[0] / 1e6
    current = struct.unpack_from("<i", packet, 12)[0] / 1e6
    if not 0 <= voltage <= 60 or not -6 <= current <= 6:
        raise ValueError("POWER-Z sensor values outside instrument range")
    return voltage, current


class Meter:
    def __init__(self):
        import usb.core
        import usb.util
        self.util = usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x5FC9, idProduct=0x0063))
        if len(devices) != 1:
            raise ValueError("expected exactly one KM003C")
        self.device = devices[0]
        interface = self.device.get_active_configuration()[(0, 0)]
        endpoints = {ep.bEndpointAddress: ep.bmAttributes & 3 for ep in interface}
        if endpoints.get(0x01) != 2 or endpoints.get(0x81) != 2:
            raise ValueError("KM003C interface 0 does not match powerz bulk protocol")
        self.util.claim_interface(self.device, 0)

    def read(self):
        start = time.monotonic()
        if self.device.write(0x01, b"\x0c\x00\x02\x00", timeout=500) != 4:
            raise ValueError("incomplete POWER-Z query")
        packet = bytes(self.device.read(0x81, 64, timeout=500))
        end = time.monotonic()
        voltage, current = decode_packet(packet)
        return start, end, packet, voltage, current

    def close(self):
        self.util.release_interface(self.device, 0)
        self.util.dispose_resources(self.device)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=105)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--port")
    parser.add_argument("--send-line")
    args = parser.parse_args()
    if not all(math.isfinite(v) and v > 0 for v in (args.seconds, args.interval)):
        parser.error("duration and interval must be finite and positive")
    if args.send_line and not args.port:
        parser.error("--send-line requires --port")
    args.output.mkdir(parents=True, exist_ok=False)
    meter = Meter()
    started = time.monotonic()
    metadata = {
        "status": "incomplete", "started_utc": datetime.now(timezone.utc).isoformat(),
        "host_monotonic_start_s": started, "duration_requested_s": args.seconds,
        "interval_requested_s": args.interval, "port": args.port,
        "meter": "POWER-Z KM003C", "usb_id": "5fc9:0063",
        "usb_bus": meter.device.bus, "usb_address": meter.device.address,
        "protocol_source": "https://github.com/torvalds/linux/blob/master/drivers/hwmon/powerz.c",
        "timestamp_semantics": "host query/response midpoint; not sensor conversion time",
        "measurement_boundary": "meter branch; whole-board path not yet verified",
        "calibration": "instrument default; external calibration not verified",
    }
    metadata_path = args.output / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    port = None
    try:
        with (args.output / "power.csv").open("x", newline="") as csv_file, \
                (args.output / "meter.jsonl").open("x") as raw, \
                (args.output / "uart.jsonl").open("x") as uart:
            writer = csv.writer(csv_file)
            writer.writerow(["timestamp_s", "voltage_v", "current_a"])
            count = 0
            next_sample = started
            sent = False
            buffer = b""
            while time.monotonic() - started < args.seconds:
                if time.monotonic() >= next_sample:
                    before, after, packet, voltage, current = meter.read()
                    elapsed = (before + after) / 2 - started
                    writer.writerow([elapsed, voltage, current])
                    raw.write(json.dumps({"elapsed_s": elapsed,
                                          "query_start_s": before - started,
                                          "query_end_s": after - started,
                                          "packet_hex": packet.hex()}) + "\n")
                    csv_file.flush()
                    raw.flush()
                    count += 1
                    next_sample = before + args.interval
                    if args.port and port is None:
                        import serial
                        port = serial.Serial(args.port, 115200, timeout=0.01)
                        port.dtr = False
                        port.rts = True
                        time.sleep(0.25)
                        port.rts = False
                        metadata["reset_release_s"] = time.monotonic() - started
                if port is not None:
                    if args.send_line and not sent and time.monotonic() - started >= 1.5:
                        port.write((args.send_line + "\n").encode())
                        sent = True
                    buffer += port.read(max(1, port.in_waiting))
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        uart.write(json.dumps({
                            "elapsed_s": time.monotonic() - started,
                            "utc": datetime.now(timezone.utc).isoformat(),
                            "line": line.decode("utf-8", errors="replace").rstrip("\r"),
                        }) + "\n")
                        uart.flush()
                else:
                    time.sleep(min(args.interval, 0.01))
            metadata.update(status="complete", sample_count=count,
                            duration_actual_s=time.monotonic() - started,
                            uart_unterminated_bytes=len(buffer))
    finally:
        if port is not None:
            port.close()
        meter.close()
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata))


if __name__ == "__main__":
    main()
