#!/usr/bin/env python3
"""Bind the native RIOT UDP workload, peer and AP driver to the pinned original."""
import argparse
import json
from pathlib import Path

from prepare_esp32_riot_network_dependencies import REVISION, fetch, sha


def urls():
    paths = {"benchmark_udp.h": "sys/include/test_utils/benchmark_udp.h"}
    for name in ("main.c", "Makefile", "README.md"):
        paths["source/" + name] = "examples/benchmark_udp/" + name
        paths["host-source/" + name] = "dist/tools/benchmark_udp/" + name
    for name in ("benchmark_udp.c", "Makefile"):
        paths["benchmark-module/" + name] = "sys/test_utils/benchmark_udp/" + name
    for name in ("Makefile", "doc.txt", "esp_wifi_gnrc.c", "esp_wifi_netdev.c", "esp_wifi_netdev.h", "esp_wifi_params.h"):
        paths["native-driver/" + name] = "cpu/esp_common/esp-wifi/" + name
    paths.update({"native-source/pkg.mk": "pkg/pkg.mk", "native-source/local.mk": "pkg/local.mk",
                  "native-source/list.h": "core/lib/include/list.h", "native-source/kernel_defines.h": "core/lib/include/kernel_defines.h"})
    return {path: f"https://raw.githubusercontent.com/RIOT-OS/RIOT/{REVISION}/{upstream}" for path, upstream in paths.items()}


def verify(directory):
    records = []
    for path, url in sorted(urls().items()):
        body = fetch(url)
        if body != (directory / path).read_bytes():
            raise ValueError(("native original source differs", path))
        records.append({"path": path, "url": url, "sha256": sha(body)})
    (directory / "official-source.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"Verified {len(records)} original RIOT UDP workload/peer/AP files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    verify(parser.parse_args().directory)
