#!/usr/bin/env python3
"""Bind the untouched AliOS iPerf/native network sources to the existing fixed release."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess

from prepare_esp32_riot_network_dependencies import fetch, sha

REVISION = "bacc144bdc5df8fe8e302e3732675a920aa40bc5"
PATHS = (
    "network/lwip/apps/iperf/iperf_task.c", "network/lwip/apps/iperf/iperf_cli.c",
    "network/lwip/include/lwip/apps/iperf.h", "network/lwip/include/lwip/apps/iperf_task.h",
    "network/lwip/include/lwip/apps/iperf_cli.h", "network/lwip/include/lwip/apps/iperf_debug.h",
    "network/lwip/aos.mk", "network/lwip/Filelists.mk", "kernel/init/aos_init.c",
    "platform/mcu/esp32/hal/wifi_port.c", "platform/mcu/esp32/bsp/entry.c",
    "platform/mcu/esp32/bsp/tcpip_adapter_lwip.c", "platform/mcu/esp32/bsp/wlanif.c",
    "kernel/cli/cli.c", "osal/aos/cli.c",
    "board/esp32devkitc/lwipopts.h",
)


def urls():
    return {"native-source/" + path.replace("board/esp32devkitc/", "board/esp32bench/"):
            f"https://raw.githubusercontent.com/alibaba/AliOS-Things/{REVISION}/{path}" for path in PATHS}


def verify(directory):
    records = []
    for path, url in sorted(urls().items()):
        body = fetch(url)
        if body != (directory / path).read_bytes():
            raise ValueError(("original native network source differs", path))
        records.append({"path": path, "url": url, "sha256": sha(body)})
    (directory / "official-source.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"Verified {len(records)} original AliOS iPerf/native network files")


def dependencies(directory, source=None):
    paths = sorted({part[2:] if part.startswith("./") else part for part in shlex.split((directory / "link.opts").read_text())
                    if part.startswith(("./platform/mcu/esp32/lib/", "platform/mcu/esp32/lib/")) and part.endswith(".a")})
    if not paths:
        raise ValueError("native linked archive list missing")
    records = []
    for path in paths:
        target = directory / "native-dependencies" / path
        if source is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != (source / path).read_bytes():
                raise ValueError("refuse to replace a changed native archive")
            shutil.copy2(source / path, target)
        else:
            url = f"https://raw.githubusercontent.com/alibaba/AliOS-Things/{REVISION}/{path}"
            if fetch(url) != target.read_bytes():
                raise ValueError(("original linked dependency differs", path))
            records.append({"path": "native-dependencies/" + path, "url": url, "sha256": sha(target.read_bytes())})
        print("Bound native archive " + path, flush=True)
    if source is None:
        (directory / "network-dependencies.json").write_text(json.dumps({"revision": REVISION,
            "link_opts_sha256": sha((directory / "link.opts").read_bytes()), "files": records}, indent=2) + "\n")


def preprocess(directory, source):
    records = []
    for name in ("iperf_task", "iperf_cli"):
        path = "network/lwip/apps/iperf/" + name + ".c"
        commands = [shlex.split(line) for line in (directory / "build.log").read_text().splitlines()
                    if line.startswith("xtensa-esp32-elf-gcc ") and path in shlex.split(line)]
        if len(commands) != 1:
            raise ValueError("unique actual original compile command missing")
        command = [token for token in commands[0] if token != "-MD"]
        command[command.index("-c")] = "-E"
        command.insert(1, "-P")
        command[command.index("-o") + 1] = str((directory / (name + "-preprocessed.c")).resolve())
        subprocess.run(command, cwd=source, check=True)
        records.append({"original_compile": commands[0], "preprocess": command,
                        "output_sha256": sha((directory / (name + "-preprocessed.c")).read_bytes())})
    (directory / "measurement-preprocess.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--dependencies", action="store_true")
    parser.add_argument("--snapshot-dependencies", type=Path)
    parser.add_argument("--preprocess", type=Path)
    args = parser.parse_args()
    if args.preprocess:
        preprocess(args.directory, args.preprocess.resolve())
    elif args.dependencies or args.snapshot_dependencies:
        dependencies(args.directory, args.snapshot_dependencies)
    else:
        verify(args.directory)
