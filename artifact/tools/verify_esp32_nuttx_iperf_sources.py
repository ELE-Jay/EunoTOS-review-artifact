#!/usr/bin/env python3
"""Bind original NuttX iPerf and the native pinned RF dependency to upstream."""
import argparse
import hashlib
import io
import json
from pathlib import Path
from urllib.request import Request, urlopen
import zipfile

from audit_esp32_nuttx_iperf_readiness import original_urls
from audit_esp32_riot_original import digest


def fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "ESP32-public-benchmark"}), timeout=45) as response:
        body = response.read(64 * 1024 * 1024 + 1)
    if len(body) > 64 * 1024 * 1024:
        raise ValueError("unexpected upstream dependency size")
    return body


def urls():
    result = original_urls()
    result["native-source/tools/version.sh"] = "https://raw.githubusercontent.com/apache/nuttx/nuttx-12.2.1/tools/version.sh"
    result["netinit-source/netinit_associate.c"] = "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/netutils/netinit/netinit_associate.c"
    for name in ("driver_wext.c", "network.c", "util.c", "wapi.c", "wireless.c"):
        result["wapi-source/src/" + name] = "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/wireless/wapi/src/" + name
    result["wapi-source/wapi.h"] = "https://raw.githubusercontent.com/apache/nuttx-apps/nuttx-12.2.1/include/wireless/wapi.h"
    return result


def verify(directory):
    originals = []
    for path, url in sorted(urls().items()):
        sha = hashlib.sha256(fetch(url)).hexdigest()
        if sha != digest(directory / path):
            raise ValueError(("original source differs", path))
        originals.append({"path": path, "url": url, "sha256": sha})
    (directory / "official-source.json").write_text(json.dumps(originals, indent=2) + "\n")
    commit_url = "https://api.github.com/repos/espressif/esp-wireless-drivers-3rdparty/commits/45701c0"
    commit_body = fetch(commit_url)
    commit = json.loads(commit_body)["sha"]
    if len(commit) != 40 or not commit.startswith("45701c0"):
        raise ValueError("native RF revision resolution differs")
    archive_url = "https://codeload.github.com/espressif/esp-wireless-drivers-3rdparty/zip/" + commit
    archive = fetch(archive_url)
    files = []
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        prefix = "esp-wireless-drivers-3rdparty-" + commit + "/"
        for path in sorted((directory / "wireless-dependency").rglob("*")):
            if path.is_file():
                relative = path.relative_to(directory / "wireless-dependency").as_posix()
                sha = hashlib.sha256(package.read(prefix + relative)).hexdigest()
                if digest(path) != sha:
                    raise ValueError(("native RF source/library differs", relative))
                files.append({"path": relative, "sha256": sha})
    (directory / "rf-commit.json").write_bytes(commit_body)
    (directory / "wireless-upstream.zip").write_bytes(archive)
    result = {"commit_url": commit_url, "commit": commit, "commit_response_sha256": hashlib.sha256(commit_body).hexdigest(),
              "archive_url": archive_url, "archive_sha256": hashlib.sha256(archive).hexdigest(), "files": files}
    (directory / "rf-provenance.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified %d original files and %d fixed-revision RF files" % (len(originals), len(files)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    verify(parser.parse_args().directory)
