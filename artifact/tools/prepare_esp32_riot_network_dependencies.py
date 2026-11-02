#!/usr/bin/env python3
"""Prepare exact RIOT package archives through its native local-source interface."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.request import Request, urlopen
import zipfile

REVISION = "dd06b3727c41c2c44bf93f47ff7831fdd501d68b"
PACKAGES = {
    "esp32_sdk_lib_phy": ("espressif/esp-phy-lib", "dcbe6085e0215e2ea6a2e43b1106bdb15807f398"),
    "esp32_sdk_lib_wifi": ("espressif/esp32-wifi-lib", "5a0d2aee49633b1a0c0374c2a01ed8c2a10e2fe4"),
    "tlsf": ("mattconte/tlsf", "a1f743ffac0305408b39e791e0ffb45f6d9bc777"),
}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "ESP32-public-benchmark"}), timeout=60) as response:
        body = response.read(128 * 1024 * 1024 + 1)
    if len(body) > 128 * 1024 * 1024:
        raise ValueError("archive exceeds bound")
    return body


def prepare(directory, offline=False):
    if offline:
        if not directory.is_dir():
            raise ValueError("offline dependency directory missing")
    else:
        directory.mkdir(parents=True, exist_ok=True)
    records = []
    for name, (repository, revision) in PACKAGES.items():
        manifest = directory / (name + "-Makefile")
        url = f"https://raw.githubusercontent.com/RIOT-OS/RIOT/{REVISION}/pkg/{name}/Makefile"
        if not offline:
            body = fetch(url)
            if manifest.exists() and manifest.read_bytes() != body:
                raise ValueError("refuse to replace package manifest")
            manifest.write_bytes(body)
        text = manifest.read_text()
        if not re.search(r"^PKG_URL=https://github.com/" + re.escape(repository) + r"$", text, re.M) or \
                not re.search(r"^PKG_VERSION=" + revision + r"$", text, re.M):
            raise ValueError("fixed native package binding differs")
        archive = directory / (name + ".zip")
        archive_url = f"https://codeload.github.com/{repository}/zip/{revision}"
        if not archive.exists():
            if offline:
                raise ValueError("offline archive missing")
            archive.write_bytes(fetch(archive_url))
        files = []
        prefix = repository.split("/")[-1] + "-" + revision + "/"
        source = directory / "sources" / name
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if not member.filename.startswith(prefix):
                    raise ValueError("unexpected archive root")
                relative = Path(member.filename[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts or stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("unsafe archive member")
                if member.is_dir():
                    continue
                target = source / relative
                body = package.read(member)
                if target.exists() and target.read_bytes() != body:
                    raise ValueError("native source changed")
                if not target.exists():
                    if offline:
                        raise ValueError("offline native source missing")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(body)
                files.append({"path": relative.as_posix(), "sha256": sha(body)})
        if {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()} != {row["path"] for row in files}:
            raise ValueError("unexpected local-source file")
        records.append({"package": name, "repository": repository, "revision": revision,
                        "manifest_url": url, "manifest_sha256": sha(manifest.read_bytes()),
                        "archive_url": archive_url, "archive_sha256": sha(archive.read_bytes()), "files": files})
        print(f"Verified original {name}: {len(files)} files", flush=True)
    # RIOT's local-source hook skips pkg.mk's native patch stage; preserve that stage explicitly.
    patch_name = "0001-Fix-warnining-on-implicit-pointer-conversion.patch"
    patch_url = f"https://raw.githubusercontent.com/RIOT-OS/RIOT/{REVISION}/pkg/tlsf/patches/{patch_name}"
    patch = directory / patch_name
    if not offline:
        patch.write_bytes(fetch(patch_url))
    native = directory / "native-sources/tlsf"
    native_files = []
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        for target in (directory / "sources/tlsf").rglob("*"):
            if target.is_file():
                copy = staging / target.relative_to(directory / "sources/tlsf")
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(target.read_bytes())
        subprocess.run(["git", "apply", "--check", str(patch.resolve())], cwd=staging, check=True)
        subprocess.run(["git", "apply", str(patch.resolve())], cwd=staging, check=True)
        for target in staging.rglob("*"):
            if target.is_file():
                relative = target.relative_to(staging)
                copy = native / relative
                if copy.exists() and copy.read_bytes() != target.read_bytes():
                    raise ValueError("native patched source changed")
                if not copy.exists():
                    if offline:
                        raise ValueError("offline native patched source missing")
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    copy.write_bytes(target.read_bytes())
                native_files.append({"path": relative.as_posix(), "sha256": sha(target.read_bytes())})
    native_files.sort(key=lambda row: row["path"])
    path = directory / "provenance.json"
    previous = json.loads(path.read_text()) if path.exists() else None
    result = {"riot_revision": REVISION, "packages": records,
              "native_tlsf_patch": {"url": patch_url, "sha256": sha(patch.read_bytes()), "files": native_files}}
    if offline and previous != result:
        raise ValueError("offline dependency provenance changed")
    if not offline:
        path.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    prepare(args.directory, args.offline)
