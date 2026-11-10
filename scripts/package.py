#!/usr/bin/env python3
"""Package a staged module tree into a flashable zip with fixed permissions
and write a release manifest plus the online-update files (update.json,
changelog.md), then verify the result.

usage: package.py <staged-dir> <out.zip> <version> <versionCode> <buildId> <CHANGELOG.md>
"""
import hashlib
import json
import os
import stat
import sys
import zipfile

sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
import release_meta  # noqa: E402

EXECUTABLES = {
    "customize.sh", "service.sh", "action.sh", "uninstall.sh", "proxyctl",
    "bin/arm64-v8a/proxy-managerd", "bin/arm64-v8a/proxyctl",
    "bin/x86_64/proxy-managerd", "bin/x86_64/proxyctl",
    "META-INF/com/google/android/update-binary",
}
# ELF e_machine per ABI directory: EM_AARCH64 and EM_X86_64.
MACHINES = {"arm64-v8a": 183, "x86_64": 62}
REQUIRED = EXECUTABLES | {
    "module.prop", "README.md", "THIRD_PARTY_NOTICES.txt", "docs/DESIGN.md", "webroot/index.html",
    "webroot/assets/app.css", "webroot/assets/main.js", "webroot/assets/api.js", "webroot/assets/ui.js",
    "webroot/assets/theme.js", "webroot/assets/icons.js", "webroot/assets/vendor/lucide.js",
    "webroot/assets/vendor/lucide-LICENSE.txt",
    "META-INF/com/google/android/updater-script",
}
TEXT_SUFFIXES = (".sh", ".prop", ".md", ".txt", ".html", ".js", ".css", "updater-script", "update-binary", "proxyctl")
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                sys.exit(f"symlink not allowed in package: {rel}")
            files.append(rel)
    return files


def check_text(root, rel):
    if not rel.endswith(TEXT_SUFFIXES) or rel.startswith("bin/"):
        return
    data = open(os.path.join(root, rel), "rb").read()
    if b"\r" in data:
        sys.exit(f"CR line endings in {rel}")
    if data.startswith(b"\xef\xbb\xbf"):
        sys.exit(f"UTF-8 BOM in {rel}")
    if rel.endswith(".sh") or rel == "proxyctl":
        if not data.startswith(b"#!/system/bin/sh\n"):
            sys.exit(f"{rel} must start with #!/system/bin/sh")


def main():
    if len(sys.argv) != 7:
        sys.exit(__doc__)
    root, out, version, code, build_id, changelog_path = sys.argv[1:]
    files = collect(root)
    missing = sorted(REQUIRED - set(files))
    if missing:
        sys.exit("missing files: " + ", ".join(missing))
    prop = dict(line.split("=", 1) for line in open(os.path.join(root, "module.prop"), encoding="utf-8").read().splitlines() if "=" in line)
    if prop.get("id") != "ksu_proxy_manager" or prop.get("version") != version or prop.get("versionCode") != code:
        sys.exit("module.prop does not match the build version")
    # The update files describe the module.prop that is actually shipped.
    try:
        update, zip_name, changelog = release_meta.load(os.path.join(root, "module.prop"), changelog_path)
    except release_meta.Error as e:
        sys.exit(str(e))
    if zip_name != os.path.basename(out):
        sys.exit(f"update.json points at {zip_name}, but the package is {os.path.basename(out)}")
    for rel in files:
        check_text(root, rel)
        if rel.startswith("bin/"):
            abi = rel.split("/")[1]
            with open(os.path.join(root, rel), "rb") as f:
                head = f.read(20)
            machine = int.from_bytes(head[18:20], "little")
            if head[:4] != b"\x7fELF" or head[4] != 2 or MACHINES.get(abi) != machine:
                sys.exit(f"{rel} is not an ELF64 for {abi}")

    tmp = out + ".tmp"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        dirs = sorted({os.path.dirname(f) for f in files if os.path.dirname(f)} |
                      {"/".join(f.split("/")[:i]) for f in files for i in range(1, f.count("/") + 1)})
        for d in dirs:
            info = zipfile.ZipInfo(d + "/", FIXED_TIME)
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            info.create_system = 3
            z.writestr(info, b"")
        for rel in files:
            info = zipfile.ZipInfo(rel, FIXED_TIME)
            mode = 0o755 if rel in EXECUTABLES else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(root, rel), "rb") as f:
                z.writestr(info, f.read())
    os.replace(tmp, out)

    manifest = {
        "id": "ksu_proxy_manager",
        "version": version,
        "versionCode": int(code),
        "buildId": build_id,
        "zip": os.path.basename(out),
        "zipSha256": sha256(out),
        "files": {rel: sha256(os.path.join(root, rel)) for rel in files},
    }
    manifest_path = os.path.join(os.path.dirname(out), "release-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    # Verify the archive against the manifest.
    with zipfile.ZipFile(out) as z:
        names = [i.filename for i in z.infolist() if not i.filename.endswith("/")]
        if sorted(names) != sorted(files):
            sys.exit("zip content mismatch")
        for info in z.infolist():
            if info.filename.endswith("/"):
                continue
            mode = (info.external_attr >> 16) & 0o777
            want = 0o755 if info.filename in EXECUTABLES else 0o644
            if mode != want:
                sys.exit(f"bad mode {oct(mode)} for {info.filename}")
            if hashlib.sha256(z.read(info)).hexdigest() != manifest["files"][info.filename]:
                sys.exit(f"hash mismatch for {info.filename}")
    print(f"packaged {out} ({len(files)} files, sha256 {manifest['zipSha256']})")
    # Written last: a failed build leaves no update files describing it.
    release_meta.write(os.path.dirname(out), update, changelog)
    print(f"release assets for tag v{version}: {zip_name}, update.json, changelog.md")


if __name__ == "__main__":
    main()
