#!/usr/bin/env python3
"""Online-update metadata of a release, derived from module.prop and
CHANGELOG.md: the update.json that root managers poll through the module's
updateJson address, and the changelog they show before installing.

usage: release_meta.py <module.prop> <CHANGELOG.md> [<out-dir>]

Without <out-dir> the inputs are only validated.
"""
import json
import os
import re
import sys

# update.json is served from the newest published release, so an update only
# becomes visible once that release (and its zip) exists.
UPDATE_JSON = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/latest/download/update\.json")
VERSION = re.compile(r"(\d+)\.(\d{1,2})\.(\d{1,2})")


class Error(Exception):
    pass


def read_prop(path):
    with open(path, encoding="utf-8") as f:
        return dict(line.split("=", 1) for line in f.read().splitlines() if "=" in line)


def changelog_section(path, version):
    """Return the body of the "## <version>" section."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    body, inside = [], False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = line[3:].strip() == version
            continue
        if inside:
            body.append(line)
    text = "\n".join(body).strip()
    if not text:
        raise Error(f"CHANGELOG.md has no entry for {version}")
    return text


def load(prop_path, changelog_path):
    """Return (update.json content, zip file name, changelog text)."""
    prop = read_prop(prop_path)
    version, code = prop.get("version", ""), prop.get("versionCode", "")
    m = VERSION.fullmatch(version)
    if not m:
        raise Error(f"module.prop version {version!r} is not MAJOR.MINOR.PATCH")
    major, minor, patch = (int(g) for g in m.groups())
    # Managers offer an update only when versionCode grows, so it must follow
    # the version instead of being edited separately.
    want = major * 10000 + minor * 100 + patch
    if code != str(want):
        raise Error(f"module.prop versionCode {code!r} does not match version {version} (expected {want})")
    m = UPDATE_JSON.fullmatch(prop.get("updateJson", ""))
    if not m:
        raise Error("module.prop updateJson must be https://github.com/<owner>/<repo>/releases/latest/download/update.json")
    zip_name = f"{prop.get('id', '')}-v{version}.zip"
    base = f"https://github.com/{m.group(1)}/releases/download/v{version}/"
    update = {
        "version": version,
        "versionCode": want,
        "zipUrl": base + zip_name,
        "changelog": base + "changelog.md",
    }
    return update, zip_name, f"## {version}\n\n{changelog_section(changelog_path, version)}\n"


def write(out_dir, update, changelog):
    with open(os.path.join(out_dir, "update.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(update, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(os.path.join(out_dir, "changelog.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(changelog)


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    try:
        update, _, changelog = load(sys.argv[1], sys.argv[2])
    except Error as e:
        sys.exit(str(e))
    if len(sys.argv) == 4:
        os.makedirs(sys.argv[3], exist_ok=True)
        write(sys.argv[3], update, changelog)
    print(f"release metadata ok: {update['version']} ({update['versionCode']})")


if __name__ == "__main__":
    main()
