#!/usr/bin/env python3
"""Generate THIRD_PARTY_LICENSES.txt for the rust-authentication binary.

Step 1: `cargo about` renders every shipped crate with its licence text and
        copyright notices (licenses/about.hbs, about.toml).
Step 2: this script appends, verbatim, every NOTICE / COPYRIGHT / AUTHORS file
        those crates ship. Apache-2.0 section 4(d) requires NOTICE contents to
        be redistributed, and several crates keep their copyright statement in
        COPYRIGHT/AUTHORS instead of the licence file.

Usage (from the repository root; offline, deterministic):
    python3 -I licenses/generate_notices.py [output-path]
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "crates" / "authn-server" / "Cargo.toml"
TEMPLATE = ROOT / "licenses" / "about.hbs"
NOTICE_RE = re.compile(r"^(NOTICE|COPYRIGHT|AUTHORS)(\.(txt|md))?$", re.IGNORECASE)
CRATE_LINE_RE = re.compile(r"^\* (\S+) (\S+): ")


def run(args):
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def main():
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "THIRD_PARTY_LICENSES.txt"

    about = run([
        "cargo", "about", "generate",
        "--manifest-path", str(MANIFEST),
        "--all-features", "--frozen", "--fail",
        str(TEMPLATE),
    ])

    # The "Crates" section lists exactly the crates linked into the binary.
    crates_section = about.split("\nCrates\n", 1)[1].split("\nLicence texts\n", 1)[0]
    shipped = set()
    for line in crates_section.splitlines():
        m = CRATE_LINE_RE.match(line)
        if m:
            shipped.add((m.group(1), m.group(2)))
    if not shipped:
        sys.exit("no crates found in cargo-about output")

    metadata = json.loads(run([
        "cargo", "metadata", "--manifest-path", str(MANIFEST),
        "--all-features", "--frozen", "--format-version", "1",
    ]))
    roots = {}
    for pkg in metadata["packages"]:
        key = (pkg["name"], pkg["version"])
        if key in shipped:
            roots[key] = pathlib.Path(pkg["manifest_path"]).parent
    missing = sorted(shipped - roots.keys())
    if missing:
        sys.exit(f"crates without a source directory: {missing}")

    parts = [about.rstrip("\n"), "", "",
             "Additional notice files",
             "-----------------------",
             "NOTICE, COPYRIGHT and AUTHORS files shipped by the crates above, reproduced verbatim.",
             ""]
    for key in sorted(roots):
        crate_dir = roots[key]
        for f in sorted(p for p in crate_dir.iterdir() if p.is_file() and NOTICE_RE.match(p.name)):
            parts += [
                "",
                "==============================================================================",
                f"{key[0]} {key[1]}: {f.name}",
                "==============================================================================",
                "",
                f.read_text(encoding="utf-8").rstrip("\n"),
            ]
    out_path.write_text("\n".join(parts) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
