#!/usr/bin/env python3
"""Vendor samp_common.py and the pack contract test into a SAMP pack.

    python3 scripts/vendor.py ../CVE-2026-111497 [../CVE-2024-3094 ...]
    python3 scripts/vendor.py --check ../CVE-*

Copies samp_common.py to <role>/files/samp_common.py and
pack-tests/test_samp_pack.py to tests/test_samp_pack.py in each pack, then
writes the copy's sha256 and VERSION into the pack's samp.yaml
(spec.vendored.samp_common). With --check it changes nothing and exits 1 if
any pack's copy differs from this checkout.

Why a line edit and not a YAML round-trip: samp.yaml is reviewed by hand and
carries comments; a dump would drop them. The three lines it rewrites are
the ones under spec.vendored.samp_common, matched exactly.

Exit codes: 0 done (or every pack matches), 1 a pack differs or could not be
written, 2 bad arguments.
"""

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
LIBRARY = HERE / "samp_common.py"
CONTRACT = HERE / "pack-tests" / "test_samp_pack.py"
VERSION_RE = re.compile(r'^VERSION = "([^"]+)"$', re.M)
ROLE_RE = re.compile(r"^  role: (\S+)$", re.M)
VENDORED_RE = re.compile(
    r"(  vendored:\n    samp_common:\n      path: )(\S+)\n"
    r"      version: \S+\n      sha256: [0-9a-f]{64}\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vendor(pack: Path, check: bool) -> bool:
    manifest = pack / "samp.yaml"
    text = manifest.read_text()
    role = ROLE_RE.search(text)
    if not role:
        print(f"{pack}: samp.yaml has no spec.role", file=sys.stderr)
        return False
    library = pack / role.group(1) / "files" / "samp_common.py"
    contract = pack / "tests" / "test_samp_pack.py"
    version = VERSION_RE.search(LIBRARY.read_text()).group(1)
    digest = sha256(LIBRARY)
    block = (f"  vendored:\n    samp_common:\n      path: {role.group(1)}/files/samp_common.py\n"
             f"      version: {version}\n      sha256: {digest}\n")
    if check:
        same = (library.is_file() and sha256(library) == digest
                and contract.is_file() and sha256(contract) == sha256(CONTRACT)
                and block in text)
        print(f"{pack.name}: {'matches' if same else 'DIFFERS'} samp-common {version}")
        return same
    if not VENDORED_RE.search(text):
        print(f"{pack}: samp.yaml has no spec.vendored.samp_common block", file=sys.stderr)
        return False
    shutil.copyfile(LIBRARY, library)
    contract.parent.mkdir(exist_ok=True)
    shutil.copyfile(CONTRACT, contract)
    manifest.write_text(VENDORED_RE.sub(block, text, count=1))
    print(f"{pack.name}: vendored samp-common {version} sha256={digest}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("packs", nargs="+", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="change nothing; exit 1 if any pack differs")
    args = parser.parse_args()
    ok = True
    for pack in args.packs:
        if not (pack / "samp.yaml").is_file():
            print(f"{pack}: no samp.yaml", file=sys.stderr)
            ok = False
            continue
        ok = vendor(pack, args.check) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
