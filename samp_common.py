"""Shared code for Substrate Ansible Mitigation Packs (SAMP).

One file, standard library only, vendored by copy into each pack's
<role>/files/ directory. A pack declares the sha256 of the copy it carries in
its samp.yaml, and the pack's own tests refuse a copy whose hash differs, so a
pack's diff shows only its own code and this file is reviewed once per
version.

What is here:
  * dpkg, rpm and apk version comparison, in pure Python, so one host can
    judge another distribution's container and the tests need no package
    manager;
  * the distribution key a pack's fixed-version table is keyed on, and the
    verdict for one installed package against that table;
  * the SAMP result line, the exit codes and the verdict ladder every pack
    reports with;
  * config loading: JSON on stdin (detection: nothing written to the target)
    or a YAML file (a hand run or an installed apply), with PyYAML imported
    only when a YAML file is actually read.

Why a pack does not import this from an installed location: a detection run
must write nothing outside its own temporary directory, so the library
travels with the script into that directory and leaves with it.
"""

import json
import logging
import re
import sys
from pathlib import Path

VERSION = "1.0.3"

# ------------------------------------------------------------ exit codes --
#
# One convention across every pack. 2 is a result, not a failure: the host
# was read and something on it needs action, or could not be decided.

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2
EXIT_INTERRUPTED = 130

# ---------------------------------------------------------------- verdicts --
#
# Worst first. "unknown" is never clean: a host whose state could not be
# decided is listed for action, not dropped.
#   vulnerable    affected, and a fix (or the pack's workaround) is available
#   no_fix        affected, and the vendor has published no fix
#   unknown       could not be decided
#   fixed         the affected component is at a fixed version, or the pack's
#                 workaround is in effect (the result line says which)
#   not_affected  the affected component is not on the host
# "failed" is not a host state: it means the pack itself could not finish,
# and it always exits EXIT_ERROR.

VERDICTS = ("vulnerable", "no_fix", "unknown", "fixed", "not_affected")
FAILED = "failed"
RESULT_FORMAT = 1
RESULT_PREFIX = "SAMP-RESULT "


def worst(statuses, default: str = "not_affected") -> str:
    """The worst verdict among statuses, by VERDICTS order."""
    statuses = set(statuses)
    if FAILED in statuses:
        return FAILED
    for verdict in VERDICTS:
        if verdict in statuses:
            return verdict
    return default


def exit_code(verdict: str) -> int:
    if verdict == FAILED:
        return EXIT_ERROR
    if verdict in ("vulnerable", "no_fix", "unknown"):
        return EXIT_FINDINGS
    if verdict in ("fixed", "not_affected"):
        return EXIT_CLEAN
    raise ValueError(f"not a SAMP verdict: {verdict!r}")


def result_line(pack: str, cves, mode: str, verdict: str, counters: dict,
                backups=(), workaround: bool = False) -> str:
    """The one machine-read line, printed last on stdout.

    Why JSON on one prefixed line: the substrate parses it strictly and treats
    anything that does not parse as a failed member, never as clean. The
    human key=value summary stays on the line before it, so a role's
    changed_when keeps working.
    """
    if verdict != FAILED and verdict not in VERDICTS:
        raise ValueError(f"not a SAMP verdict: {verdict!r}")
    if mode not in ("detect", "apply"):
        raise ValueError(f"not a SAMP mode: {mode!r}")
    body = {
        "format": RESULT_FORMAT,
        "pack": pack,
        "cves": list(cves),
        "mode": mode,
        "verdict": verdict,
        "workaround": bool(workaround),
        "counters": {str(k): int(v) for k, v in counters.items()},
        "backups": sorted({str(b) for b in backups}),
    }
    return RESULT_PREFIX + json.dumps(body, sort_keys=True, separators=(",", ":"))


def parse_result_line(line: str) -> dict:
    """Inverse of result_line, strict. Raises ValueError on anything else."""
    if not line.startswith(RESULT_PREFIX):
        raise ValueError("not a SAMP-RESULT line")
    body = json.loads(line[len(RESULT_PREFIX):])
    if not isinstance(body, dict) or body.get("format") != RESULT_FORMAT:
        raise ValueError("unsupported SAMP-RESULT format")
    if body.get("verdict") not in VERDICTS + (FAILED,):
        raise ValueError(f"not a SAMP verdict: {body.get('verdict')!r}")
    return body


def finish(pack: str, cves, apply: bool, verdict: str, counters: dict,
           backups=(), workaround: bool = False, stream=None,
           emit: bool = True) -> int:
    """Print the result line and return the exit code for verdict.

    emit=False returns the exit code without printing the line. A pre-apply
    detection run inside an apply step uses it: the substrate reads exactly
    one SAMP-RESULT line per step, and that step's line is the apply's.
    """
    if emit:
        stream = stream or sys.stdout
        print(result_line(pack, cves, "apply" if apply else "detect", verdict,
                          counters, backups, workaround), file=stream)
        stream.flush()
    return exit_code(verdict)


def run_main(main) -> None:
    """sys.exit(main()), with an interrupt reported as EXIT_INTERRUPTED."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)


# ------------------------------------------------------------------ config --

STDIN = "-"


def load_config(path, stdin=None) -> dict:
    """Read a pack's config.

    "-" reads JSON from stdin: that is how a detection run gets its config,
    so nothing is templated onto the target. A path ending .json is JSON. Any
    other path is YAML, and only then is PyYAML imported: a detection run
    never needs it installed.
    """
    path = str(path)
    try:
        if path == STDIN:
            text = (stdin or sys.stdin).read()
            data = json.loads(text) if text.strip() else {}
        elif path.endswith(".json"):
            data = json.loads(Path(path).read_text())
        else:
            try:
                import yaml
            except ImportError:
                sys.exit(f"config {path} is YAML and PyYAML is not installed; "
                         "install the distribution's python3-yaml, or pass the "
                         "config as JSON on stdin with --config -")
            with open(path, "r") as handle:
                data = yaml.safe_load(handle)
    except FileNotFoundError:
        sys.exit(f"config not found: {path}")
    except ValueError as exc:
        sys.exit(f"config is not valid JSON: {path}: {exc}")
    except Exception as exc:  # yaml.YAMLError, without importing yaml here
        if type(exc).__module__.startswith("yaml"):
            sys.exit(f"config is not valid YAML: {path}: {exc}")
        raise
    if data is None:
        return {}
    if not isinstance(data, dict):
        sys.exit(f"config is not a mapping: {path}")
    return data


def setup_logging(log_file) -> None:
    """Log to a file, or to stdout when log_file is "-" or empty.

    Why stdout and not a file during detection: a log file under /var/log is a
    write to the target, and detection writes nothing.
    """
    fmt = "%(asctime)s %(levelname)s %(message)s"
    if not log_file or str(log_file) == STDIN:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=fmt)
        return
    try:
        logging.basicConfig(filename=str(log_file), level=logging.INFO, format=fmt)
    except OSError as exc:
        sys.exit(f"cannot write log file {log_file}: {exc}")


# ------------------------------------------------------ version comparison --

def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def _dpkg_order(char: str) -> int:
    if char == "~":
        return -1
    if char == "" or char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _dpkg_compare_part(left: str, right: str) -> int:
    """dpkg's verrevcmp(): alternating non-digit and digit runs."""
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or \
                (j < len(right) and not right[j].isdigit()):
            a = _dpkg_order(left[i] if i < len(left) and not left[i].isdigit() else "")
            b = _dpkg_order(right[j] if j < len(right) and not right[j].isdigit() else "")
            if a != b:
                return _sign(a - b)
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        first_diff = 0
        while i < len(left) and left[i].isdigit() and \
                j < len(right) and right[j].isdigit():
            if not first_diff:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _dpkg_split(version: str) -> tuple:
    epoch, sep, rest = version.partition(":")
    if not sep:
        epoch, rest = "0", version
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return int(epoch or 0), upstream, revision


def dpkg_compare(left: str, right: str) -> int:
    """Compare two Debian package versions as dpkg --compare-versions does."""
    le, lu, lr = _dpkg_split(left.strip())
    re_, ru, rr = _dpkg_split(right.strip())
    if le != re_:
        return _sign(le - re_)
    return _dpkg_compare_part(lu, ru) or _dpkg_compare_part(lr, rr)


def _rpmvercmp(left: str, right: str) -> int:
    """rpm's rpmvercmp(), including tilde (sorts before) and caret (after)."""
    if left == right:
        return 0
    i = j = 0
    while i < len(left) or j < len(right):
        while i < len(left) and not left[i].isalnum() and left[i] not in "~^":
            i += 1
        while j < len(right) and not right[j].isalnum() and right[j] not in "~^":
            j += 1
        lt = left[i] if i < len(left) else ""
        rt = right[j] if j < len(right) else ""
        if lt == "~" or rt == "~":
            if lt != "~":
                return 1
            if rt != "~":
                return -1
            i += 1
            j += 1
            continue
        if lt == "^" or rt == "^":
            if not lt:
                return -1
            if not rt:
                return 1
            if lt != "^":
                return 1
            if rt != "^":
                return -1
            i += 1
            j += 1
            continue
        if not lt or not rt:
            break
        numeric = lt.isdigit()
        test = str.isdigit if numeric else str.isalpha
        i2, j2 = i, j
        while i2 < len(left) and test(left[i2]):
            i2 += 1
        while j2 < len(right) and test(right[j2]):
            j2 += 1
        a, b = left[i:i2], right[j:j2]
        if not b:
            return 1 if numeric else -1
        if numeric:
            a, b = a.lstrip("0"), b.lstrip("0")
            if len(a) != len(b):
                return 1 if len(a) > len(b) else -1
        if a != b:
            return 1 if a > b else -1
        i, j = i2, j2
    if i >= len(left) and j >= len(right):
        return 0
    return -1 if i >= len(left) else 1


def _rpm_split(evr: str) -> tuple:
    epoch, sep, rest = evr.partition(":")
    if not sep:
        epoch, rest = "0", evr
    version, sep, release = rest.rpartition("-")
    if not sep:
        version, release = rest, ""
    return int(epoch or 0), version, release


def rpm_compare(left: str, right: str) -> int:
    """Compare two [epoch:]version-release strings as rpm does."""
    le, lv, lr = _rpm_split(left.strip())
    re_, rv, rr = _rpm_split(right.strip())
    if le != re_:
        return _sign(le - re_)
    return _rpmvercmp(lv, rv) or _rpmvercmp(lr, rr)


APK_SUFFIX_ORDER = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
                    "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
APK_VERSION_RE = re.compile(
    r"^(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z]?)(?P<suffixes>(?:_[a-z]+\d*)*)"
    r"(?:~[0-9a-f]+)?(?:-r(?P<rev>\d+))?$"
)


def _apk_key(version: str) -> tuple:
    match = APK_VERSION_RE.match(version.strip())
    if not match:
        raise ValueError(f"not an apk version: {version!r}")
    nums = [int(n) for n in match.group("nums").split(".")]
    suffixes = []
    for name, number in re.findall(r"_([a-z]+)(\d*)", match.group("suffixes")):
        if name not in APK_SUFFIX_ORDER:
            raise ValueError(f"unknown apk suffix _{name} in {version!r}")
        suffixes.append((APK_SUFFIX_ORDER[name], int(number or 0)))
    return nums, match.group("letter"), suffixes, int(match.group("rev") or 0)


def apk_compare(left: str, right: str) -> int:
    """Compare two Alpine package versions (x.y.z[letter][_suffixN][-rN]).

    A version with no suffix sorts after _alpha/_beta/_pre/_rc and before _p,
    as in apk-tools.
    """
    ln, ll, ls, lr = _apk_key(left)
    rn, rl, rs, rr = _apk_key(right)
    if ln != rn:
        return -1 if ln < rn else 1
    if ll != rl:
        return -1 if ll < rl else 1
    width = max(len(ls), len(rs))
    ls = ls + [(0, 0)] * (width - len(ls))
    rs = rs + [(0, 0)] * (width - len(rs))
    if ls != rs:
        return -1 if ls < rs else 1
    return _sign(lr - rr)


COMPARATORS = {"deb": dpkg_compare, "rpm": rpm_compare, "apk": apk_compare}


def compare(fmt: str, left: str, right: str) -> int:
    """-1, 0 or 1 for two versions of package format fmt (deb, rpm, apk)."""
    try:
        comparator = COMPARATORS[fmt]
    except KeyError:
        raise ValueError(f"not a package format: {fmt!r}") from None
    return comparator(left, right)


# ------------------------------------------------- distributions, verdicts --

def os_release(path: Path = Path("/etc/os-release")) -> dict:
    values = {}
    try:
        for line in Path(path).read_text().splitlines():
            key, sep, value = line.strip().partition("=")
            if sep:
                values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def distro_key(release: dict, fmt: str) -> str:
    """Key into a fixed-version table: ubuntu:noble, debian:bookworm, rocky:9,
    alpine:3.24, alpine:edge.

    <os-release ID>:<VERSION_CODENAME> on dpkg systems, <ID>:<major
    VERSION_ID> on rpm systems, alpine:<major.minor> or alpine:edge on Alpine.
    A pack whose table needs more (a key carrying a branch, say the
    runtime's "/<branch>") appends it to this key itself;
    fixed_version_status takes any key.
    """
    distro = release.get("ID", "")
    version_id = release.get("VERSION_ID", "")
    if fmt == "deb":
        return f"{distro}:{release.get('VERSION_CODENAME', '')}"
    if fmt == "apk":
        # Why edge is special: its VERSION_ID looks like 3.25.0_alpha2026...,
        # which would otherwise be read as the unreleased 3.25 branch.
        if "_alpha" in version_id or not version_id:
            return f"{distro}:edge"
        return f"{distro}:{'.'.join(version_id.split('.')[:2])}"
    return f"{distro}:{version_id.split('.')[0]}"


def fixed_version_status(fmt: str, key: str, version: str,
                         fixed_versions: dict) -> tuple:
    """(status, reason) for one installed package against a fixed table.

    A key absent from the table is unknown: the vendor has published no
    verdict the pack knows of. A key present with no version (YAML null)
    means the vendor lists the release as affected with no fix released yet:
    no_fix. Otherwise the package format's own comparison decides, never the
    upstream version string, because distributions backport fixes.
    """
    if key not in fixed_versions:
        return "unknown", (f"{version} on {key}: no fixed version in the config; "
                           "check the distribution's tracker")
    fixed = fixed_versions[key]
    if not fixed:
        return "no_fix", f"{version} on {key}: affected, no fixed package published"
    try:
        result = compare(fmt, version, str(fixed))
    except ValueError as exc:
        return "unknown", f"{version} on {key}: cannot compare: {exc}"
    if result >= 0:
        return "fixed", f"{version} >= fixed {fixed} on {key}"
    return "vulnerable", f"{version} < fixed {fixed} on {key}"
