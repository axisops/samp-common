"""Unit tests for samp_common.py.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The comparison cases are the union of two packs' suites, where these
comparators were first written, plus the polkit, OpenSSH and xz versions
the older packs judge.

Agreement with the real tools: the dpkg cases are checked against
dpkg --compare-versions when dpkg is installed. With SAMP_REAL_TOOLS=docker
the rpm cases are also checked against rpm.labelCompare in a Rocky Linux
container and the apk cases against apk version -t in an Alpine container,
one container per tool for the whole case list. Images are SAMP_RPM_IMAGE
(default rockylinux:9) and SAMP_APK_IMAGE (default alpine:3.21); no network
is used, so the images must be present locally.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import samp_common as sc  # noqa: E402

REAL_TOOLS = os.environ.get("SAMP_REAL_TOOLS") == "docker" and shutil.which("docker")

DPKG_CASES = [
    # brotli
    ("1.0.9-2+b6", "1.0.9-2+deb12u1", -1),
    ("1.0.9-2+deb12u1", "1.0.9-2+deb12u1", 0),
    ("1.0.9-2+deb12u2", "1.0.9-2+deb12u1", 1),
    ("1.0.9-2", "1.0.9-2+deb12u1", -1),
    ("1.1.0-2+b7", "1.1.0-2+deb13u1", -1),
    ("1.1.0-2build2", "1.1.0-2ubuntu0.1", -1),
    ("1.0.9-2build6", "1.0.9-2ubuntu0.1", -1),
    ("1.1.0-2ubuntu0.2", "1.1.0-2ubuntu0.1", 1),
    ("1.2.0-4", "1.2.0-4.1", -1),
    ("1.2.0-4.1", "1.2.0-4", 1),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1:1.0-1", "2.0-1", 1),
    ("1.0", "1.0-0", 0),
    ("1.0a", "1.0+", -1),
    ("1.007", "1.7", 0),
    # php2shell
    ("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0),
    ("8.3.6-0ubuntu0.24.04.14", "8.3.6-0ubuntu0.24.04.13", 1),
    ("8.2.32-1~deb12u1", "8.2.35-1~deb12u1", -1),
    ("8.4.24-1~deb13u1", "8.4.27-1~deb13u1", -1),
    ("8.4.27-1~deb13u1", "8.4.27-1", -1),
    ("8.1.2-1ubuntu2.27", "8.1.2-1ubuntu2.28", -1),
    ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29+esm4", 1),
    ("2:8.3+93ubuntu2", "8.3.36-1", 1),
    # polkit (CVE-2021-4034), OpenSSH (CVE-2024-6387), xz (CVE-2024-3094)
    ("0.105-26ubuntu1.1", "0.105-26ubuntu1.2", -1),
    ("0.105-31+deb11u1", "0.105-31+deb11u1", 0),
    ("0.105-14.1ubuntu0.5+esm1", "0.105-14.1ubuntu0.5", 1),
    ("1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.20", -1),
    ("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", -1),
    ("9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.3", -1),
    ("5.6.1+really5.4.5-1", "5.6.1-1", 1),
]

RPM_CASES = [
    # brotli
    ("1.0.9-7.el9_5", "1.0.9-9.el9_7", -1),
    ("1.1.0-7.el10_1", "1.1.0-7.el10_1", 0),
    ("1.0.6-3.el8", "1.0.6-3.el8_10.1", -1),
    ("1:1.0.6-3.el8", "1.2.1-1.el8", 1),
    ("0:1.0.9-7.el9", "1.0.9-7.el9", 0),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1.0^git1-1", "1.0-1", 1),
    ("1.0a-1", "1.0.1-1", -1),
    ("1.10-1", "1.9-1", 1),
    # php2shell
    ("8.2.13-1.module+el9.5.0+90000+a1b2c3d4",
     "8.2.33-1.module_el9.8.0+327+37dfd4b4.alma.1", -1),
    ("8.3.33-1.el10_2.alma.1", "8.3.33-1.el10_2", 1),
    ("8.0.30-7.el9_8", "8.0.30-8.el9_8.alma.1", -1),
    ("7.4.33-7.module_el8.10.0+4321+cf5fd4bb",
     "7.4.33-8.module_el8.10.0+4321+cf5fd4bb", -1),
    ("1:8.2.33-1.el9", "8.3.33-1.el9", 1),
    # polkit, OpenSSH
    ("0.115-13.el8_5", "0.115-13.el8_5.1", -1),
    ("0.112-26.el7_9.1", "0.112-26.el7_9.1", 0),
    ("0.117-10.el9", "0.115-13.el8_5.1", 1),
    ("8.7p1-38.el9_4", "8.7p1-38.el9_4.1", -1),
    ("8.7p1-38.el9_4.4", "8.7p1-38.el9_4.1", 1),
    ("8.7p1-38.el9", "8.7p1-38.el9_4.1", -1),
]

APK_CASES = [
    # brotli
    ("1.2.0-r1", "1.2.1-r0", -1),
    ("1.2.1-r0", "1.2.1-r0", 0),
    ("1.1.0-r2", "1.1.1-r0", -1),
    ("1.0.9-r14", "1.1.1-r0", -1),
    ("1.2.1-r1", "1.2.1-r0", 1),
    ("1.2.1_rc1-r0", "1.2.1-r0", -1),
    ("1.2.1_p1-r0", "1.2.1-r0", 1),
    ("1.2.1a-r0", "1.2.1-r0", 1),
    ("1.2-r0", "1.2.0-r0", -1),
    # php2shell
    ("8.2.34-r0", "8.2.35-r0", -1),
    ("8.3.6-r0", "8.3.36-r0", -1),
    ("8.5.12-r0", "8.5.9-r0", 1),
    ("8.5.12_rc1-r0", "8.5.12-r0", -1),
    ("8.5.12_p1-r0", "8.5.12-r0", 1),
]


class Comparators(unittest.TestCase):
    def check(self, comparator, cases):
        for left, right, expected in cases:
            with self.subTest(left=left, right=right):
                self.assertEqual(comparator(left, right), expected)
                self.assertEqual(comparator(right, left), -expected)

    def test_dpkg(self):
        self.check(sc.dpkg_compare, DPKG_CASES)

    def test_rpm(self):
        self.check(sc.rpm_compare, RPM_CASES)

    def test_apk(self):
        self.check(sc.apk_compare, APK_CASES)

    def test_apk_rejects_garbage(self):
        with self.assertRaises(ValueError):
            sc.apk_compare("not-a-version", "1.2.1-r0")
        with self.assertRaises(ValueError):
            sc.apk_compare("1.2.1_bogus1-r0", "1.2.1-r0")

    def test_compare_dispatches_and_refuses_unknown_formats(self):
        self.assertEqual(sc.compare("deb", "1.0-1", "1.0-2"), -1)
        self.assertEqual(sc.compare("rpm", "1.0-2", "1.0-1"), 1)
        self.assertEqual(sc.compare("apk", "1.0-r0", "1.0-r0"), 0)
        with self.assertRaises(ValueError):
            sc.compare("pacman", "1", "2")

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg not installed")
    def test_dpkg_agrees_with_dpkg(self):
        for left, right, expected in DPKG_CASES:
            op = {-1: "lt", 0: "eq", 1: "gt"}[expected]
            rc = subprocess.run(["dpkg", "--compare-versions", left, op, right]).returncode
            with self.subTest(left=left, right=right):
                self.assertEqual(rc, 0, f"dpkg disagrees: {left} {op} {right}")

    def _in_container(self, image, script, cases):
        lines = "".join(f"{l} {r}\n" for l, r, _ in cases)
        result = subprocess.run(
            ["docker", "run", "--rm", "-i", "--network", "none", image, "sh", "-c", script],
            input=lines, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        answers = result.stdout.split()
        # Why: zip() over an empty answer list would pass every case unread.
        self.assertEqual(len(answers), len(cases), result.stdout + result.stderr)
        return answers

    @unittest.skipUnless(REAL_TOOLS, "SAMP_REAL_TOOLS=docker not set")
    def test_rpm_agrees_with_rpm(self):
        script = ("python3 -c 'import rpm,sys\n"
                  "def evr(s):\n"
                  "    e,_,r=s.partition(\":\") if \":\" in s else (\"0\",\"\",s)\n"
                  "    v,_,rel=r.rpartition(\"-\")\n"
                  "    return (e,v,rel)\n"
                  "for line in sys.stdin:\n"
                  "    l,r=line.split()\n"
                  "    print(rpm.labelCompare(evr(l),evr(r)))'")
        got = self._in_container(os.environ.get("SAMP_RPM_IMAGE", "rockylinux:9"),
                                 script, RPM_CASES)
        for (left, right, expected), answer in zip(RPM_CASES, got):
            with self.subTest(left=left, right=right):
                self.assertEqual(int(answer), expected, f"rpm disagrees: {left} {right}")

    @unittest.skipUnless(REAL_TOOLS, "SAMP_REAL_TOOLS=docker not set")
    def test_apk_agrees_with_apk(self):
        script = 'while read l r; do apk version -t "$l" "$r"; done'
        got = self._in_container(os.environ.get("SAMP_APK_IMAGE", "alpine:3.21"),
                                 script, APK_CASES)
        for (left, right, expected), answer in zip(APK_CASES, got):
            with self.subTest(left=left, right=right):
                self.assertEqual({"<": -1, "=": 0, ">": 1}[answer], expected,
                                 f"apk disagrees: {left} {right}")


class DistroKey(unittest.TestCase):
    def test_keys(self):
        cases = [
            ({"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"}, "deb", "ubuntu:noble"),
            ({"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"}, "deb", "debian:bookworm"),
            ({"ID": "rocky", "VERSION_ID": "9.6"}, "rpm", "rocky:9"),
            ({"ID": "rhel", "VERSION_ID": "10.0"}, "rpm", "rhel:10"),
            ({"ID": "alpine", "VERSION_ID": "3.24.3"}, "apk", "alpine:3.24"),
            ({"ID": "alpine", "VERSION_ID": "3.25.0_alpha20261001"}, "apk", "alpine:edge"),
        ]
        for release, fmt, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(sc.distro_key(release, fmt), expected)

    def test_os_release_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text('ID=ubuntu\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\n')
            self.assertEqual(sc.distro_key(sc.os_release(path), "deb"), "ubuntu:noble")

    def test_missing_os_release_is_empty(self):
        self.assertEqual(sc.os_release(Path("/nonexistent/os-release")), {})


class FixedVersionStatus(unittest.TestCase):
    TABLE = {
        "ubuntu:noble": "1.1.0-2ubuntu0.1",
        "rhel:9": None,
        # A branch-carrying key shape: <distro key>/<branch>.
        "ubuntu:noble/8.3": "8.3.6-0ubuntu0.24.04.13",
        "alpine:3.24/8.4": "8.4.27-r0",
    }

    def status(self, fmt, key, version):
        return sc.fixed_version_status(fmt, key, version, self.TABLE)[0]

    def test_verdicts(self):
        self.assertEqual(self.status("deb", "ubuntu:noble", "1.1.0-2build2"), "vulnerable")
        self.assertEqual(self.status("deb", "ubuntu:noble", "1.1.0-2ubuntu0.1"), "fixed")
        self.assertEqual(self.status("rpm", "rhel:9", "1.0.9-9.el9_7"), "no_fix")
        self.assertEqual(self.status("deb", "ubuntu:focal", "1.0.7-6"), "unknown")

    def test_branch_suffixed_keys(self):
        self.assertEqual(self.status("deb", "ubuntu:noble/8.3", "8.3.6-0ubuntu0.24.04.12"),
                         "vulnerable")
        self.assertEqual(self.status("deb", "ubuntu:noble/8.3", "8.3.6-0ubuntu0.24.04.13"),
                         "fixed")
        self.assertEqual(self.status("apk", "alpine:3.24/8.4", "8.4.24-r0"), "vulnerable")
        # A branch the table does not list is unknown, never borrowed from a
        # neighbour.
        self.assertEqual(self.status("deb", "ubuntu:noble/8.4", "8.4.27-1"), "unknown")

    def test_uncomparable_version_is_unknown(self):
        status, reason = sc.fixed_version_status("apk", "alpine:3.24/8.4", "garbage",
                                                 self.TABLE)
        self.assertEqual(status, "unknown")
        self.assertIn("cannot compare", reason)

    def test_reason_names_the_key(self):
        _, reason = sc.fixed_version_status("deb", "ubuntu:noble/8.3",
                                            "8.3.6-0ubuntu0.24.04.12", self.TABLE)
        self.assertEqual(reason, "8.3.6-0ubuntu0.24.04.12 < fixed "
                                 "8.3.6-0ubuntu0.24.04.13 on ubuntu:noble/8.3")


class Verdicts(unittest.TestCase):
    def test_worst(self):
        self.assertEqual(sc.worst(["fixed", "vulnerable", "unknown"]), "vulnerable")
        self.assertEqual(sc.worst(["fixed", "no_fix", "unknown"]), "no_fix")
        self.assertEqual(sc.worst(["fixed", "unknown"]), "unknown")
        self.assertEqual(sc.worst(["fixed", "not_affected"]), "fixed")
        self.assertEqual(sc.worst([]), "not_affected")
        self.assertEqual(sc.worst(["vulnerable", "failed"]), "failed")

    def test_exit_codes(self):
        self.assertEqual(sc.exit_code("fixed"), 0)
        self.assertEqual(sc.exit_code("not_affected"), 0)
        for verdict in ("vulnerable", "no_fix", "unknown"):
            with self.subTest(verdict=verdict):
                # unknown is never clean.
                self.assertEqual(sc.exit_code(verdict), 2)
        self.assertEqual(sc.exit_code("failed"), 1)
        with self.assertRaises(ValueError):
            sc.exit_code("patched")

    def test_constants(self):
        self.assertEqual((sc.EXIT_CLEAN, sc.EXIT_ERROR, sc.EXIT_FINDINGS,
                          sc.EXIT_INTERRUPTED), (0, 1, 2, 130))


class ResultLine(unittest.TestCase):
    def test_round_trip(self):
        line = sc.result_line("brotli-decoder", ["CVE-2026-111497"], "detect",
                              "vulnerable", {"host_vulnerable": 1, "upgraded": 0},
                              backups=["/b/2", "/b/1", "/b/1"])
        self.assertTrue(line.startswith("SAMP-RESULT {"))
        self.assertNotIn("\n", line)
        body = sc.parse_result_line(line)
        self.assertEqual(body["format"], 1)
        self.assertEqual(body["verdict"], "vulnerable")
        self.assertEqual(body["mode"], "detect")
        self.assertEqual(body["counters"], {"host_vulnerable": 1, "upgraded": 0})
        self.assertEqual(body["backups"], ["/b/1", "/b/2"])
        self.assertIs(body["workaround"], False)

    def test_refuses_unknown_verdicts_and_modes(self):
        with self.assertRaises(ValueError):
            sc.result_line("p", [], "detect", "patched", {})
        with self.assertRaises(ValueError):
            sc.result_line("p", [], "restore", "fixed", {})

    def test_parse_is_strict(self):
        for bad in ("scanned=1", "SAMP-RESULT {", 'SAMP-RESULT {"format":2,"verdict":"fixed"}',
                    'SAMP-RESULT {"format":1,"verdict":"clean"}', "SAMP-RESULT []"):
            with self.subTest(line=bad):
                with self.assertRaises(ValueError):
                    sc.parse_result_line(bad)

    def test_finish_prints_and_returns_the_exit_code(self):
        out = io.StringIO()
        rc = sc.finish("p", ["CVE-1"], True, "fixed", {"n": 1}, workaround=True, stream=out)
        self.assertEqual(rc, 0)
        body = sc.parse_result_line(out.getvalue().strip())
        self.assertEqual((body["mode"], body["workaround"]), ("apply", True))


class Config(unittest.TestCase):
    def test_stdin_json(self):
        self.assertEqual(sc.load_config("-", io.StringIO('{"a": [1, null]}')),
                         {"a": [1, None]})
        self.assertEqual(sc.load_config("-", io.StringIO("")), {})

    def test_json_file_and_yaml_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            j = Path(tmp) / "c.json"
            j.write_text('{"log_file": "-"}')
            self.assertEqual(sc.load_config(j), {"log_file": "-"})
            try:
                import yaml  # noqa: F401
            except ImportError:
                self.skipTest("PyYAML not installed")
            y = Path(tmp) / "c.yaml"
            y.write_text('fixed_versions:\n  "rhel:9": null\n')
            self.assertEqual(sc.load_config(y), {"fixed_versions": {"rhel:9": None}})

    def test_bad_input_exits_with_a_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (("bad.json", "{"), ("list.json", "[1]")):
                path = Path(tmp) / name
                path.write_text(text)
                with self.subTest(name=name), self.assertRaises(SystemExit) as raised:
                    sc.load_config(path)
                self.assertIsInstance(raised.exception.code, str)
            with self.assertRaises(SystemExit):
                sc.load_config(Path(tmp) / "missing.json")

    def test_stdin_import_does_not_need_yaml(self):
        # A detection run reads JSON on stdin on a host with no PyYAML.
        code = ("import sys; sys.modules['yaml'] = None; sys.path.insert(0, %r);"
                "import samp_common as sc, io;"
                "print(sc.load_config('-', io.StringIO('{\"x\": 1}')))" % str(ROOT))
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "{'x': 1}")


class Stdlib(unittest.TestCase):
    def test_imports_only_the_standard_library(self):
        import ast
        tree = ast.parse((ROOT / "samp_common.py").read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module.split(".")[0])
        # yaml is imported lazily, inside load_config, for YAML files only.
        self.assertEqual(names - {"json", "logging", "re", "sys", "pathlib"}, {"yaml"})


if __name__ == "__main__":
    unittest.main()
