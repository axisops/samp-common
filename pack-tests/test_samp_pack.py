"""The SAMP pack contract, checked against this repository.

This file is the same in every pack; samp-common keeps the master copy in
pack-tests/. It reads samp.yaml and checks the role against it:

  * the manifest has the fields the substrate reads;
  * the vendored samp_common.py is byte-for-byte the version the manifest
    names (by sha256);
  * nothing installs from PyPI;
  * the detection entry uses only the tasks a write-nothing detection needs,
    runs under --check, passes the config on stdin and never applies;
  * every restart or reload option defaults off, in the manifest and in the
    role;
  * a detection run of the script, with tests/samp_smoke_config.json on
    stdin, as the current user, writes nothing to its working directory and
    ends with a SAMP-RESULT line in detect mode.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = yaml.safe_load((ROOT / "samp.yaml").read_text())
SPEC = MANIFEST["spec"]
ROLE = ROOT / SPEC["role"]
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text()) or {}
VENDORED = SPEC["vendored"]["samp_common"]

sys.path.insert(0, str(ROLE / "files"))
import samp_common  # noqa: E402

# Modules a detection entry may use. tempfile, copy and file exist only to
# stage the script and the library in a private temporary directory and to
# remove it again.
DETECT_MODULES = {"ansible.builtin.tempfile", "ansible.builtin.copy",
                  "ansible.builtin.command", "ansible.builtin.debug",
                  "ansible.builtin.file"}
TASK_KEYWORDS = {"name", "register", "when", "check_mode", "changed_when",
                 "failed_when", "loop", "vars", "environment", "block",
                 "always", "rescue", "become", "no_log"}


def tasks(path: Path) -> list:
    return yaml.safe_load(path.read_text()) or []


def flatten(task_list):
    for task in task_list:
        yield task
        for key in ("block", "always", "rescue"):
            yield from flatten(task.get(key) or [])


def module_of(task: dict) -> str:
    names = [k for k in task if k not in TASK_KEYWORDS]
    return names[0] if names else ""


class Manifest(unittest.TestCase):
    def test_header(self):
        self.assertEqual(MANIFEST["apiVersion"], "samp.substrate.microcelium/v1")
        self.assertEqual(MANIFEST["kind"], "MitigationPack")
        self.assertRegex(MANIFEST["metadata"]["name"], r"^[a-z0-9][a-z0-9-]*$")
        self.assertRegex(str(MANIFEST["metadata"]["version"]), r"^\d+\.\d+\.\d+$")

    def test_fields(self):
        self.assertTrue(SPEC["cves"])
        for cve in SPEC["cves"]:
            self.assertRegex(cve, r"^CVE-\d{4}-\d{4,}$")
        self.assertTrue((ROLE / "tasks").is_dir())
        self.assertTrue(SPEC["applies_to"]["os_families"])
        for entry in ("detect", "apply"):
            self.assertTrue((ROLE / "tasks" / SPEC[entry]["tasks_from"]).is_file(), entry)
            self.assertIsInstance(SPEC[entry]["needs_root"], bool)
        self.assertNotEqual(SPEC["detect"]["tasks_from"], SPEC["apply"]["tasks_from"])
        self.assertEqual(SPEC["result"], "samp-result/v1")
        for key in ("touches", "commands", "restarts"):
            self.assertIsInstance(SPEC[key], list, key)
        for path in SPEC["touches"]:
            self.assertTrue(path.startswith("/"), path)

    def test_options_name_real_variables_with_matching_defaults(self):
        for name, option in (SPEC.get("options") or {}).items():
            with self.subTest(option=name):
                self.assertIn(option["var"], DEFAULTS)
                self.assertEqual(option["type"], "bool")
                self.assertEqual(DEFAULTS[option["var"]], option["default"])

    def test_restarts_default_off(self):
        # A restart is an outage the operator schedules, never a default.
        for name, option in (SPEC.get("options") or {}).items():
            if "restart" in name or "reload" in name:
                with self.subTest(option=name):
                    self.assertIs(option["default"], False)
        for var, value in DEFAULTS.items():
            if ("restart" in var or "reload" in var) and isinstance(value, bool):
                with self.subTest(var=var):
                    self.assertIs(value, False)

    def test_no_restore_or_revert_mode_is_offered(self):
        # A revert reinstates the vulnerability; SAMP never offers one.
        for name in (SPEC.get("options") or {}):
            self.assertNotIn("restore", name)
            self.assertNotIn("revert", name)
        for var, value in (SPEC["apply"].get("vars") or {}).items():
            if "restore" in var:
                self.assertIs(value, False)


class Vendored(unittest.TestCase):
    def test_samp_common_matches_the_manifest(self):
        path = ROOT / VENDORED["path"]
        self.assertEqual(path.parent, ROLE / "files")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest, VENDORED["sha256"],
                         "samp_common.py differs from the version samp.yaml names; "
                         "re-vendor it from samp-common, never edit it here")
        self.assertEqual(samp_common.VERSION, str(VENDORED["version"]))


class Role(unittest.TestCase):
    def test_nothing_installs_from_pypi(self):
        for path in sorted((ROLE / "tasks").glob("*.yml")):
            with self.subTest(file=path.name):
                for task in flatten(tasks(path)):
                    self.assertNotIn(module_of(task).split(".")[-1], {"pip", "easy_install"})

    def test_pyyaml_comes_from_the_distribution(self):
        main = (ROLE / "tasks" / SPEC["apply"]["tasks_from"]).read_text()
        if "yaml" in main.lower() and "PyYAML" in main:
            self.assertIn("python3-yaml", main)
            self.assertIn("py3-yaml", main)
            self.assertIn("python3-pyyaml", main)


class DetectEntry(unittest.TestCase):
    TASKS = list(flatten(tasks(ROLE / "tasks" / SPEC["detect"]["tasks_from"])))

    def test_only_write_nothing_modules(self):
        for task in self.TASKS:
            module = module_of(task)
            if not module:
                continue
            with self.subTest(task=task.get("name")):
                self.assertIn(module, DETECT_MODULES)

    def test_every_task_runs_under_check_and_never_reports_changed(self):
        for task in self.TASKS:
            module = module_of(task)
            if not module or module == "ansible.builtin.debug":
                continue
            with self.subTest(task=task.get("name")):
                self.assertIs(task.get("check_mode"), False)
                self.assertIs(task.get("changed_when"), False)

    def test_writes_only_inside_the_temporary_directory(self):
        tmp_vars = [t["register"] for t in self.TASKS
                    if module_of(t) == "ansible.builtin.tempfile"]
        self.assertEqual(len(tmp_vars), 1)
        for task in self.TASKS:
            module = module_of(task)
            if module == "ansible.builtin.copy":
                self.assertIn(f"{tmp_vars[0]}.path", task[module]["dest"])
            if module == "ansible.builtin.file":
                self.assertEqual(task[module]["state"], "absent")
                self.assertIn(f"{tmp_vars[0]}.path", task[module]["path"])

    def test_removal_is_in_always(self):
        top = tasks(ROLE / "tasks" / SPEC["detect"]["tasks_from"])
        always = [t for block in top for t in (block.get("always") or [])]
        self.assertTrue(any(module_of(t) == "ansible.builtin.file" for t in always))

    def test_config_on_stdin_and_never_apply(self):
        commands = [t for t in self.TASKS if module_of(t) == "ansible.builtin.command"]
        self.assertTrue(commands)
        for task in commands:
            body = task["ansible.builtin.command"]
            argv = str(body["argv"])
            self.assertIn("'--config', '-'", argv)
            self.assertIn("stdin", body)
            self.assertNotIn("--apply", argv)
            self.assertNotIn("--restart", argv)
            self.assertNotIn("--restore", argv)
            self.assertIn("rc not in [0, 2]", str(task["failed_when"]))

    def test_no_bytecode_written_by_any_task(self):
        # Ansible's modules are Python too; set for the whole detection.
        top = tasks(ROLE / "tasks" / SPEC["detect"]["tasks_from"])
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["environment"]["PYTHONDONTWRITEBYTECODE"], "1")


class DetectionRun(unittest.TestCase):
    """The script itself, run the way detect.yml runs it."""

    def test_detection_writes_nothing_and_reports(self):
        config = json.loads((ROOT / "tests" / "samp_smoke_config.json").read_text())
        scripts = [p for p in (ROLE / "files").glob("*_mitigator.py")]
        self.assertEqual(len(scripts), 1)
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                [sys.executable, str(scripts[0]), "--config", "-"],
                input=json.dumps(config), capture_output=True, text=True,
                cwd=tmp, env=env, timeout=120)
            self.assertEqual(os.listdir(tmp), [])
        self.assertIn(result.returncode, (0, 2), result.stderr)
        last = result.stdout.strip().splitlines()[-1]
        body = samp_common.parse_result_line(last)
        self.assertEqual(body["mode"], "detect")
        self.assertEqual(body["pack"], MANIFEST["metadata"]["name"])
        self.assertEqual(body["cves"], SPEC["cves"])
        self.assertEqual(body["backups"], [])
        self.assertEqual(samp_common.exit_code(body["verdict"]), result.returncode)


if __name__ == "__main__":
    unittest.main()
