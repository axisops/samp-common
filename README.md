# samp-common

Shared code for the Substrate Ansible Mitigation Packs (SAMP): the
remediation modules under `github.com/axisops/CVE-*`, each a Python
detect/back-up/mitigate/verify script wrapped in an Ansible role, that the
[Microcelium Substrate](https://www.micro-substrate.com) imports, pins,
verifies, scans and runs under review.

Before this library each pack carried its own copy of the dpkg, rpm and apk
version comparisons, and the copies had drifted: several reimplemented the
same algorithms, some incompletely, and some shelled out to
`dpkg --compare-versions`. Now there is one copy, reviewed once per version.

## What is in it

`samp_common.py`, one file, standard library only:

* `dpkg_compare`, `rpm_compare`, `apk_compare` (and `compare(fmt, a, b)`):
  pure-Python versions of each package manager's ordering, so one host can
  judge another distribution's container and nothing needs the tools
  installed;
* `os_release`, `distro_key`: the `<ID>:<codename>`, `<ID>:<major>`,
  `alpine:<major.minor>` keys the packs' fixed-version tables use;
* `fixed_version_status(fmt, key, version, table)`: `vulnerable`, `fixed`,
  `no_fix` (key present, value null) or `unknown` (key absent). Any key
  works, so a pack that needs more than the distribution key (a key carrying
  a branch, say `debian:trixie/8.4`) builds its own and passes it in;
* the SAMP result: `VERDICTS`, `worst`, `exit_code`, `result_line`,
  `parse_result_line`, `finish`, `run_main`. One line,
  `SAMP-RESULT {"format":1,…}`, printed last on stdout; exit codes `0` clean,
  `2` vulnerable or undecided, `1` the run failed, `130` interrupted;
* `load_config`: JSON on stdin (`--config -`, how a detection run gets its
  config, so nothing is written to the target), a `.json` file, or a YAML
  file, with PyYAML imported only for YAML;
* `setup_logging`: a log file, or stdout when the log file is `-`.

`pack-tests/test_samp_pack.py` is the pack contract test, the same file in
every pack: the manifest's fields, the vendored copy's sha256, no `pip`, a
detection entry that writes nothing outside a temporary directory it removes,
restarts off by default, no revert mode, and a detection run that writes
nothing and ends in a parseable result line.

## How packs use it: vendored by copy, checked by sha

A pack does not import this from an installed location. Each pack carries a
byte-for-byte copy at `<role>/files/samp_common.py`, travelling with its
script into the detection run's temporary directory, and names the copy in
its `samp.yaml`:

```yaml
  vendored:
    samp_common:
      path: <role_name>/files/samp_common.py
      version: 1.0.4
      sha256: d41ad387df1e89c7c36614bb0b91bf25b3f544aeb3667bcd6de7a8c3c0313cab
```

The pack's tests fail if the copy's hash differs, and the substrate's linter
refuses a vendored copy whose hash is not an approved samp-common release. So
a pack's diff shows only its own code. Never edit the copy in a pack; change
it here, release, and re-vendor:

```bash
python3 scripts/vendor.py ../CVE-YYYY-NNNNN               # copy + update samp.yaml
python3 scripts/vendor.py --check ../CVE-*                # exit 1 if any pack differs
```

## Releases

| Version | Tag | `samp_common.py` sha256 |
|---|---|---|
| 1.0.4 | `samp/v1.0.4` | `d41ad387df1e89c7c36614bb0b91bf25b3f544aeb3667bcd6de7a8c3c0313cab` |
| 1.0.3 | `samp/v1.0.3` | `d3616cfd45da9c8d17c55b2e6d7ecafbd386023cffebde668249b4e1f38fa3cf` |
| 1.0.2 | `samp/v1.0.2` | `cdac76588f328979fd7aad73a45ac23a9d45d9bebfd38c4d4b1c40d5aa97ea8c` |
| 1.0.1 | `samp/v1.0.1` | `63089827aff2ee8af02d069c4876b38982b114d5113bf01af93442f2f4069edb` |
| 1.0.0 | `samp/v1.0.0` | `86355590e91434cc41162caa50ed26283c6d5bb375c0a57239dcbe9e18503474` |

Releases are SSH-signed annotated tags `samp/v<version>`, signed with a
hardware-backed key, the same scheme as the packs. The substrate imports a
signed tag, never a branch.

## Tests

```bash
python3 -m unittest discover -s tests -v
SAMP_REAL_TOOLS=docker python3 -m unittest discover -s tests -v
```

The comparison cases are the union of the packs' own suites, covering the
distribution version formats they judge. The dpkg cases
are checked against `dpkg --compare-versions` when dpkg is installed. With
`SAMP_REAL_TOOLS=docker` the rpm cases are checked against `rpm.labelCompare`
in a `rockylinux:9` container and the apk cases against `apk version -t` in an
`alpine:3.21` container (`--network none`; the images must be local).

## License

MIT. See [LICENSE](LICENSE).

---

**SysOps Team @ AxisOps**
