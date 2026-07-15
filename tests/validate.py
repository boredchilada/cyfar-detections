"""Suricata rule validator: syntax check + pcap-based fire testing.

Reads YAML fixture files from ./fixtures/, runs each rule through:
  Level 1 — suricata -T (syntax check)
  Level 2 — craft a pcap per test case, replay with suricata -r,
            check eve.json for expected alert/no-alert.

Designed to run inside the Docker container (jasonish/suricata:7.0 base).
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

from craft_pcap import craft_pcap

# Minimal suricata.yaml that enables the HTTP app-layer parser.
# Without this, content matches against http_method / http_uri /
# http_client_body will never fire.
SURICATA_YAML = """\
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80, 2375, 2376, 3100, 8000, 8080, 8443, 8888]"

app-layer:
  protocols:
    http:
      enabled: yes
      ports: [80, 2375, 2376, 3100, 8000, 8080, 8443, 8888]

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert

logging:
  default-log-level: error
  outputs:
    - console:
        enabled: yes
"""


def write_suricata_yaml(directory):
    """Write a minimal suricata.yaml into `directory` and return its path."""
    path = os.path.join(directory, "suricata.yaml")
    with open(path, "w") as f:
        f.write(SURICATA_YAML)
    return path


def write_rule_file(directory, rule_text):
    """Write the rule to a .rules file and return its path."""
    path = os.path.join(directory, "test.rules")
    with open(path, "w") as f:
        f.write(rule_text.strip() + "\n")
    return path


def syntax_check(rule_path, yaml_path):
    """Level 1: run suricata -T to validate rule syntax.

    Returns (ok: bool, stderr: str).
    """
    result = subprocess.run(
        [
            "suricata", "-T",
            "-S", rule_path,
            "-c", yaml_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0, result.stderr


def fire_test(rule_path, yaml_path, pcap_path, log_dir, expected_sids):
    """Level 2: replay a pcap and check eve.json for expected SIDs.

    `expected_sids` is a list of ints. If empty, the test expects NO
    alerts (negative test case).

    Returns (ok: bool, detail: str).
    """
    eve_path = os.path.join(log_dir, "eve.json")
    # Clean any stale eve.json from a prior run in this dir.
    if os.path.exists(eve_path):
        os.remove(eve_path)

    result = subprocess.run(
        [
            "suricata",
            "-r", pcap_path,
            "-S", rule_path,
            "-c", yaml_path,
            "-l", log_dir,
            "--set", "outputs.0.eve-log.filename=eve.json",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        return False, f"suricata -r exited {result.returncode}: {result.stderr}"

    # Parse eve.json for alert events.
    fired_sids = set()
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    sid = event.get("alert", {}).get("signature_id")
                    if sid is not None:
                        fired_sids.add(int(sid))

    if expected_sids:
        missing = set(expected_sids) - fired_sids
        extra = fired_sids - set(expected_sids)
        if missing:
            return False, f"expected SIDs {sorted(missing)} did not fire; got {sorted(fired_sids)}"
        if extra:
            return False, f"unexpected SIDs {sorted(extra)} fired"
        return True, f"SIDs {sorted(fired_sids)} fired as expected"
    else:
        # Negative test: no alerts expected.
        if fired_sids:
            return False, f"expected no alerts but got SIDs {sorted(fired_sids)}"
        return True, "no alerts (correct for negative test)"


def run_fixture(fixture_path, output_base):
    """Run all checks for a single YAML fixture. Returns (pass_count, fail_count)."""
    with open(fixture_path) as f:
        fixture = yaml.safe_load(f)

    name = fixture.get("name", os.path.basename(fixture_path))
    rule = fixture["rule"]
    tests = fixture.get("tests", [])

    print(f"\n{'='*60}")
    print(f"Fixture: {name}")
    print(f"{'='*60}")

    passes = 0
    fails = 0

    # --- Level 1: syntax check ---
    work_dir = tempfile.mkdtemp(prefix="sv_")
    try:
        yaml_path = write_suricata_yaml(work_dir)
        rule_path = write_rule_file(work_dir, rule)

        ok, stderr = syntax_check(rule_path, yaml_path)
        if ok:
            print(f"  [PASS] Level 1: syntax check")
            passes += 1
        else:
            print(f"  [FAIL] Level 1: syntax check")
            for line in stderr.strip().splitlines():
                print(f"         {line}")
            fails += 1
            # If syntax fails, skip fire tests (they'll all fail).
            return passes, fails

        # --- Level 2: fire tests ---
        if not tests:
            print(f"  [SKIP] Level 2: no test cases defined")
            return passes, fails

        for i, tc in enumerate(tests):
            tc_name = tc.get("name", f"test_{i}")
            request_spec = tc["request"]
            expected_sids = tc.get("expected_sids", [])

            # Each test case gets its own subdirectory.
            tc_dir = os.path.join(work_dir, f"tc_{i}")
            os.makedirs(tc_dir, exist_ok=True)

            pcap_path = os.path.join(tc_dir, "traffic.pcap")
            craft_pcap(request_spec, pcap_path, client_port=49152 + i)

            ok, detail = fire_test(rule_path, yaml_path, pcap_path, tc_dir, expected_sids)
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] Level 2: {tc_name} -- {detail}")
            if ok:
                passes += 1
            else:
                fails += 1

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return passes, fails


def main():
    fixture_dir = os.environ.get("FIXTURE_DIR", "/validator/fixtures")
    output_dir = os.environ.get("OUTPUT_DIR", "/validator/output")
    os.makedirs(output_dir, exist_ok=True)

    patterns = sys.argv[1:] if len(sys.argv) > 1 else ["*.yaml", "*.yml"]
    fixture_files = []
    for pat in patterns:
        fixture_files.extend(glob.glob(os.path.join(fixture_dir, pat)))

    if not fixture_files:
        print(f"No fixtures found in {fixture_dir}")
        sys.exit(1)

    fixture_files.sort()
    total_pass = 0
    total_fail = 0

    for fp in fixture_files:
        p, f = run_fixture(fp, output_dir)
        total_pass += p
        total_fail += f

    print(f"\n{'='*60}")
    print(f"Total: {total_pass} passed, {total_fail} failed")
    print(f"{'='*60}")
    sys.exit(1 if total_fail > 0 else 0)


if __name__ == "__main__":
    main()
