"""Benign traffic false-positive checker.

Collects all .rules files from the suricata/ directory, builds pcaps from
benign traffic specs in benign-corpus/, runs Suricata against each one,
and fails if ANY rule fires on benign traffic.

Designed to run both standalone and inside the Docker container.
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

# Minimal suricata.yaml — same as validate.py.
SURICATA_YAML = """\
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80, 2375, 2376, 3100, 8000, 8080, 8443, 8545, 8888, 9090]"

app-layer:
  protocols:
    http:
      enabled: yes
      ports: [80, 2375, 2376, 3100, 8000, 8080, 8443, 8545, 8888, 9090]

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


def find_repo_root():
    """Walk up from this script to find the repo root (has suricata/ dir)."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.isdir(os.path.join(d, "suricata")):
            return d
        d = os.path.dirname(d)
    return None


def collect_rules(rules_dir):
    """Concatenate all .rules files into one combined rule text."""
    rule_files = sorted(glob.glob(os.path.join(rules_dir, "*.rules")))
    if not rule_files:
        return None, []
    lines = []
    sources = []
    for rf in rule_files:
        sources.append(os.path.basename(rf))
        with open(rf) as f:
            lines.append(f.read())
    return "\n".join(lines), sources


def write_config(directory, yaml_text):
    """Write suricata.yaml and combined rules into a work directory."""
    yaml_path = os.path.join(directory, "suricata.yaml")
    with open(yaml_path, "w") as f:
        f.write(yaml_text)
    return yaml_path


def write_rules(directory, rule_text):
    """Write combined rules to a file and return its path."""
    path = os.path.join(directory, "combined.rules")
    with open(path, "w") as f:
        f.write(rule_text)
    return path


def run_suricata(rule_path, yaml_path, pcap_path, log_dir):
    """Run suricata against a pcap, return set of fired SIDs and their msgs."""
    eve_path = os.path.join(log_dir, "eve.json")
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
        return None, f"suricata exited {result.returncode}: {result.stderr.strip()}"

    fired = []
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
                    alert = event.get("alert", {})
                    sid = alert.get("signature_id")
                    msg = alert.get("signature", "")
                    if sid is not None:
                        fired.append((int(sid), msg))

    return fired, None


def main():
    corpus_dir = os.environ.get("CORPUS_DIR", None)
    rules_dir = os.environ.get("RULES_DIR", None)

    # Auto-detect paths relative to script location.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if corpus_dir is None:
        corpus_dir = os.path.join(script_dir, "benign-corpus")
    if rules_dir is None:
        repo_root = find_repo_root()
        if repo_root:
            rules_dir = os.path.join(repo_root, "suricata")
        else:
            print("Cannot find suricata/ directory. Set RULES_DIR env var.")
            sys.exit(1)

    # Collect rules.
    rule_text, rule_sources = collect_rules(rules_dir)
    if rule_text is None:
        print(f"No .rules files found in {rules_dir}")
        sys.exit(1)

    print(f"Loaded {len(rule_sources)} rule file(s): {', '.join(rule_sources)}")

    # Collect benign specs.
    spec_files = sorted(glob.glob(os.path.join(corpus_dir, "*.yaml"))
                        + glob.glob(os.path.join(corpus_dir, "*.yml")))
    if not spec_files:
        print(f"No benign specs found in {corpus_dir}")
        sys.exit(1)

    print(f"Found {len(spec_files)} benign spec(s)")

    total_cases = 0
    fp_cases = []

    work_dir = tempfile.mkdtemp(prefix="benign_")
    try:
        yaml_path = write_config(work_dir, SURICATA_YAML)
        rule_path = write_rules(work_dir, rule_text)

        for sf in spec_files:
            with open(sf) as f:
                spec = yaml.safe_load(f)

            spec_name = spec.get("name", os.path.basename(sf))
            requests = spec.get("requests", [])

            print(f"\n{'='*60}")
            print(f"Corpus: {spec_name}")
            print(f"{'='*60}")

            for i, req in enumerate(requests):
                req_name = req.get("name", f"request_{i}")
                total_cases += 1

                tc_dir = os.path.join(work_dir, f"{os.path.basename(sf)}_{i}")
                os.makedirs(tc_dir, exist_ok=True)

                pcap_path = os.path.join(tc_dir, "traffic.pcap")
                craft_pcap(req, pcap_path, client_port=49152 + i)

                fired, err = run_suricata(rule_path, yaml_path, pcap_path, tc_dir)

                if err:
                    print(f"  [ERR]  {req_name} -- {err}")
                    fp_cases.append((spec_name, req_name, err))
                elif fired:
                    sids = sorted(set(s for s, _ in fired))
                    msgs = sorted(set(m for _, m in fired))
                    print(f"  [FAIL] {req_name} -- false positive: SIDs {sids}")
                    for m in msgs:
                        print(f"         -> {m}")
                    fp_cases.append((spec_name, req_name, f"SIDs {sids}"))
                else:
                    print(f"  [PASS] {req_name} -- no alerts")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"Total: {total_cases} benign cases, {len(fp_cases)} false positive(s)")
    print(f"{'='*60}")

    if fp_cases:
        print("\nFalse positives:")
        for spec_name, req_name, detail in fp_cases:
            print(f"  {spec_name} / {req_name}: {detail}")
        sys.exit(1)
    else:
        print("\nAll clean — no false positives detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
