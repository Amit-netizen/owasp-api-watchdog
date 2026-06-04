#!/usr/bin/env python3
"""
run_local.py — One-command local DevSecOps pipeline for Windows 11 / WSL2
Runs all scan stages locally without GitHub Actions.

Usage:
    python run_local.py              # full pipeline
    python run_local.py --stage sast # single stage
"""

import subprocess
import sys
import os
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)


def run(cmd: str, label: str, check: bool = False) -> int:
    """Run a shell command, print output live, return exit code."""
    print(f"\n{'─'*60}")
    print(f"  ▶  {label}")
    print(f"{'─'*60}")
    result = subprocess.run(cmd, shell=True, cwd=str(ROOT))
    return result.returncode


def stage_sast():
    print("\n" + "="*60)
    print("  STAGE 1: SAST — Semgrep + Bandit")
    print("="*60)

    # Semgrep
    rc = run(
        f'semgrep scan --config "p/owasp-top-ten" --config "p/python" --config "p/flask" '
        f'--config semgrep.yml --json --output reports/semgrep.json .',
        "Semgrep OWASP scan"
    )
    if rc == 0:
        print("  [✓] Semgrep: no findings")
    else:
        # Parse and display findings
        try:
            with open(REPORTS / "semgrep.json") as f:
                data = json.load(f)
            findings = data.get("results", [])
            print(f"  [!] Semgrep found {len(findings)} issue(s):")
            for r in findings:
                print(f"      {r['path']}:{r['start']['line']} — {r['check_id']}")
                print(f"      {r['extra']['message'][:100]}")
        except Exception:
            pass

    # Bandit
    run(
        "bandit -r app/ -f json -o reports/bandit.json -ll || true",
        "Bandit Python security scan"
    )
    run(
        "python scripts/parse_bandit.py reports/bandit.json",
        "Bandit result gate"
    )


def stage_dependency():
    print("\n" + "="*60)
    print("  STAGE 2: Dependency Scan — pip-audit")
    print("="*60)

    run(
        "pip-audit --requirement requirements.txt --format json --output reports/pip-audit.json || true",
        "pip-audit CVE scan"
    )
    run(
        "python scripts/parse_pip_audit.py reports/pip-audit.json",
        "pip-audit result gate"
    )


def stage_container():
    print("\n" + "="*60)
    print("  STAGE 3: Container Scan — Trivy (requires Docker)")
    print("="*60)

    # Check Docker is available
    rc = subprocess.run("docker --version", shell=True, capture_output=True).returncode
    if rc != 0:
        print("  [SKIP] Docker not found. Skipping container scan.")
        return

    image = "owasp-api-scanner:local"
    run(f"docker build -t {image} .", "Build Docker image")
    run(
        f'docker run --rm -v "%cd%/reports:/reports" '
        f'aquasec/trivy image --format json --output /reports/trivy.json '
        f'--severity HIGH,CRITICAL {image}',
        "Trivy container scan"
    )


def stage_tests():
    print("\n" + "="*60)
    print("  STAGE 4: OWASP API Security Tests — pytest")
    print("="*60)

    run(
        "pytest tests/ -v --tb=short "
        "--html=reports/security-test-report.html --self-contained-html "
        "--json-report --json-report-file=reports/security-test-report.json",
        "pytest OWASP security suite"
    )
    print("\n  📄 HTML report: reports/security-test-report.html")


def main():
    parser = argparse.ArgumentParser(description="Local DevSecOps pipeline")
    parser.add_argument(
        "--stage",
        choices=["sast", "dependency", "container", "tests", "all"],
        default="all",
        help="Which stage to run (default: all)"
    )
    args = parser.parse_args()

    if args.stage in ("sast", "all"):
        stage_sast()
    if args.stage in ("dependency", "all"):
        stage_dependency()
    if args.stage in ("container", "all"):
        stage_container()
    if args.stage in ("tests", "all"):
        stage_tests()

    print("\n" + "="*60)
    print("  Pipeline complete. Reports in: ./reports/")
    print("="*60)


if __name__ == "__main__":
    main()
