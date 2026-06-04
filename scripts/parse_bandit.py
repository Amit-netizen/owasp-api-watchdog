"""
scripts/parse_bandit.py
Parses Bandit JSON output and fails the pipeline if HIGH severity issues found.
Usage: python scripts/parse_bandit.py reports/bandit.json
"""

import json
import sys
import os


def main():
    report_path = sys.argv[1] if len(sys.argv) > 1 else "reports/bandit.json"

    if not os.path.exists(report_path):
        print(f"[WARNING] Bandit report not found at {report_path}. Skipping check.")
        sys.exit(0)

    with open(report_path) as f:
        data = json.load(f)

    results = data.get("results", [])
    metrics = data.get("metrics", {}).get("_totals", {})

    print("\n" + "="*60)
    print("  Bandit SAST Results")
    print("="*60)
    print(f"  Total issues   : {len(results)}")
    print(f"  HIGH severity  : {metrics.get('SEVERITY.HIGH', 0)}")
    print(f"  MEDIUM severity: {metrics.get('SEVERITY.MEDIUM', 0)}")
    print(f"  LOW severity   : {metrics.get('SEVERITY.LOW', 0)}")
    print("="*60)

    # Print HIGH severity findings
    high_findings = [r for r in results if r.get("issue_severity") == "HIGH"]
    if high_findings:
        print("\n[!] HIGH SEVERITY FINDINGS:")
        for finding in high_findings:
            print(f"\n  File    : {finding['filename']}:{finding['line_number']}")
            print(f"  Test    : {finding['test_id']} - {finding['test_name']}")
            print(f"  Issue   : {finding['issue_text']}")
            print(f"  Severity: {finding['issue_severity']} / Confidence: {finding['issue_confidence']}")

    # Print ALL findings summary
    if results:
        print(f"\n[!] All findings ({len(results)} total):")
        for r in results:
            print(f"  [{r['issue_severity']:6}] {r['filename']}:{r['line_number']} — {r['test_id']}: {r['issue_text'][:80]}")

    # Gate: fail on HIGH severity
    high_count = metrics.get("SEVERITY.HIGH", 0)
    if high_count > 0:
        print(f"\n[PIPELINE GATE] BUILD FAILED: {high_count} HIGH severity issue(s) found.")
        print("Fix the HIGH severity findings before merging.\n")
        sys.exit(1)
    else:
        print("\n[PIPELINE GATE] PASSED: No HIGH severity Bandit findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()
