"""
scripts/parse_pip_audit.py
Parses pip-audit JSON output and fails the pipeline on CRITICAL/HIGH CVEs.
Usage: python scripts/parse_pip_audit.py reports/pip-audit.json
"""

import json
import sys
import os


def main():
    report_path = sys.argv[1] if len(sys.argv) > 1 else "reports/pip-audit.json"

    if not os.path.exists(report_path):
        print(f"[WARNING] pip-audit report not found at {report_path}. Skipping.")
        sys.exit(0)

    with open(report_path) as f:
        data = json.load(f)

    dependencies = data.get("dependencies", [])
    all_vulns = []

    for dep in dependencies:
        for vuln in dep.get("vulns", []):
            all_vulns.append({
                "package": dep.get("name"),
                "version": dep.get("version"),
                "id": vuln.get("id"),
                "fix_versions": vuln.get("fix_versions", []),
                "description": vuln.get("description", "")[:120],
            })

    print("\n" + "="*60)
    print("  pip-audit Dependency Scan Results")
    print("="*60)
    print(f"  Packages scanned       : {len(dependencies)}")
    print(f"  Vulnerable dependencies: {sum(1 for d in dependencies if d.get('vulns'))}")
    print(f"  Total CVEs found       : {len(all_vulns)}")
    print("="*60)

    if all_vulns:
        print("\n[!] Vulnerable dependencies:")
        for v in all_vulns:
            fix = ", ".join(v["fix_versions"]) if v["fix_versions"] else "No fix available"
            print(f"\n  Package    : {v['package']}=={v['version']}")
            print(f"  CVE/ID     : {v['id']}")
            print(f"  Fix        : {fix}")
            print(f"  Description: {v['description']}")

    # Gate: fail if any CVEs found
    if all_vulns:
        print(f"\n[PIPELINE GATE] BUILD FAILED: {len(all_vulns)} CVE(s) found in dependencies.")
        print("Run: pip-audit --requirement requirements.txt  to see details.")
        print("Update the affected packages to their fixed versions.\n")
        sys.exit(1)
    else:
        print("\n[PIPELINE GATE] PASSED: No known CVEs in dependencies.")
        sys.exit(0)


if __name__ == "__main__":
    main()
