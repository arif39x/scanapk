import json
import os
import time

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))


def _verdict(severity: str) -> str:
    return {"CLEAN": "INSTALL", "LOW": "REVIEW"}.get(severity.upper(), "DO_NOT_INSTALL")


def generate(static_info: dict, ai_result: dict, output_dir: str = REPORT_DIR) -> str:
    os.makedirs(output_dir, exist_ok=True)

    pkg = static_info.get("package", "unknown").replace(".", "_")
    ts = int(time.time())
    filename = f"report_{pkg}_{ts}.json"
    path = os.path.join(output_dir, filename)

    report = {
        "schema_version": "1.0",
        "generated_at": ts,
        "verdict": _verdict(ai_result.get("severity", "")),
        "app": {
            "name": static_info.get("app_name"),
            "package": static_info.get("package"),
            "target_sdk": static_info.get("target_sdk"),
        },
        "assessment": ai_result,
        "static_evidence": {
            "dangerous_permissions": static_info.get("dangerous_permissions", []),
            "suspicious_apis": static_info.get("suspicious_apis", []),
            "embedded_urls": static_info.get("urls", []),
            "embedded_ips": static_info.get("ips", []),
            "receivers": static_info.get("receivers", []),
            "services": static_info.get("services", []),
            "native_libs": static_info.get("native_libs", []),
        },
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    _print_summary(report)
    return path


def _print_summary(report: dict):
    a = report["assessment"]
    score = a.get("risk_score", "?")
    severity = a.get("severity", "?")
    family = a.get("malware_family") or "unknown"
    pkg = report["app"].get("package", "?")

    bar_filled = int(score / 5) if isinstance(score, int) else 0
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print("\n" + "=" * 60)
    print(f"  INVESTIGATION REPORT — {pkg}")
    print("=" * 60)
    print(f"  Risk score : [{bar}] {score}/100")
    print(f"  Severity   : {severity}")
    print(f"  Verdict    : {_verdict(severity)}")
    print(f"  Family     : {family}")
    print(f"  Confidence : {a.get('confidence', '?')}")
    print()
    print("  Key findings:")
    for finding in a.get("key_findings", []):
        print(f"    \u2022 {finding}")
    print()
    print("  Recommendations:")
    for rec in a.get("recommendations", []):
        print(f"    \u2192 {rec}")
    print("=" * 60)
