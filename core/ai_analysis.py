import json
import os
import re

from openai import OpenAI

_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

_SYSTEM_PROMPT = """You are a mobile malware analyst at a bank's cybersecurity team.
You receive structured evidence from static and dynamic analysis of Android APK files
and must produce a precise, actionable threat assessment.

Always respond with valid JSON only — no markdown fences, no preamble.
Schema:
{
  "risk_score": <int 0-100>,
  "severity": "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "malware_family": <string or null>,
  "threat_types": [<list of strings>],
  "iocs": { "urls": [<string>], "ips": [<string>], "apis": [<string>] },
  "key_findings": [<3-7 strings>],
  "recommendations": [<3-5 strings>],
  "confidence": "LOW" | "MEDIUM" | "HIGH"
}

Risk score guidance:
  0-20   Clean or benign
  21-40  Suspicious, needs review
  41-60  Likely malicious
  61-80  High confidence malicious
  81-100 Confirmed malware / critical threat"""


def analyse(evidence: dict, static_info: dict) -> dict:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return _error("OPENROUTER_API_KEY not set")

    payload = _build_payload(evidence, static_info)
    prompt = "Analyse this Android APK evidence and return your assessment as JSON:\n\n" + json.dumps(payload, indent=2)

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        default_headers={"HTTP-Referer": "https://github.com/scanapk", "X-Title": "ScanAPK"},
    )
    try:
        resp = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        raw = resp.choices[0].message.content.strip()
        return _parse_json(raw)
    except Exception as e:
        return _error(str(e))


def _build_payload(evidence: dict, static_info: dict) -> dict:
    return {
        "app": {
            "name": static_info.get("app_name"),
            "package": static_info.get("package"),
            "target_sdk": static_info.get("target_sdk"),
        },
        "static": {
            "dangerous_permissions": static_info.get("dangerous_permissions", []),
            "suspicious_apis": static_info.get("suspicious_apis", []),
            "embedded_urls": static_info.get("urls", [])[:20],
            "embedded_ips": static_info.get("ips", [])[:10],
            "receivers": static_info.get("receivers", []),
            "services": static_info.get("services", []),
            "native_libs": static_info.get("native_libs", []),
            "raw_strings_sample": static_info.get("raw_strings_sample", [])[:15],
        },
        "dynamic": {
            "frida_hits": [h["detail"] for h in evidence.get("frida_hits", [])][:30],
            "network_requests": evidence.get("network_requests", [])[:20],
            "logcat_hits": evidence.get("logcat_hits", [])[:30],
        },
    }


def _parse_json(raw: str) -> dict:
    raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
    raw = re.sub(r"\n?```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        brace_start = raw.find("{")
        brace_end = raw.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(raw[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass
        return _error(f"Could not parse JSON from model output:\n{raw[:500]}")


def _error(msg: str) -> dict:
    return {
        "risk_score": -1,
        "severity": "ERROR",
        "malware_family": None,
        "threat_types": [],
        "iocs": {"urls": [], "ips": [], "apis": []},
        "key_findings": [msg],
        "recommendations": ["Fix the error above and retry."],
        "confidence": "LOW",
    }
