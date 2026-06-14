import json
import os
import re

from core.models import resolve
from core.tools import TOOL_DEFINITIONS, execute_tool

_SYSTEM_PROMPT = """You are a mobile malware analyst at a bank's cybersecurity team.
You have access to Android APK analysis tools. Your job is to:

1. Systematically gather evidence from the APK using the available tools
2. Analyze permissions, embedded URLs/IPs, suspicious API calls, manifest components, and string patterns
3. Think step by step about what each finding means in context
4. When you have enough evidence, produce a FINAL structured assessment

Always call tools to gather evidence before concluding. Once you have sufficient information,
produce your final assessment as valid JSON with this exact schema (no markdown fences):

{
  "risk_score": <int 0-100>,
  "severity": "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "malware_family": <string or null>,
  "threat_types": [<string>],
  "iocs": { "urls": [<string>], "ips": [<string>], "apis": [<string>] },
  "key_findings": [<string>],
  "recommendations": [<string>],
  "confidence": "LOW" | "MEDIUM" | "HIGH"
}

Risk score: 0-20 clean, 21-40 suspicious, 41-60 likely malicious, 61-80 high confidence malicious, 81-100 confirmed malware.
Be conservative — a banking app legitimately needs INTERNET + READ_PHONE_STATE.

When you are ready to produce the final assessment, call the `finalize_assessment` tool with the JSON as the `report` parameter."""


def analyse(
    apk_path: str,
    static_info: dict,
    evidence: dict | None = None,
    max_tool_rounds: int = 20,
) -> dict:
    from openai import OpenAI

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return _error("OPENROUTER_API_KEY not set")

    _, model_id = resolve()
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "https://github.com/scanapk",
            "X-Title": "ScanAPK",
        },
    )

    tools = TOOL_DEFINITIONS + [_FINALIZE_TOOL]

    msgs = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Analyse this APK for malware indicators:\n\n"
                f"Path: {apk_path}\n"
                f"Package: {static_info.get('package', '?')}\n"
                f"App name: {static_info.get('app_name', '?')}\n\n"
                + (_format_dynamic_evidence(evidence) if evidence else "Dynamic analysis was not performed.")
            ),
        },
    ]

    for _ in range(max_tool_rounds):
        try:
            resp = client.chat.completions.create(
                model=model_id,
                messages=msgs,
                tools=tools,
                temperature=0.1,
                max_tokens=8192,
            )
        except Exception as e:
            return _error(str(e))

        msg = resp.choices[0].message
        msgs.append(msg)

        if not msg.tool_calls:
            return _try_extract_report(msg.content)

        for tc in msg.tool_calls:
            fn = tc.function
            if fn.name == "finalize_assessment":
                try:
                    args = json.loads(fn.arguments)
                    raw = args.get("report", {})
                except (json.JSONDecodeError, KeyError) as e:
                    return _error(f"Invalid finalize_assessment call: {e}")

                if isinstance(raw, str):
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        pass
                    try:
                        import ast
                        return ast.literal_eval(raw)
                    except (ValueError, SyntaxError):
                        pass
                    fixed = raw.replace("'", '"').replace("None", "null").replace("True", "true").replace("False", "false")
                    try:
                        return json.loads(fixed)
                    except json.JSONDecodeError:
                        pass
                    return _error(f"Could not parse report JSON:\n{raw[:300]}")
                return raw

            result = execute_tool(fn.name, apk_path, **(json.loads(fn.arguments) if fn.arguments else {}))
            msgs.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

    return _error("Agent reached max tool call rounds without finalizing.")


def _format_dynamic_evidence(evidence: dict) -> str:
    parts = []
    frida = evidence.get("frida_hits", [])
    network = evidence.get("network_requests", [])
    logcat = evidence.get("logcat_hits", [])
    if frida:
        parts.append("Frida hooks fired:")
        for h in frida[:15]:
            parts.append(f"  - {h.get('detail', h)}")
    if network:
        parts.append("Network requests observed:")
        for r in network[:10]:
            parts.append(f"  - {r.get('method', '?')} {r.get('url', r)}")
    if logcat:
        parts.append("Suspicious logcat lines:")
        for l in logcat[:10]:
            parts.append(f"  - {l}")
    return "\n".join(parts) if parts else "No dynamic evidence collected."


_FINALIZE_TOOL = {
    "type": "function",
    "function": {
        "name": "finalize_assessment",
        "description": "Call this when you have enough evidence to produce the final structured assessment.",
        "parameters": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "string",
                    "description": "JSON string matching the required schema with risk_score, severity, etc.",
                },
            },
            "required": ["report"],
        },
    },
}


def _try_extract_report(content: str) -> dict:
    if not content:
        return _error("Agent returned empty response")
    content = re.sub(r"^```[a-z]*\n?", "", content.strip())
    content = re.sub(r"\n?```$", "", content)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        brace_start = content.find("{")
        brace_end = content.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(content[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass
        return _error(f"Could not parse JSON from model output. Raw:\n{content[:500]}")


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
