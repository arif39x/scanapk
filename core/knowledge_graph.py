def _san(val: str, maxlen: int = 200) -> str:
    return str(val).replace("|", "/").replace("\n", " ")[:maxlen]


def build_graph(apk_path: str, static_info: dict, evidence: dict | None = None) -> str:
    lines: list[str] = []
    pkg = static_info.get("package", "?")
    app_name = static_info.get("app_name", "?")
    target_sdk = static_info.get("target_sdk", "?")

    lines.append(f"# Knowledge Graph — {app_name} ({pkg})")
    lines.append("")

    lines.append(f"APP: {pkg} | {app_name} | targetSdk={target_sdk}")

    dangerous = static_info.get("dangerous_permissions") or []
    for p in dangerous:
        lines.append(f"PERM: {_san(p)} | dangerous")

    for a in (static_info.get("suspicious_apis") or [])[:30]:
        lines.append(f"API: {_san(a)}")

    for u in (static_info.get("urls") or [])[:20]:
        lines.append(f"URL: {_san(u)}")

    for ip in (static_info.get("ips") or [])[:10]:
        lines.append(f"IP: {_san(ip)}")

    for r in static_info.get("receivers") or []:
        lines.append(f"RECV: {_san(r)}")
    for s in static_info.get("services") or []:
        lines.append(f"SVC: {_san(s)}")

    for lib in (static_info.get("native_libs") or [])[:15]:
        lines.append(f"LIB: {_san(lib)}")

    for s in (static_info.get("raw_strings_sample") or [])[:10]:
        lines.append(f"STR: {_san(s)}")

    if evidence:
        for h in (evidence.get("frida_hits") or [])[:15]:
            detail = _san(h if isinstance(h, str) else h.get("detail", str(h)))
            lines.append(f"FRIDA: {detail}")

        for r in (evidence.get("network_requests") or [])[:10]:
            method = _san(r.get("method", "?"))
            url = _san(r.get("url", str(r)))
            lines.append(f"NET: {method} | {url}")

        for l in (evidence.get("logcat_hits") or [])[:10]:
            lines.append(f"LOGCAT: {_san(l)}")

        detected = evidence.get("detected_techniques") or []
        for dt in detected:
            technique = _san(dt.get("technique", "?"))
            confidence = _san(dt.get("confidence", "?"))
            lines.append(f"TECH: {technique} | confidence={confidence}")
            for ind in (dt.get("indicators") or [])[:3]:
                lines.append(f"  INDICATOR: {_san(ind)}")

    lines.append(f"\n# Total: {len(lines) - 2} triples")
    return "\n".join(lines)
