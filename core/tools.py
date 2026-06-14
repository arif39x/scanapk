import json
import os
import re
import warnings
from androguard.core.apk import APK
from androguard.core.dex import DEX

_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")

_TOOLS = None
_apk_cache = {}
_dex_cache = []


def _load_apk(apk_path: str):
    if apk_path not in _apk_cache:
        _apk_cache[apk_path] = APK(apk_path)
    return _apk_cache[apk_path]


def _load_dex(apk_path: str):
    if not _dex_cache:
        a = _load_apk(apk_path)
        for raw in a.get_all_dex():
            _dex_cache.append(DEX(raw))
    return _dex_cache


def _as(result):
    return json.dumps(result, indent=2)


def handle_list_permissions(apk_path: str, **_kw) -> str:
    a = _load_apk(apk_path)
    perms = a.get_permissions()
    dangerous = [
        p
        for p in perms
        if p.startswith("android.permission.")
        and p.split(".")[-1]
        in (
            "READ_SMS",
            "RECEIVE_SMS",
            "SEND_SMS",
            "READ_PHONE_STATE",
            "READ_CONTACTS",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "RECORD_AUDIO",
            "CAMERA",
            "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE",
            "BIND_ACCESSIBILITY_SERVICE",
            "SYSTEM_ALERT_WINDOW",
            "BIND_NOTIFICATION_LISTENER_SERVICE",
            "BIND_DEVICE_ADMIN",
            "REQUEST_INSTALL_PACKAGES",
            "REQUEST_DELETE_PACKAGES",
        )
    ]
    return _as(
        {
            "total": len(perms),
            "dangerous_count": len(dangerous),
            "dangerous": dangerous,
            "all": perms,
        }
    )


def handle_search_strings(apk_path: str, pattern: str = "", **_kw) -> str:
    dexes = _load_dex(apk_path)
    if not pattern:
        return _as({"count": 0, "matches": [], "error": "pattern is required"})
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return _as({"count": 0, "matches": [], "error": str(e)})
    matches = []
    seen = set()
    for dex in dexes:
        for s in dex.get_strings():
            if regex.search(s) and s not in seen:
                seen.add(s)
                matches.append(s[:200])
    return _as({"count": len(matches), "matches": matches[:50]})


def handle_extract_network_indicators(apk_path: str, **_kw) -> str:
    dexes = _load_dex(apk_path)
    urls = set()
    ips = set()
    for dex in dexes:
        for s in dex.get_strings():
            for u in _URL_PATTERN.findall(s):
                urls.add(u)
            for ip in _IP_PATTERN.findall(s):
                ips.add(ip)
    return _as(
        {
            "urls": sorted(urls)[:30],
            "ips": sorted(ips)[:20],
        }
    )


def handle_list_manifest_components(apk_path: str, **_kw) -> str:
    a = _load_apk(apk_path)
    exported_activities = []
    for activity in a.get_activities():
        if a.get_intent_filters("activity", activity):
            exported_activities.append(activity)
    return _as(
        {
            "receivers": a.get_receivers(),
            "services": a.get_services(),
            "exported_activities": exported_activities,
            "all_activities": a.get_activities(),
        }
    )


def handle_list_native_libs(apk_path: str, **_kw) -> str:
    a = _load_apk(apk_path)
    libs = [f for f in a.get_files() if f.endswith(".so")]
    return _as({"count": len(libs), "libraries": libs})


def handle_get_app_info(apk_path: str, **_kw) -> str:
    a = _load_apk(apk_path)
    return _as(
        {
            "app_name": a.get_app_name(),
            "package": a.get_package(),
            "target_sdk": a.get_target_sdk_version(),
            "min_sdk": a.get_min_sdk_version(),
            "version": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
        }
    )


def handle_search_suspicious_apis(apk_path: str, **_kw) -> str:
    dexes = _load_dex(apk_path)
    apis = {
        "data_theft": [
            "getDeviceId",
            "getSubscriberId",
            "getImei",
            "getImsi",
            "getLastKnownLocation",
            "getLatitude",
            "getLongitude",
            "getAllContacts",
        ],
        "sms_intercept": [
            "sendTextMessage",
            "sendMultipartTextMessage",
            "RECEIVE_SMS",
            "READ_SMS",
            "abortBroadcast",
        ],
        "crypto": ["Cipher", "SecretKeySpec", "IvParameterSpec"],
        "shell_exec": ["Runtime.exec", "ProcessBuilder", "su ", "/system/bin/sh"],
        "network": [
            "ServerSocket",
            "DatagramSocket",
            "HttpURLConnection",
            "OkHttpClient",
        ],
        "ransomware": [
            "lockNow",
            "wipeData",
            "DevicePolicyManager",
            "setPasswordQuality",
        ],
        "persistence": ["RECEIVE_BOOT_COMPLETED", "PACKAGE_REPLACED"],
    }
    hits = {cat: [] for cat in apis}
    for dex in dexes:
        for s in dex.get_strings():
            for cat, patterns in apis.items():
                for p in patterns:
                    if p in s and p not in hits[cat]:
                        hits[cat].append(p)
    return _as({k: v for k, v in hits.items() if v})


def handle_get_raw_strings(apk_path: str, keyword: str = "", **_kw) -> str:
    dexes = _load_dex(apk_path)
    results = []
    seen = set()
    for dex in dexes:
        for s in dex.get_strings():
            if not keyword or keyword.lower() in s.lower():
                if s not in seen and len(s) > 3:
                    seen.add(s)
                    results.append(s[:200])
    return _as({"count": len(results), "strings": results[:40]})


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_app_info",
            "description": "Get basic app info: name, package, SDK versions",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_permissions",
            "description": "List all APK permissions, highlighting dangerous ones",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_manifest_components",
            "description": "List receivers, services, and activities from the manifest",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": "Search DEX bytecode strings with a regex pattern. Use this to find suspicious strings, class names, or API references.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for in DEX strings",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_network_indicators",
            "description": "Extract all embedded URLs and IP addresses from DEX bytecode",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_native_libs",
            "description": "List bundled native (.so) libraries",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_suspicious_apis",
            "description": "Search for categories of suspicious API calls (data theft, SMS intercept, crypto, shell exec, ransomware, persistence)",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_raw_strings",
            "description": "Get raw DEX strings, optionally filtered by keyword",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Optional keyword to filter strings",
                    },
                },
            },
        },
    },
]

TOOL_HANDLERS = {
    "get_app_info": handle_get_app_info,
    "list_permissions": handle_list_permissions,
    "list_manifest_components": handle_list_manifest_components,
    "search_strings": handle_search_strings,
    "extract_network_indicators": handle_extract_network_indicators,
    "list_native_libs": handle_list_native_libs,
    "search_suspicious_apis": handle_search_suspicious_apis,
    "get_raw_strings": handle_get_raw_strings,
}


def execute_tool(name: str, apk_path: str, **kwargs) -> str:
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})
    return handler(apk_path, **kwargs)
