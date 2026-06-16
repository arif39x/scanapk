from .base import load_dex, as_json


_SUSPICIOUS_APIS = {
    "data_theft": [
        "getDeviceId", "getSubscriberId", "getImei", "getImsi",
        "getLastKnownLocation", "getLatitude", "getLongitude", "getAllContacts",
    ],
    "sms_intercept": [
        "sendTextMessage", "sendMultipartTextMessage", "RECEIVE_SMS", "READ_SMS", "abortBroadcast",
    ],
    "crypto": ["Cipher", "SecretKeySpec", "IvParameterSpec"],
    "shell_exec": ["Runtime.exec", "ProcessBuilder", "su ", "/system/bin/sh"],
    "network": ["ServerSocket", "DatagramSocket", "HttpURLConnection", "OkHttpClient"],
    "ransomware": ["lockNow", "wipeData", "DevicePolicyManager", "setPasswordQuality"],
    "persistence": ["RECEIVE_BOOT_COMPLETED", "PACKAGE_REPLACED"],
}


def handle_search_suspicious_apis(apk_path: str, **_kw) -> str:
    dexes = load_dex(apk_path)
    hits = {cat: [] for cat in _SUSPICIOUS_APIS}
    for dex in dexes:
        for s in dex.get_strings():
            for cat, patterns in _SUSPICIOUS_APIS.items():
                for p in patterns:
                    if p in s and p not in hits[cat]:
                        hits[cat].append(p)
    return as_json({k: v for k, v in hits.items() if v})


HANDLERS = {
    "search_suspicious_apis": handle_search_suspicious_apis,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_suspicious_apis",
            "description": "Search for categories of suspicious API calls (data theft, SMS intercept, crypto, shell exec, ransomware, persistence)",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
