import re
from androguard.core.apk import APK
from androguard.core.dex import DEX

_SUSPICIOUS_APIS = {
    "getDeviceId", "getSubscriberId", "getImei", "getImsi",
    "getLine1Number", "getLastKnownLocation", "getLatitude",
    "getLongitude", "getAllContacts",
    "sendTextMessage", "sendMultipartTextMessage", "onReceive",
    "RECEIVE_SMS", "READ_SMS", "abortBroadcast",
    "Cipher", "SecretKeySpec", "IvParameterSpec",
    "Runtime.exec", "ProcessBuilder", "su ", "/system/bin/sh",
    "ServerSocket", "DatagramSocket",
    "lockNow", "wipeData", "setPasswordQuality",
    "BIND_DEVICE_ADMIN", "DevicePolicyManager",
    "setComponentEnabledSetting", "HIDE", "PACKAGE_REPLACED",
    "RECEIVE_BOOT_COMPLETED",
}

_URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}"
)
_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"
)


def scan_dex(apk_path: str) -> dict:
    result = {
        "suspicious_apis": [],
        "urls": [],
        "ips": [],
        "receivers": [],
        "services": [],
        "activities": [],
        "native_libs": [],
        "raw_strings_sample": [],
    }

    a = APK(apk_path)

    result["receivers"] = a.get_receivers()
    result["services"] = a.get_services()

    for activity in a.get_activities():
        if a.get_intent_filters("activity", activity):
            result["activities"].append(activity)

    result["native_libs"] = [
        f for f in a.get_files() if f.endswith(".so")
    ]

    seen_urls = set()
    seen_ips = set()
    seen_apis = set()
    raw_hits = []

    for dex_bytes in a.get_all_dex():
        dex = DEX(dex_bytes)

        for s in dex.get_strings():
            for url in _URL_PATTERN.findall(s):
                if url not in seen_urls:
                    seen_urls.add(url)
                    result["urls"].append(url)

            for ip in _IP_PATTERN.findall(s):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    result["ips"].append(ip)

            for api in _SUSPICIOUS_APIS:
                if api in s and api not in seen_apis:
                    seen_apis.add(api)
                    result["suspicious_apis"].append(api)
                    if len(raw_hits) < 30:
                        raw_hits.append(s[:120])

    result["raw_strings_sample"] = raw_hits

    return result
