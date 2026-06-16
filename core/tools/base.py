import json
import re
import warnings
from androguard.core.apk import APK
from androguard.core.dex import DEX

_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")

_apk_cache: dict[str, APK] = {}
_dex_cache: list[DEX] = []


def load_apk(apk_path: str) -> APK:
    if apk_path not in _apk_cache:
        _apk_cache[apk_path] = APK(apk_path)
    return _apk_cache[apk_path]


def load_dex(apk_path: str) -> list[DEX]:
    if not _dex_cache:
        a = load_apk(apk_path)
        for raw in a.get_all_dex():
            _dex_cache.append(DEX(raw))
    return _dex_cache


def as_json(result) -> str:
    return json.dumps(result, indent=2)
