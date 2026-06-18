import json
import re
from dataclasses import dataclass
from androguard.core.apk import APK
from androguard.core.dex import DEX

_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")


@dataclass
class StaticData:
    apk: APK
    dexes: list[DEX]
    all_strings: list[str]
    urls: list[str]
    ips: list[str]


_apk_cache: dict[str, StaticData] = {}


def _init(apk_path: str) -> StaticData:
    if apk_path in _apk_cache:
        return _apk_cache[apk_path]

    a = APK(apk_path)
    dexes = [DEX(raw) for raw in a.get_all_dex()]

    all_strings: list[str] = []
    seen_urls: set[str] = set()
    seen_ips: set[str] = set()
    for dex in dexes:
        for s in dex.get_strings():
            all_strings.append(s)
            for u in _URL_PATTERN.findall(s):
                seen_urls.add(u)
            for ip in _IP_PATTERN.findall(s):
                seen_ips.add(ip)

    data = StaticData(
        apk=a,
        dexes=dexes,
        all_strings=all_strings,
        urls=sorted(seen_urls),
        ips=sorted(seen_ips),
    )
    _apk_cache[apk_path] = data
    return data


def get_static(apk_path: str) -> StaticData:
    return _init(apk_path)


def load_apk(apk_path: str) -> APK:
    return _init(apk_path).apk


def load_dex(apk_path: str) -> list[DEX]:
    return _init(apk_path).dexes


def as_json(result) -> str:
    return json.dumps(result, indent=2)
