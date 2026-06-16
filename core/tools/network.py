from .base import load_dex, as_json, _URL_PATTERN, _IP_PATTERN


def handle_extract_network_indicators(apk_path: str, **_kw) -> str:
    dexes = load_dex(apk_path)
    urls = set()
    ips = set()
    for dex in dexes:
        for s in dex.get_strings():
            for u in _URL_PATTERN.findall(s):
                urls.add(u)
            for ip in _IP_PATTERN.findall(s):
                ips.add(ip)
    return as_json({
        "urls": sorted(urls)[:30],
        "ips": sorted(ips)[:20],
    })


HANDLERS = {
    "extract_network_indicators": handle_extract_network_indicators,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "extract_network_indicators",
            "description": "Extract all embedded URLs and IP addresses from DEX bytecode",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
