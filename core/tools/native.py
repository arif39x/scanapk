from .base import load_apk, as_json


def handle_list_native_libs(apk_path: str, **_kw) -> str:
    a = load_apk(apk_path)
    libs = [f for f in a.get_files() if f.endswith(".so")]
    return as_json({"count": len(libs), "libraries": libs})


HANDLERS = {
    "list_native_libs": handle_list_native_libs,
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_native_libs",
            "description": "List bundled native (.so) libraries",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
