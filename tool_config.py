import json
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")

_DEFAULT_TOOLS = {
    "ysoserial": "Analyze/third_tool/java/ysoserial-all.jar",
    "phpggc": "Analyze/third_tool/phpggc",
    "ysoserial_net": "Analyze/third_tool/dotnet/ysoserial.exe",
    "gopherus": "Analyze/third_tool/gopherus/gopherus.py",
}

_config_cache = None


def _load_raw_config() -> dict:
    config_path = os.environ.get("ETHICALQUOC_CONFIG", DEFAULT_CONFIG_PATH)
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Failed to read config at {config_path}: {e} — using built-in defaults")
        return {}


def get_tool_path(name: str) -> str:
    """Resolves a tool path by name (e.g. 'ysoserial', 'phpggc').

    Looks up config.json (or the file at ETHICALQUOC_CONFIG) under the
    'tools' key. A relative path is resolved against the project root so the
    tool works regardless of drive letter or clone location. Falls back to
    built-in defaults if the config file or key is missing.
    """
    global _config_cache
    if _config_cache is None:
        raw = _load_raw_config()
        _config_cache = {**_DEFAULT_TOOLS, **raw.get("tools", {})}

    path = _config_cache.get(name, "")
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)
