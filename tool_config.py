import json
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")

_DEFAULT_TOOLS = {
    "ysoserial": "Analyze/third_tool/java/ysoserial-all.jar",
    "phpggc": "Analyze/third_tool/phpggc/phpggc",
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
    global _config_cache
    if _config_cache is None:
        raw = _load_raw_config()
        overrides = raw.get("tools")
        if not isinstance(overrides, dict):
            overrides = {}
        _config_cache = {**_DEFAULT_TOOLS, **overrides}

    path = _config_cache.get(name, "")
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def get_oob_domain() -> str:
    env_value = os.environ.get("ETHICALQUOC_OOB_DOMAIN")
    if env_value:
        return env_value

    raw = _load_raw_config()
    value = raw.get("oob_domain")
    return value if isinstance(value, str) else ""
