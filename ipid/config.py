"""Load config.toml into a plain dict."""
import tomllib
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config.toml"


def load(path=None):
    with open(path or DEFAULT_PATH, "rb") as f:
        cfg = tomllib.load(f)
    if cfg["rates"]["max_pps"] <= 0:
        raise ValueError("rates.max_pps must be positive")
    return cfg
