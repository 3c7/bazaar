import os
from pathlib import Path
from sys import platform

from rich.console import Console


def is_linux() -> bool:
    return platform == "linux"


def is_win() -> bool:
    return platform == "win32"


def is_darwin() -> bool:
    return platform == "darwin"


def get_config_dir(ec: Console = Console(stderr=True, style="bold red")) -> Path:
    """Returns path to directory in user dir"""
    u_path = None
    u_env = os.getenv("BAZAAR_PATH", None)
    if u_env:
        return Path(u_env)
    if is_linux() or is_darwin():
        if not os.getenv("HOME"):
            raise Exception('Unable to get environment variable "HOME"')
        u_path = os.path.abspath(os.path.join(os.environ["HOME"], ".config", "bazaar"))
    elif is_win():
        if not os.getenv("APPDATA"):
            raise Exception('Unable to get environment variable "APPDATA"')
        u_path = os.path.abspath(os.path.join(os.environ["APPDATA"], "bazaar"))
    else:
        ec.print(f"Unknown platform: {platform}.")
        exit(-1)

    if not os.path.exists(u_path):
        os.mkdir(u_path)

    return Path(u_path)


def get_config_path() -> Path:
    """Return path to config.toml"""
    c_env = os.getenv("BAZAAR_CONFIG", None)
    if c_env:
        return Path(c_env)
    c_path = get_config_dir().joinpath("config.yml")
    return Path(c_path)
