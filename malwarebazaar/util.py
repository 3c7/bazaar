from typing import Union

import requests

try:
    from rich.console import Console
except ImportError:
    print("Please install malwarebazaar[cli] if you want to use the cli functionality.")
    raise

from malwarebazaar import version as ver


def get_latest_release_tag() -> Union[str, None]:
    res = requests.get("https://api.github.com/repos/3c7/bazaar/releases")
    if res.status_code != 200:
        return None

    releases = res.json()
    for release in releases:
        if not release["draft"] and not release["prerelease"]:
            return release["tag_name"]
    return None


def check_version(check: bool):
    c = Console(highlight=False)
    github_version = None
    if check:
        github_version = get_latest_release_tag()

    c.print(f"Bazaar/YARAify {ver}")

    if check:
        if github_version:
            if ver != github_version:
                c.print(f"Your version of Bazaar/YARAify does not match the most recent published version. "
                        f"The most recent version is {github_version}.",
                        style="yellow")
            else:
                c.print(f"Your version of Bazaar is up to date.", style="green")
        else:
            c.print("Could not get most recent version from Github.")

    c.print(f"https://github.com/3c7/bazaar/releases/tag/{github_version or ver}")
