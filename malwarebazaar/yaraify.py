import io
import json
import os
import zipfile
from enum import Enum
from json import dumps
from typing import List

import requests

try:
    from rich.console import Console
    from rich.progress import track
    from rich.status import Status
    from typer import Typer, Option, Argument, Exit
except ImportError:
    print("Please install malwarebazaar[cli] if you want to use the cli functionality.")
    raise

from malwarebazaar.api import Yaraify
from malwarebazaar.config import Config, YARAifyConfig
from malwarebazaar.models import Sample, YaraRule, Task
from malwarebazaar.output import print_sample_table, print_yararule_table, print_task_table, sample_csv_output, \
    yara_csv_output, format_none
from malwarebazaar.util import check_version


class QueryTypes(Enum):
    hash = "hash"
    yara = "yara"
    clamav = "clamav"
    imphash = "imphash"
    gimphash = "gimphash"
    icon = "icon"
    tlsh = "tlsh"
    telfhash = "telfhash"


def complete_query_typer(incomplete: str):
    for qtype in QueryTypes.__dict__["_member_names_"]:
        if qtype.startswith(incomplete):
            yield qtype


yaraify_app = Typer(name="YARAify cli", help="Query YARAify from your command line!")


@yaraify_app.command(name="init",
                     help="Initialize YARAify cli with the YARAify API key and optionally a Malpedia API key.")
def init(
        bazaar_key: str = Option(None, "-b", "--bazaar", help="Optional MalwareBazaar key."),
        malpedia_key: str = Option(None, "-m", "--malpedia",
                                   help="Optional Malpedia key to use for yara rule searches."),
        api_key: str = Argument(..., help="The API key from your YARAify account.")
):
    c = Console()
    try:
        conf = Config.get_instance()
    except FileNotFoundError:
        Config.init_config(
            bazaar_key,
            api_key,
            malpedia_key
        )
        conf = Config.get_instance()

    # Do not overwrite MalwareBazaar key with None
    if bazaar_key:
        conf.api_key = bazaar_key

    conf.yaraify = YARAifyConfig(
        api_key=api_key,
        malpedia_key=malpedia_key,
        csv_columns={
            "rule_name": "rule_name",
            "author": "author",
            "uuid": "yarahub_uuid"
        }
    )
    conf.save_config()
    c.print("Successfully created config:")
    c.print(conf.json())


@yaraify_app.command(name="query", help="Query the YARAify API for malware samples.")
def query(
        json: bool = Option(False, "-j", "--json", help="Output raw JSON response."),
        csv: bool = Option(False, "-c", "--csv", help="Output csv."),
        limit: int = Option(25, "-l", "--limit", help="Limit the amount of objects returned."),
        simple: bool = Option(False, "-s", "--simple", help="Just output SHA256 hashes."),
        download: bool = Option(False, "-d", "--download", help="Download samples retrieved by query."),
        query_type: QueryTypes = Argument(..., show_choices=True, help="The type of query to send to the API.",
                                          autocompletion=complete_query_typer),
        query: List[str] = Argument(..., help="The search term to use.")
):
    c, ec = Console(), Console(stderr=True, style="bold red")
    config = Config.get_instance()
    yaraify = Yaraify(
        api_key=config.yaraify.api_key,
        malpedia_key=config.yaraify.malpedia_key
    )
    try:
        with Status("Querying YARAify..."):
            results = []
            for q in query:
                if query_type == QueryTypes.hash:
                    results.append(yaraify.query_hash(q))
                elif query_type == QueryTypes.yara:
                    results.append(yaraify.query_yara_rule(q, limit))
                elif query_type == QueryTypes.clamav:
                    results.append(yaraify.query_clamav_signature(q, limit))
                elif query_type == QueryTypes.imphash:
                    results.append(yaraify.query_imphash(q, limit))
                elif query_type == QueryTypes.gimphash:
                    results.append(yaraify.query_gimphash(q, limit))
                elif query_type == QueryTypes.icon:
                    results.append(yaraify.query_icon_dhash(q, limit))
                elif query_type == QueryTypes.tlsh:
                    results.append(yaraify.query_tlsh(q, limit))
                elif query_type == QueryTypes.telfhash:
                    results.append(yaraify.query_telfhash(q, limit))
                else:
                    ec.print("Currently only \"hash\" as query type is supported.")
                    raise Exit(-1)
    except (requests.ConnectionError, requests.ConnectTimeout):
        ec.print("[bold red]Could not connect to YARAify API.[/bold red]")
        raise Exit(-1)

    if json or csv:
        data = []
        for result in results:
            r = result.get("data", None)
            if r:
                data.append(r)
        if json:
            c.print(dumps(data, indent=4))
        else:
            samples = []
            for d in data:
                if isinstance(d, List):
                    samples.extend(d)
                else:
                    samples.append(d)
            sample_csv_output([Sample(**s) for s in samples])
        raise Exit(0)

    for res in results:
        if res["query_status"] != "ok":
            ec.print(f"YARAify API returned an error for {q}: {res['query_status']}")
            raise Exit(-1)

        data = res["data"]
        sample_list = [data] if isinstance(data, dict) else data
        for idx, sample_dict in enumerate(sample_list):
            tasks = None
            if "metadata" in sample_dict:
                tasks = sample_dict["tasks"]
                sample_dict = sample_dict["metadata"]

            if simple:
                c.print(sample_dict["sha256_hash"])
            else:
                sample = Sample(**sample_dict)
                c.print(f"Sample {idx + 1}/{len(sample_list)}")
                print_sample_table(sample, c)
                if tasks:
                    for idx, task in enumerate(tasks):
                        t = Task(**task)
                        c.print(f"Task {idx + 1}/{len(tasks)}")
                        print_task_table(t, c, include_sample=False)
                c.print()

        if download:
            for sample in track(sample_list, description="Downloading samples..."):
                if "metadata" in sample:
                    sample = sample["metadata"]
                sha256_hash = sample["sha256_hash"]
                file_content = yaraify.download_file(sha256_hash)
                with io.open(sha256_hash, "wb") as fh:
                    fh.write(file_content)


@yaraify_app.command(name="recent", help="Query for recent Yara rules. Various output formats are possible.")
def recent_yara(
        json: bool = Option(False, "-j", "--json", help="Output raw JSON response."),
        simple: bool = Option(False, "-s", "--simple", help="Just print Yara rule names and the rule UUIDs."),
        csv: bool = Option(False, "-c", "--csv", help="CSV output."),
        limit: int = Option(None, "-l", "--limit", help="Limit the number of yara rules printed. "
                                                        "This has no effect on the YARAify API call itself.")
):
    c, ec = Console(), Console(stderr=True)
    config = Config.get_instance()
    yaraify = Yaraify(config.yaraify.api_key, config.yaraify.malpedia_key)
    try:
        with Status("Loading most recent yara rules..."):
            data = yaraify.query_recent_yara()
    except (requests.ConnectionError, requests.ConnectTimeout):
        ec.print("[bold red]Could not connect to YARAify API.[/bold red]")
        raise Exit(-1)

    if data["query_status"] != "ok":
        ec.print(f"[bold red]API returned with an error: {data['query_status']}[/bold red]")
        raise Exit(-1)

    if json:
        c.print(dumps(data, indent=4))
    else:
        data = data["data"]
        rules = [YaraRule(**r) for r in data]
        if limit:
            rules = rules[:limit]
        if csv:
            yara_csv_output(rules, c)
        else:
            for idx, r in enumerate(rules):
                if simple:
                    if r.rule_name == "classified":
                        rn = format_none("classified")
                    else:
                        rn = r.rule_name
                    if r.yarahub_author_twitter != "classified":
                        author = f"[deep_sky_blue1]{r.yarahub_author_twitter}[/deep_sky_blue1]"
                    else:
                        author = format_none("classified")
                    c.print(f"{rn} [{author}] ({r.yarahub_uuid})")
                else:
                    c.print(f"{idx + 1}/{len(rules)}")
                    print_yararule_table(r, c)
                    c.print()


@yaraify_app.command(name="get", help="Fetch a Yara rule by its UUID.")
def get_rule(
        uuid: str = Argument(..., help="YARAhub UUID."),
        filename: str = Argument(None, help="Filename to write Yara rule into.")
):
    c, ec = Console(), Console(stderr=True)
    config = Config.get_instance()
    yaraify = Yaraify(config.yaraify.api_key, config.yaraify.malpedia_key)
    try:
        with Status(f"Loading Yara rule {uuid}..."):
            rule = yaraify.download_yara(uuid)
    except (requests.ConnectionError, requests.ConnectTimeout):
        ec.print("[bold red]Could not connect to YARAify API.[/bold red]")
        raise Exit(-1)

    if rule[0] == "{":
        data = json.loads(rule)
        if data["query_status"] == "error":
            ec.print(f"[bold red]{data['data']}[/bold red]")
            raise Exit(-1)
        else:
            ec.print(f"Unknown JSON returned:")
            ec.print(data)
            raise Exit(-1)
    c.print(rule)
    if filename:
        with io.open(filename, "w") as fh:
            fh.write(rule)


@yaraify_app.command(name="download", help="Download (and optionally unzip) all TLP:CLEAR YARAify rules.")
def download_rules(
        unzip: bool = Option(False, "-u", "--unzip", help="Unzip the downloaded archive of rules"),
        filename: str = Argument(None, help="Optional filename.")
):
    c, ec = Console(), Console(stderr=True)
    if not filename:
        filename = "yaraify-rules.zip"
    try:
        with Status("Downloading rules...") as status:
            response = requests.get(Yaraify.ROOTURL + "download/yaraify-rules.zip", stream=True)
            if response.status_code != 200:
                ec.print(f"[bold red]Unexpected HTTP status code: {response.status_code}")
                raise Exit(-1)
            for chunk in response.iter_content(chunk_size=1024 ** 2):
                with io.open(filename, "wb") as fh:
                    fh.write(chunk)
            if unzip:
                status.update(status="Unzipping rules...")
                os.mkdir("yaraify-rules")
                zf = zipfile.ZipFile(filename)
                if not os.path.exists("yaraify-rules"):
                    ec.print("[bold red]Could not create directory \"yaraify-rules\".")
                    raise Exit(-1)
                zf.extractall("yaraify-rules")
                os.remove(filename)
    except (requests.ConnectionError, requests.ConnectTimeout):
        ec.print("[bold red]Could not connect to YARAify API.[/bold red]")
        raise Exit(-1)

    if unzip:
        listing = os.listdir("yaraify-rules")
        c.print(f"Downloaded {len(listing)} Yara rules.")
    else:
        c.print(f"Downloaded rule archive to {filename}.")


@yaraify_app.command(name="task", help="Fetch task results by task UUID.")
def get_task(
        json: bool = Option(False, "-j", "--json", help="Output raw JSON response."),
        uuid: str = Argument(..., help="Task (UU)ID.")
):
    c, ec = Console(), Console(stderr=True)
    config = Config.get_instance()
    yaraify = Yaraify(config.yaraify.api_key, config.yaraify.malpedia_key)
    try:
        with Status(f"Query YARAify API for task {uuid}..."):
            data = yaraify.query_task(uuid)
    except (requests.ConnectionError, requests.ConnectTimeout):
        ec.print("[bold red]Could not connect to YARAify API.[/bold red]")
        raise Exit(-1)

    if data["query_status"] != "ok":
        ec.print(f"[bold red]API returned with an error: {data['query_status']}[/bold red]")
        raise Exit(-1)

    if json:
        c.print(dumps(data, indent=4))
    else:
        data = data["data"]
        if isinstance(data, str):
            if data == "queued":
                ec.print(f"[yellow]Task is currently queued.[/yellow]")
                raise Exit(0)
            else:
                ec.print(f"[bold red]API returned an unexpected string: {data}.")
                raise Exit(-1)
        task = Task(**data)
        print_task_table(task, c)


@yaraify_app.command(name="version", help="Print and check YARAify version.")
def version(
        check: bool = Option(False, "-c", "--check", help="Check if you're using the latest version via Github API.")
):
    check_version(check)


if __name__ == "__main__":
    yaraify_app()
