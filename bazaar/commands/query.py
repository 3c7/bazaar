import os

import click
from requests import Session
from rich.status import Status

from bazaar import BASEURL
from bazaar.output import *
from bazaar.util import Sample

ALLOWED_TYPES = [
    "hash",
    "imphash"
]


@click.command()
@click.option("-k", "--key", type=str, help="API key used for bazaar API (default BAZAAR_KEY env).")
@click.option("-j", "--json", is_flag=True, help="Write JSON response to stdout.")
@click.option("-c", "--csv", is_flag=True, help="Convert output to CSV.")
@click.argument("query_type", type=click.Choice(ALLOWED_TYPES, case_sensitive=False))
@click.argument("query", type=str)
def query(key, json, csv, query_type, query):
    c, ec = Console(), Console(stderr=True, style="bold red")
    session = Session()
    if not key:
        key = os.getenv("BAZAAR_KEY", None)

    if not key:
        ec.print("No API key given. Please use -k/--key option or provide BAZAAR_KEY env.")
        exit(-1)

    session.headers.update({
        "API-KEY": key
    })

    with Status("Querying Bazaar..."):
        if query_type.lower() == "hash":
            res = session.post(BASEURL, data={
                "query": "get_info",
                "hash": query
            })
        elif query_type.lower() == "imphash":
            res = session.post(BASEURL, data={
                "query": "get_imphash",
                "imphash": query
            })
    if res.status_code != 200:
        ec.print(f"Bazaar response was HTTP {res.status_code}: {res.text}")
        exit(-1)
    res = res.json()
    if not "data" in res:
        ec.print(f"Bazaar reponse was likely an error message: {res}")
        exit(-1)
    if json:
        c.print(res)
    elif csv:
        samples = [Sample(**sample) for sample in res["data"]]
        c.print("md5,sha1,sha256,imphash,signature")
        for s in samples:
            c.print(f"{s.md5_hash},{s.sha1_hash},{s.sha256_hash},{s.imphash},{s.signature}")
    else:
        samples = [Sample(**sample) for sample in res["data"]]
        multiple_samples(samples, c)
