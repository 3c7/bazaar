from typing import Optional, Dict, Union

from requests import Session
from sys import stderr


class Bazaar:
    def __init__(self, key: str):
        self.session = Session()
        self.session.headers.update({
            "API-KEY": key
        })
        self.baseurl = "https://mb-api.abuse.ch/api/v1/"

    def query_hash(self, hash: str) -> Dict:
        return self.session.post(self.baseurl, data={"query": "get_info", "hash": hash}).json()

    def query_tag(self, tag: str, limit: Optional[int] = 50):
        return self.session.post(self.baseurl, data={"query": "get_taginfo", "tag": tag, "limit": limit}).json()

    def query_signature(self, signature: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_siginfo", "signature": signature, "limit": limit}).json()

    def query_filetype(self, filetype: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_file_type", "file_type": filetype, "limit": limit}).json()

    def query_clamav_signature(self, clamav_sig: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_clamavinfo", "clamav": clamav_sig, "limit": limit}).json()

    def query_imphash(self, impash: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_imphash", "imphash": impash, "limit": limit}).json()

    def query_tlsh(self, tlsh: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_tlsh", "tlsh": tlsh, "limit": limit}).json()

    def query_telfhash(self, telfhash: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_telfhash", "telfhash": telfhash, "limit": limit}).json()

    def query_yara(self, rule_name: str, limit: Optional[int] = 100):
        return self.session.post(self.baseurl, data={"query": "get_yarainfo", "yara_rule": rule_name, "limit": limit}).json()

    def query_signing_issuer(self, common_name: str):
        return self.session.post(self.baseurl, data={"query": "get_issuerinfo", "issuer_cn": common_name}).json()

    def query_signing_subject(self, common_name: str):
        return self.session.post(self.baseurl, data={"query": "get_subjectinfo", "subject_cn": common_name}).json()

    def query_recent(self, selector: Union[int, str] = "time"):
        if isinstance(selector, int):
            if selector != 100:
                print(f"As Bazaar only supports grabbing the last 100 samples, we're going to use 100 instead of {selector}.")
            selector = {"selector": 100}
        else:
            selector = {"selector": "time"}
        return self.session.post(self.baseurl, data={"query": "get_recent", **selector}).json()
