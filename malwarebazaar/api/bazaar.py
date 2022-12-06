from typing import Optional, Dict, Union, Text

from requests import Session


class Bazaar:
    def __init__(self, api_key: str):
        self.session = Session()
        self.session.headers.update({"API-KEY": api_key})
        self.baseurl = "https://mb-api.abuse.ch/api/v1/"

    def query_hash(self, hash: str) -> Dict:
        return self.session.post(
            self.baseurl, data={"query": "get_info", "hash": hash}
        ).json()

    def query_tag(self, tag: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl, data={"query": "get_taginfo", "tag": tag, "limit": limit}
        ).json()

    def query_signature(self, signature: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_siginfo", "signature": signature, "limit": limit},
        ).json()

    def query_filetype(self, filetype: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_file_type", "file_type": filetype, "limit": limit},
        ).json()

    def query_clamav_signature(
            self, clamav_sig: str, limit: Optional[int] = 100
    ) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_clamavinfo", "clamav": clamav_sig, "limit": limit},
        ).json()

    def query_imphash(self, impash: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_imphash", "imphash": impash, "limit": limit},
        ).json()

    def query_gimphash(self, gimphash: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_gimphash", "gimphash": gimphash, "limit": limit}
        ).json()

    def query_icon_dhash(self, icon_dhash: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_dhash_icon", "dhash_icon": icon_dhash, "limit": limit}
        ).json()

    def query_tlsh(self, tlsh: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl, data={"query": "get_tlsh", "tlsh": tlsh, "limit": limit}
        ).json()

    def query_telfhash(self, telfhash: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_telfhash", "telfhash": telfhash, "limit": limit},
        ).json()

    def query_yara(self, rule_name: str, limit: Optional[int] = 100) -> Dict:
        return self.session.post(
            self.baseurl,
            data={"query": "get_yarainfo", "yara_rule": rule_name, "limit": limit},
        ).json()

    def query_signing_issuer(self, common_name: str) -> Dict:
        return self.session.post(
            self.baseurl, data={"query": "get_issuerinfo", "issuer_cn": common_name}
        ).json()

    def query_signing_subject(self, common_name: str) -> Dict:
        return self.session.post(
            self.baseurl, data={"query": "get_subjectinfo", "subject_cn": common_name}
        ).json()

    def query_recent(self, last_100_samples: bool = False) -> Dict:
        """According to the API documentation (https://bazaar.abuse.ch/api/#latest_additions) the selector can only be
        "time" or "100"."""
        if last_100_samples:
            query_selector = {"selector": "100"}
        else:
            query_selector = {"selector": "time"}
        return self.session.post(
            self.baseurl, data={"query": "get_recent", **query_selector}
        ).json()

    def download_file(self, sha256_hash) -> bytes:
        return self.session.post(
            self.baseurl, data={"query": "get_file", "sha256_hash": sha256_hash}
        ).content
