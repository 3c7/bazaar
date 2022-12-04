from typing import Optional, Dict

from requests import Session


class Yaraify:
    ROOTURL = "https://yaraify-api.abuse.ch/"
    BASEURL = ROOTURL + "api/v1/"

    def __init__(self, api_key: str, malpedia_key: str = None):
        self.session = Session()
        self.session.headers.update({
            "API-KEY": api_key
        })
        self.malpedia_key = malpedia_key

    def _api_request(self, **kwargs):
        return self.session.post(
            self.BASEURL, json=kwargs
        ).json()

    def query_hash(self, hash: str) -> Dict:
        return self._api_request(
            **{
                "query": "lookup_hash",
                "search_term": hash,
                "malpedia-token": self.malpedia_key
            }
        )

    def query_yara_rule(self, yara_rule: str, limit: Optional[int] = 25) -> Dict:
        return self._api_request(
            **{
                "query": "get_yara",
                "search_term": yara_rule,
                "result_max": limit
            }
        )

    def query_clamav_signature(self, clamav_sig: str, limit: Optional[int] = 25) -> Dict:
        return self._api_request(
            **{
                "query": "get_clamav",
                "search_term": clamav_sig,
                "result_max": limit
            }
        )

    def query_imphash(self, impash: str, limit: Optional[int] = 25) -> Dict:
        return self._api_request(
            **{
                "query": "get_imphash",
                "search_term": impash,
                "result_max": limit
            }
        )

    def query_gimphash(self, gimphash: str, limit: Optional[int] = 100) -> Dict:
        return self._api_request(
            **{
                "query": "get_gimphash",
                "search_term": gimphash,
                "result_max": limit
            }
        )

    def query_icon_dhash(self, icon_dhash: str, limit: Optional[int] = 100) -> Dict:
        return self._api_request(
            **{
                "query": "get_dhash_icon",
                "search_term": icon_dhash,
                "result_max": limit
            }
        )

    def query_tlsh(self, tlsh: str, limit: Optional[int] = 100) -> Dict:
        return self._api_request(
            **{
                "query": "get_tlsh",
                "search_term": tlsh,
                "result_max": limit
            }
        )

    def query_telfhash(self, telfhash: str, limit: Optional[int] = 100) -> Dict:
        return self._api_request(
            **{
                "query": "get_telfhash",
                "search_term": telfhash,
                "result_max": limit
            }
        )

    def query_recent_yara(self) -> Dict:
        return self._api_request(
            **{
                "query": "recent_yararules"
            }
        )

    def query_task(self, task_uuid: str) -> Dict:
        return self._api_request(
            **{
                "query": "get_results",
                "task_id": task_uuid,
                "malpedia-token": self.malpedia_key
            }
        )

    def download_yara(self, rule_uuid: str):
        return self.session.post(
            self.BASEURL, json={"query": "get_yara_rule", "uuid": rule_uuid}
        ).text

    def download_file(self, sha256_hash) -> bytes:
        return self.session.post(
            self.BASEURL, json={"query": "get_file", "sha256_hash": sha256_hash}
        ).content
