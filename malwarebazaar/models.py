from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, validator


class Sample(BaseModel):
    """Just a simple dictionary wrapper."""
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    sha3_384_hash: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    file_name: Optional[str]
    file_size: int
    file_type_mime: Optional[str]
    file_type: Optional[str]
    signature: Optional[str]
    tags: Optional[List[str]]
    imphash: Optional[str]
    gimphash: Optional[str]
    dhash_icon: Optional[str]
    reporter: Optional[str]
    telfhash: Optional[str]
    tlsh: Optional[str]
    origin_country: Optional[str]
    anonymous: Optional[bool]
    ssdeep: Optional[str]
    sightings: Optional[int]
    vendor_intel: Optional[Dict[Any, Any]]

    def __init__(self, **data):
        tasks = None
        if "metadata" in data:
            tasks = data["tasks"]
            data = data["metadata"]
        super().__init__(
            sha3_384_hash=data.pop("sha3_384", None) or data.pop("sha3_384_hash", None),
            **data
        )

    @validator("first_seen", pre=True)
    def validate_fs(cls, value):
        if not value:
            return value
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC")

    @validator("last_seen", pre=True)
    def validate_ls(cls, value):
        if not value:
            return value
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC")


class YaraRule(BaseModel):
    time_stamp: Optional[datetime]
    rule_name: Optional[str]
    author: Optional[str]
    description: Optional[str]
    date: Optional[str]
    tlp: Optional[str]
    reference: Optional[str]
    yarahub_uuid: Optional[str]
    yarahub_license: Optional[str]
    yarahub_author_twitter: Optional[str]
    yarahub_reference_link: Optional[str]
    yarahub_reference_md5: Optional[str]
    yarahub_rule_matching_tlp: Optional[str]
    yarahub_rule_sharing_tlp: Optional[str]
    malpedia_family: Optional[str]

    @validator("time_stamp", pre=True)
    def validate_ts(cls, value):
        if not value:
            return value
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC")


class UnpackResult(BaseModel):
    unpacked_file_name: Optional[str]
    unpacked_md5: Optional[str]
    unpacked_sha256: Optional[str]
    unpacked_yara_matches: Optional[List[YaraRule]]


class Task(BaseModel):
    task_id: Optional[str]
    clamav_scan: Optional[bool]
    unpack: Optional[bool]
    share_file: Optional[bool]
    metadata: Optional[Sample]
    static_results: Optional[List[YaraRule]]
    clamav_results: Optional[List[str]]
    unpacked_results: Optional[List[UnpackResult]]

    def __init__(self, **data):
        params = data.pop("task_parameters", {})
        unpacked_results = data.pop("unpacked_results", [])
        if len(unpacked_results) == 0:
            unpacked_results = data.pop("unpack_results", [])

        super().__init__(**data, **params, unpacked_results=unpacked_results)
