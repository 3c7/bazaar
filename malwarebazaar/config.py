import io
import os
from pathlib import Path
from sys import exit
from typing import Optional, OrderedDict, Union

import yaml
from pydantic import BaseModel
from rich.console import Console

from malwarebazaar.platform import get_config_path, get_config_dir


class YARAifyConfig(BaseModel):
    api_key: Optional[str]
    malpedia_key: Optional[str]
    csv_columns: Optional[OrderedDict]


class Config(BaseModel):
    api_key: Optional[str]
    yaraify: Optional[YARAifyConfig]
    csv_columns: Optional[OrderedDict[str, str]]

    @staticmethod
    def get_instance():
        return Config.from_yaml(get_config_path())

    @staticmethod
    def exists() -> bool:
        return get_config_path().exists()

    @staticmethod
    def from_yaml(yaml_path: Union[str, Path]):
        with io.open(yaml_path, "r") as fh:
            data = yaml.load(fh.read(), Loader=yaml.Loader)

        return Config(**data)

    def to_yaml(self) -> str:
        return yaml.dump(self.dict(), Dumper=yaml.Dumper, sort_keys=False)

    def save_config(self) -> bool:
        data = self.to_yaml()
        with io.open(get_config_path(), "w") as fh:
            amount_bytes = fh.write(data)
        return amount_bytes > 0

    @staticmethod
    def ensure_path(ec: Console = Console(stderr=True, style="bold red")):
        config_dir = get_config_dir()

        if not os.path.exists(config_dir):
            os.mkdir(config_dir)

        if not os.path.isdir(config_dir):
            ec.print(f"{config_dir} should be a dir, but is a file.")
            exit(-1)

    @staticmethod
    def init_config(key: Union[str, None], yaraify_key: Union[str, None] = None, malpedia_key: Union[str, None] = None):
        Config.ensure_path()
        config = Config(
            api_key=key,
            yaraify=YARAifyConfig(
                api_key=yaraify_key,
                malpedia_key=malpedia_key,
                csv_colums={
                    "rule_name": "rule_name",
                    "author": "author",
                    "uuid": "yarahub_uuid"
                }
            ),
            csv_columns={
                "md5": "md5_hash",
                "sha1": "sha1_hash",
                "sha256": "sha256_hash",
                "imphash": "imphash",
                "signature": "signature",
                "tags": "tags"
            }
        )
        if not config.save_config():
            raise IOError(f"Writing to config file failed.")
        return True
