class Sample(dict):
    """Just a simple dictionary wrapper."""
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    imphash: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __getattr__(self, item):
        return self[item.lower()]

    def __setattr__(self, key, value):
        self[key.lower()] = value
