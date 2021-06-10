from typing import Optional, List

from rich.console import Console

from bazaar.util import Sample


def single_sample(s: Sample, console: Optional[Console] = Console()):
    console.print(f"MD5:\t\t{s.md5_hash}")
    console.print(f"SHA1:\t\t{s.sha1_hash}")
    console.print(f"SHA256:\t\t{s.sha256_hash}")
    console.print(f"Imphash:\t{s.imphash}")
    console.print(f"Signature:\t{s.signature}")
    console.print(f"Tags:\t\t{', '.join([tag for tag in s.tags])}")


def multiple_samples(samples: List[Sample], console: Optional[Console] = Console()):
    for sample in samples:
        single_sample(sample, console)
