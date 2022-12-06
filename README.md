# malwarebazaar
**A [MalwareBazaar](https://bazaar.abuse.ch) and [YARAify](https://yaraify.abuse.ch) API wrapper and CLI**

This python module includes Python API bindings for MalwareBazaar as well as YARAify which can be used very easy to
access both APIs:

```python
from malwarebazaar import Bazaar, Yaraify

b = Bazaar(
    api_key="my_api_key"
)
b.query_hash(...)

y = Yaraify(
    api_key="my_api_key",
    malpedia_key="optional_malpedia_api_key"
)
y.query_hash(...)
```

Additionally, for both services a cli client will be installed. They can be accessed using `bazaar` and `yaraify`
commands:

```text
$ bazaar --help

 Usage: bazaar [OPTIONS] COMMAND [ARGS]...                                                       
                                                                                                 
 Query MalwareBazaar from the command line!                                                      
                                                                                                 
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion        [bash|zsh|fish|powershell|pwsh]  Install completion for the       │
│                                                              specified shell.                 │
│                                                              [default: None]                  │
│ --show-completion           [bash|zsh|fish|powershell|pwsh]  Show completion for the          │
│                                                              specified shell, to copy it or   │
│                                                              customize the installation.      │
│                                                              [default: None]                  │
│ --help                                                       Show this message and exit.      │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────╮
│ batch    Download daily malware batches. The DATE_STR argument needs to be in the format of   │
│          YYYY-mm-dd.                                                                          │
│ init     Initialize bazaar config file.                                                       │
│ query    Query the MalwareBazaar API.                                                         │
│ recent   Get information about recently submitted samples. The API allows either the last 100 │
│          samples or samples uploaded in the last 60 minutes. As the amount is quite big, the  │
│          default output type is csv.                                                          │
│ version  Print and check bazaar version.                                                      │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
```

```text
$ yaraify --help

 Usage: yaraify [OPTIONS] COMMAND [ARGS]...                                                      
                                                                                                 
 Query YARAify from your command line!                                                           
                                                                                                 
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion        [bash|zsh|fish|powershell|pwsh]  Install completion for the       │
│                                                              specified shell.                 │
│                                                              [default: None]                  │
│ --show-completion           [bash|zsh|fish|powershell|pwsh]  Show completion for the          │
│                                                              specified shell, to copy it or   │
│                                                              customize the installation.      │
│                                                              [default: None]                  │
│ --help                                                       Show this message and exit.      │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────╮
│ download           Download all TLP:CLEAR YARAify rules.                                      │
│ get                Fetch Yara rule by its UUID                                                │
│ init               Initialize YARAify cli.                                                    │
│ query              Query the YARAify API.                                                     │
│ recent             Query for recent Yara rules.                                               │
│ task               Fetch task results                                                         │
│ version            Print and check yaraify version.                                           │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Installation
Usually, this module will be distributed via PyPI. If you want to use pre-release versions, check the release section of
this repository. If you don't intent to use the CLI, you do not need to install the "cli eye candy modules" and stick to
the pure Python API via:

```
pip install malwarebazaar
```

If you want to use the CLI, you need to include the `cli` extra:

```
pip install malwarebazaar[cli]
```

_**Note**: Previous versions also included pre-built binaries, however, I stopped adding them.
Please just use a local python environment instead._

## Usage

### Python API
```python
from malwarebazaar.api import Bazaar
from malwarebazaar.models import Sample

b = Bazaar(
    api_key="myapikey"
)
response = b.query_recent()
samples = [Sample(**sample_dict) for sample_dict in response["data"]]
file_content = b.download_file(samples[0].sha256_hash)  # or response["data"][0]["sha256_hash"]
```

### CLI
```commandline
$ bazaar init myapikey
Successfully set API-Key!
$ bazaar query hash f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
Filename:       03891ab57eb301579005f62953dfd21e.exe
MD5:            03891ab57eb301579005f62953dfd21e
SHA1:           41efd56ea49b72c6dd53b5341f295e549b1b64a5
SHA256:         f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
Imphash:        f34d5f2d4577ed6d9ceec516c1f5a744
Signature:      RedLineStealer
Tags:           exe, RedLineStealer
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip: Zip archive data, at least v5.1 to extract
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807 --unzip
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```