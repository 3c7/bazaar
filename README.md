# (Malware)Bazaar
**A [MalwareBazaar](https://bazaar.abuse.ch) API wrapper and CLI**

## Installation
```
pip install malwarebazaar
```
~~or, for pure cli usage, you can grab one of the [prebuilt binaries](https://github.com/3c7/bazaar/releases/)~~.

The creation of prebuilt binaries was removed in v0.1.5.

## Usage
### Python
```python
from malwarebazaar.api import Bazaar

bazaar = Bazaar("myapikey")
response = bazaar.query_hash("Hash to search for.")
file = bazaar.download_file("Sha256 hash for file to donwload.")
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