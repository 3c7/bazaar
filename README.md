# malwarebazaar
**A [MalwareBazaar](https://bazaar.abuse.ch) and [YARAify](https://yaraify.abuse.ch) API wrapper and CLI**

This python module provides a Python API for MalwareBazaar as well as YARAify which can be used very easy to
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

Optionally, this module provides a CLI for both services, too:

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
from malwarebazaar import Bazaar, Yaraify
from malwarebazaar.models import Sample, YaraRule

b = Bazaar(
    api_key="myapikey"
)
y = Yaraify(
    api_key="myapikey"
)
response = b.query_recent()
samples = [Sample(**sample_dict) for sample_dict in response["data"]]
file_content = b.download_file(samples[0].sha256_hash)  # or response["data"][0]["sha256_hash"]

response = y.query_recent_yara()
yaras = [YaraRule(**yara_dict) for yara_dict in response["data"]]
for yara in yaras:
    if yara.rule_name != "classified":
        rule = y.download_yara(yara.yarahub_uuid)
        print(rule)
        break
```

There is no dedicated API documentation, however, the function names are pretty self-explanatory and you can just take
a look at the respective API functions here:

- Bazaar: [bazaar.py](malwarebazaar/api/bazaar.py)
- YARAify: [yaraify.py](malwarebazaar/api/yaraify.py)

### CLI

This module provides two CLI commands: `bazaar` and `yaraify`.
They use the same configuration file and must be initialized with the specific API key before they can be used.
Optionally, auto-completion can be installed for your shell via `bazaar --install-completion <shell>` (same for
`yaraify`).

#### `bazaar` example
```text
$ bazaar init myapikey
Successfully set API-Key!
$ bazaar query hash f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
                ╷                                                                                
  Filename      │ 03891ab57eb301579005f62953dfd21e.exe                                           
  Filesize      │ 21504 bytes                                                                    
  Filetype      │ application/x-dosexec                                                          
  Sightings     │ First-Seen: 2021-06-04 07:22:18                                                
                │ Last-Seen:  None                                                               
                │ Sightings:  None                                                               
  Hashes        │ MD5:        03891ab57eb301579005f62953dfd21e                                   
                │ SHA1:       41efd56ea49b72c6dd53b5341f295e549b1b64a5                           
                │ SHA256:     f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807   
                │ SHA3-384:                                                                      
                │ 72399548d0b0c9c679b3c492bef7f5df38f24e772d0897116b443937c16102fe2b9009aa2f2d0  
                │ b534ac7bfb710e4a394                                                            
                │ Icon Dhash: None                                                               
  Import Hashes │ Imphash:    f34d5f2d4577ed6d9ceec516c1f5a744                                   
                │ Gimphash:   None                                                               
                │ Telfhash:   None                                                               
  Fuzzy Hashes  │ Ssdeep:     384:/SkWXcoDeR7tojS+hsQjouy9lda2zEaNc5jPp:Acie1Cj9hsQDOXEr         
                │ Tlsh:                                                                          
                │ 04A2196433DCD671ECEB0B71AAB28644E6F5F4855802FB2B1AC481C759A3758CE32793         
                │                                                                                
  Signature     │ RedLineStealer                                                                 
  Tags          │ exe, RedLineStealer                                                            
                ╵                                                                                
             ╷            ╷               ╷                               
  ANY.RUN    │ No family  │ CERT-PL_MWDB  │ Undetected                    
             │ malicious  │               │                               
             │            │               │                               
  YOROI_YOMI │ suspicious │ vxCube        │ malicious                     
             │            │               │                               
  InQuest    │ malicious  │ CAPE          │ RedLine                       
             │            │               │                               
  Triage     │ redline    │ ReversingLabs │ ByteCode-MSIL.Trojan.Wacatac  
             │ malicious  │               │ malicious                     
             │            │               │                               
  UnpacMe    │ Undetected │               │                               
             │            │               │                               
             │            │               │                               
             ╵            ╵               ╵                               
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip: Zip archive data, at least v5.1 to extract
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807 --unzip
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
$ bazaar recent -s -l5
c2ae8ce5833306a5f311cf95a75271d9f25c037f177f935dff1d27b99b9af549 [Undetected] [@andretavare5] (exe)
b885520ef95e0c2159243d800bda652bd2b787098a9e1d29718a6e73b1204a36 [Undetected] [@andretavare5] (exe)
8b4fa170c0a68f07870823524579484ec7ba31b058ae80e23b8a29d3bfe96d84 [Undetected] [@andretavare5] (exe)
ed3d540886144d18a9f15c349cff1a89080dbb9e62ad224efbe83307af3171f2 [NanoCore] [@abuse_ch] (exe, NanoCore, RAT)
26507309b1d73937d7f62b28e9065e1fe94a74b3b293b263140370fa6cfa90f8 [Undetected] [@andretavare5] (exe)
```

#### `yaraify` example
```text
$ yaraify init myapikey --malpedia mymalpediaapikey
Successfully created config:
{"api_key": "bazaar_api_key", "yaraify": {"api_key": "myapikey", "mymalpediaapikey": 
"9664d7308cfbc0c33f509d28afc8145e2580ad36", "csv_columns": {"rule_name": "rule_name", "author": "author", "uuid": "yarahub_uuid"}}, 
"csv_columns": {"md5": "md5_hash", "sha1": "sha1_hash", "sha256": "sha256_hash", "imphash": "imphash", "signature": "signature", "tags": "tags"}}
$ yaraify query hash 7a6fcc2f0115c73bc66e9eacf74af4e5c11b06d600fd2038a289d5ee2163d459
Sample 1/1
                ╷                                                                                
  Filename      │ None                                                                           
  Filesize      │ 2691072 bytes                                                                  
  Filetype      │ application/x-dosexec                                                          
  Sightings     │ First-Seen: 2022-12-22 11:35:25                                                
                │ Last-Seen:  None                                                               
                │ Sightings:  1                                                                  
  Hashes        │ MD5:        6ae5d1343e41801bf5a501055f43818d                                   
                │ SHA1:       18d068b535785ec16d56c0f421addb35232fe377                           
                │ SHA256:     7a6fcc2f0115c73bc66e9eacf74af4e5c11b06d600fd2038a289d5ee2163d459   
                │ SHA3-384:                                                                      
                │ cc7dab7054f50e9bdcef92d4bdfbc2b27bcca1ea025f2d340703083ae819a2c6e312c20317804  
                │ 078a4ce124e91f74a64                                                            
                │ Icon Dhash: None                                                               
  Import Hashes │ Imphash:    5c7397fd7c1832e37a3cb00b6ee7c377                                   
                │ Gimphash:   None                                                               
                │ Telfhash:   None                                                               
  Fuzzy Hashes  │ Ssdeep:                                                                        
                │ 49152:NWrMtlmeF2RBzD8CSkkZA2loXISPEB8ClDl1mZDdeP7RWUOIQ:aMtlmeF2RBz1SkkZAKWIS  
                │ YFgDoPl8IQ                                                                     
                │ Tlsh:                                                                          
                │ T14EC5AE83B7C690F1DB963030051F976EEA7DBE285C749607B3A13A6F69302016B2D79D       
                │                                                                                
                ╵                                                                                
Task 1/1
                     ╷                                                 
  Task ID            │ ba3f2653-81ec-11ed-a7d0-42010aa4000b            
  YARAify Parameters │ ClamAV ✔ Unpack ✖ Share ✔                       
  Detections         │ Clam-AV:     No Clam-AV results                 
                     │ Name:        BitcoinAddress                     
                     │ Author:      Didier Stevens (@DidierStevens)    
                     │ Description: Contains a valid Bitcoin address   
                     │ TLP:         WHITE                              
                     │                                                 
                     │ Name:        malware_shellcode_hash             
                     │ Author:      JPCERT/CC Incident Response Group  
                     │ Description: detect shellcode api hash value    
                     │ TLP:         WHITE                              
                     │                                                 
                     │ Name:        meth_get_eip                       
                     │ Author:      Willi Ballenthin                   
                     │ Description: No description provided.           
                     │ TLP:         WHITE                              
                     │                                                 
                     │ Name:        pdb_YARAify                        
                     │ Author:      @wowabiy314                        
                     │ Description: PDB                                
                     │ TLP:         WHITE                              
                     │                                                 
                     ╵                             
$ yaraify recent -s -l 5
classified [classified] (4e00e916-1b7a-4020-b64a-701ff3390ca9)
classified [classified] (8f965345-b8d2-4a55-a9c3-2ff23a03ed1e)
win_aurora_stealer_a_706a [@viql] (706a5977-69fb-44ae-bfa7-f61e214148e7)
classified [classified] (5d5e97ac-33f7-4823-9534-ca969d135556)
win_phorpiex_a_84fc [@viql] (84fc2940-d204-4d75-9f17-89cce6b1dea2)
$ yaraify get 706a5977-69fb-44ae-bfa7-f61e214148e7
rule win_aurora_stealer_a_706a {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-14"
        description               = "detects Aurora Stealer samples"
        hash1_md5                 = "51c153501e991f6ce4901e6d9578d0c8"
        hash1_sha1                = "3816f17052b28603855bde3e57db77a8455bdea4"
        hash1_sha256              = "c148c449e1f6c4c53a7278090453d935d1ab71c3e8b69511f98993b6057f612d"
        hash2_md5                 = "65692e1d5b98225dbfb1b6b2b8935689"
        hash2_sha1                = "0b51765c175954c9e47c39309e020bcb0f90b783"
        hash2_sha256              = "5a42aa4fc8180c7489ce54d7a43f19d49136bd15ed7decf81f6e9e638bdaee2b"
        malpedia_family           = "win.aurora_stealer"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "51c153501e991f6ce4901e6d9578d0c8"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "706a5977-69fb-44ae-bfa7-f61e214148e7"

    strings:

        $str_func_01 = "main.(*DATA_BLOB).ToByteArray"
        $str_func_02 = "main.Base64Encode"
        $str_func_03 = "main.Capture"
        $str_func_04 = "main.CaptureRect"
        $str_func_05 = "main.ConnectToServer"
        $str_func_06 = "main.CreateImage"
        $str_func_07 = "main.FileExsist"
        $str_func_08 = "main.GetDisplayBounds"
        $str_func_09 = "main.GetInfoUser"
        $str_func_10 = "main.GetOS"
        $str_func_11 = "main.Grab"
        $str_func_12 = "main.MachineID"
        $str_func_13 = "main.NewBlob"
        $str_func_14 = "main.NumActiveDisplays"
        $str_func_15 = "main.PathTrans"
        $str_func_16 = "main.SendToServer_NEW"
        $str_func_17 = "main.SetUsermame"
        $str_func_18 = "main.Zip"
        $str_func_19 = "main.base64Decode"
        $str_func_20 = "main.countupMonitorCallback"
        $str_func_21 = "main.enumDisplayMonitors"
        $str_func_22 = "main.getCPU"
        $str_func_23 = "main.getDesktopWindow"
        $str_func_24 = "main.getGPU"
        $str_func_25 = "main.getMasterKey"
        $str_func_26 = "main.getMonitorBoundsCallback"
        $str_func_27 = "main.getMonitorRealSize"
        $str_func_28 = "main.sysTotalMemory"
        $str_func_29 = "main.xDecrypt"

        $str_type_01 = "type..eq.main.Browser_G"
        $str_type_02 = "type..eq.main.STRUSER"
        $str_type_03 = "type..eq.main.Telegram_G"
        $str_type_04 = "type..eq.main.Crypto_G"
        $str_type_05 = "type..eq.main.ScreenShot_G"
        $str_type_06 = "type..eq.main.FileGrabber_G"
        $str_type_07 = "type..eq.main.FTP_G"
        $str_type_08 = "type..eq.main.Steam_G"
        $str_type_09 = "type..eq.main.DATA_BLOB"
        $str_type_10 = "type..eq.main.Grabber"

        $varia_01 = "\\User Data\\Local State"
        $varia_02 = "\\\\Opera Stable\\\\Local State"
        $varia_03 = "Reconnect 1"
        $varia_04 = "@ftmone"
        $varia_05 = "^user^"
        $varia_06 = "wmic path win32_VideoController get name"
        $varia_07 = "\\AppData\\Roaming\\Telegram Desktop\\tdata"
        $varia_08 = "C:\\Windows.old\\Users\\"
        $varia_09 = "ScreenShot"
        $varia_10 = "Crypto"

    condition:
        uint16(0) == 0x5A4D and
        (
            32 of ($str_*) or
            9 of ($varia_*)
        )
}
```
