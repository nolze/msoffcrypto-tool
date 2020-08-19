# msoffcrypto-tool

[![PyPI version](https://badge.fury.io/py/msoffcrypto-tool.svg)](https://badge.fury.io/py/msoffcrypto-tool)
[![PyPI downloads](https://img.shields.io/pypi/dm/msoffcrypto-tool.svg)](https://pypistats.org/packages/msoffcrypto-tool)
[![Build Status](https://travis-ci.com/nolze/msoffcrypto-tool.svg?branch=master)](https://travis-ci.com/nolze/msoffcrypto-tool)
[![Coverage Status](https://codecov.io/gh/nolze/msoffcrypto-tool/branch/master/graph/badge.svg)](https://codecov.io/gh/nolze/msoffcrypto-tool)
[![Documentation Status](https://readthedocs.org/projects/msoffcrypto-tool/badge/?version=latest)](http://msoffcrypto-tool.readthedocs.io/en/latest/?badge=latest)

msoffcrypto-tool (formerly ms-offcrypto-tool) is a Python tool and library for decrypting encrypted MS Office files with password, intermediate key, or private key which generated its escrow key.

## Contents

* [Install](#install)
* [Examples](#examples)
* [Supported encryption methods](#supported-encryption-methods)
* [Tests](#tests)
* [Todo](#todo)
* [Resources](#resources)
* [Use cases and mentions](#use-cases-and-mentions)
* [Contributors](#contributors)

## Install

```
pip install msoffcrypto-tool
```

## Examples

### As CLI tool (with password)

```
msoffcrypto-tool encrypted.docx decrypted.docx -p Passw0rd
```

Password is prompted if you omit the password argument value:

```bash
$ msoffcrypto-tool encrypted.docx decrypted.docx -p
Password:
```

Test if the file is encrypted or not (exit code 0 or 1 is returned):

```
msoffcrypto-tool document.doc --test -v
```

### As library

Password and more key types are supported with library functions.

Basic usage:

```python
import msoffcrypto

file = msoffcrypto.OfficeFile(open("encrypted.docx", "rb"))

# Use password
file.load_key(password="Passw0rd")

file.decrypt(open("decrypted.docx", "wb"))
```

Basic usage (in-memory):

```python
import msoffcrypto
import io
import pandas as pd

file = msoffcrypto.OfficeFile(open("encrypted.xlsx", "rb"))

# Use password
file.load_key(password="Passw0rd")

decrypted = io.BytesIO()
file.decrypt(decrypted)

df = pd.read_excel(decrypted)
print(df)
```

Advanced usage:

```python
# Verify password before decryption (default: False)
# The ECMA-376 Agile/Standard crypto system allows one to know whether the supplied password is correct before actually decrypting the file
# Currently, the verify_password option is only meaningful for ECMA-376 Agile/Standard Encryption
file.load_key(password="Passw0rd", verify_password=True)

# Use private key
file.load_key(private_key=open("priv.pem", "rb"))

# Use intermediate key (secretKey)
file.load_key(secret_key=binascii.unhexlify("AE8C36E68B4BB9EA46E5544A5FDB6693875B2FDE1507CBC65C8BCF99E25C2562"))

# Check the HMAC of the data payload before decryption (default: False)
# Currently, the verify_integrity option is only meaningful for ECMA-376 Agile Encryption
file.decrypt(open("decrypted.docx", "wb"), verify_integrity=True)
```

## Supported encryption methods

### MS-OFFCRYPTO specs

* [x] ECMA-376 (Agile Encryption/Standard Encryption)
  * [x] MS-DOCX (OOXML) (Word 2007-2016)
  * [x] MS-XLSX (OOXML) (Excel 2007-2016)
  * [x] MS-PPTX (OOXML) (PowerPoint 2007-2016)
* [x] Office Binary Document RC4 CryptoAPI
  * [x] MS-DOC (Word 2002, 2003, 2004)
  * [x] MS-XLS (Excel 2002, 2003, 2004) (experimental)
  * [x] MS-PPT (PowerPoint 2002, 2003, 2004) (partial, experimental)
* [x] Office Binary Document RC4
  * [x] MS-DOC (Word 97, 98, 2000)
  * [x] MS-XLS (Excel 97, 98, 2000) (experimental)
* [ ] ECMA-376 (Extensible Encryption)
* [ ] XOR Obfuscation

### Other

* [ ] Word 95 Encryption (Word 95 and prior)
* [ ] Excel 95 Encryption (Excel 95 and prior)
* [ ] PowerPoint 95 Encryption (PowerPoint 95 and prior)

PRs are welcome!

## Tests

Tests can be run in various ways:

* `python -m nose -c .noserc`
* `nosetests -c .noserc`
* `python -m unittest discover`
* `python setup.py test`
* `./tests/test_cli.sh`

If the [cryptography](https://pypi.org/project/cryptography/) package is not installed, tests are skipped. If you have dependencies installed only for a certain python version, replace "python" with "pythonX.Y" in the above commands.

## Todo

* [x] Add tests
* [x] Support decryption with passwords
* [x] Support older encryption schemes
* [x] Add function-level tests
* [x] Add API documents
* [x] Publish to PyPI
* [x] Add decryption tests for various file formats
* [x] Integrate with more comprehensive projects handling MS Office files (such as [oletools](https://github.com/decalage2/oletools/)?) if possible
* [x] Add the password prompt mode for CLI
* [ ] Redesign APIs (v5.0.0)
* [ ] Improve error types (v5.0.0)
* [ ] Use a kind of `ctypes.Structure`
* [ ] Support encryption

## Resources

* "Backdooring MS Office documents with secret master keys" <http://secuinside.com/archive/2015/2015-1-9.pdf>
* Technical Documents <https://msdn.microsoft.com/en-us/library/cc313105.aspx>
  * [MS-OFFCRYPTO] Agile Encryption <https://msdn.microsoft.com/en-us/library/dd949735(v=office.12).aspx>
* LibreOffice/core <https://github.com/LibreOffice/core>
* LibreOffice/mso-dumper <https://github.com/LibreOffice/mso-dumper>
* wvDecrypt <http://www.skynet.ie/~caolan/Packages/wvDecrypt.html>
* Microsoft Office password protection - Wikipedia <https://en.wikipedia.org/wiki/Microsoft_Office_password_protection#History_of_Microsoft_Encryption_password>
* office2john.py <https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/office2john.py>

## Alternatives

* herumi/msoffice <https://github.com/herumi/msoffice>
* DocRecrypt <https://blogs.technet.microsoft.com/office_resource_kit/2013/01/23/now-you-can-reset-or-remove-a-password-from-a-word-excel-or-powerpoint-filewith-office-2013/>
* Apache POI - the Java API for Microsoft Documents <https://poi.apache.org/>

## Use cases and mentions

* <https://repology.org/project/python:msoffcrypto-tool/versions> (kudos to maintainers!)
* <https://github.com/jbremer/sflock/commit/3f6a96abe1dbb4405e4fb7fd0d16863f634b09fb>
* <https://github.com/dtjohnson/xlsx-populate>
* <https://github.com/shombo/cyberstakes-writeps-2018/tree/master/word_up>
* <https://isc.sans.edu/forums/diary/Video+Analyzing+Encrypted+Malicious+Office+Documents/24572/>
* <https://checkroth.com/unlocking-password-protected-files.html>

## Contributors

* <https://github.com/nolze/msoffcrypto-tool/graphs/contributors>
