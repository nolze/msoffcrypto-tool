# msoffcrypto-tool

[![PyPI version](https://badge.fury.io/py/msoffcrypto-tool.svg)](https://badge.fury.io/py/msoffcrypto-tool)
[![Build Status](https://travis-ci.org/nolze/msoffcrypto-tool.svg?branch=master)](https://travis-ci.org/nolze/msoffcrypto-tool)
[![Coverage Status](https://codecov.io/gh/nolze/msoffcrypto-tool/branch/master/graph/badge.svg)](https://codecov.io/gh/nolze/msoffcrypto-tool)
[![Documentation Status](https://readthedocs.org/projects/msoffcrypto-tool/badge/?version=latest)](http://msoffcrypto-tool.readthedocs.io/en/latest/?badge=latest)

msoffcrypto-tool (formerly ms-offcrypto-tool) is a Python tool and library for decrypting encrypted MS Office files with password, intermediate key, or private key which generated its escrow key.

Early PoC version: <https://github.com/nolze/ms-offcrypto-tool/tree/v0.1.0> 

## Install

```
pip install msoffcrypto-tool
```

## Examples

### As a CLI tool (with password)

```
msoffcrypto-tool -p Passw0rd encrypted.docx decrypted.docx
```

### As a library

Password and more key types are supported with library functions.

```python
import msoffcrypto

file = msoffcrypto.OfficeFile(open("encrypted.docx", "rb"))

# Use password
file.load_key(password="Passw0rd")

# Use private key
# file.load_key(private_key=open("priv.pem", "rb"))
# Use intermediate key (secretKey)
# file.load_key(secret_key=binascii.unhexlify("AE8C36E68B4BB9EA46E5544A5FDB6693875B2FDE1507CBC65C8BCF99E25C2562"))

file.decrypt(open("decrypted.docx", "wb"))
```

## Supported encryption methods

* [x] ECMA-376
  * [x] MS-DOCX (OOXML) (Word 2007-2016)
  * [x] MS-XLSX (OOXML) (Excel 2007-2016)
  * [x] MS-PPTX (OOXML) (PowerPoint 2007-2016)
* [x] Office Binary Document RC4
  * [x] MS-DOC (Word 97-2004)
  * [ ] MS-XLS (Excel 97-2004)
* [ ] Office Binary Document RC4 CryptoAPI
* [ ] XOR Obfuscation
* [ ] Word 95 Encryption

PRs welcome!

## Todo

* [x] Add tests
* [x] Support decryption with passwords
* [x] Support older encryption schemes
* [x] Add function-level tests
* [x] Add API documents
* [x] Publish to PyPI
* [ ] Add decryption tests for various file formats
* [ ] Merge to more comprehensive projects handling MS Office files (such as [oletools](https://github.com/decalage2/oletools/)?) if possible

## References

* "Backdooring MS Office documents with secret master keys" <http://secuinside.com/archive/2015/2015-1-9.pdf>
* [MS-OFFCRYPTO] Agile Encryption <https://msdn.microsoft.com/en-us/library/dd949735(v=office.12).aspx>
* LibreOffice/core <https://github.com/LibreOffice/core>
* LibreOffice/mso-dumper <https://github.com/LibreOffice/mso-dumper>
* wvDecrypt <http://www.skynet.ie/~caolan/Packages/wvDecrypt.html>

## Alternatives

* herumi/msoffice <https://github.com/herumi/msoffice>
* DocRecrypt <https://blogs.technet.microsoft.com/office_resource_kit/2013/01/23/now-you-can-reset-or-remove-a-password-from-a-word-excel-or-powerpoint-filewith-office-2013/>

## Use cases and mentions

* <https://github.com/jbremer/sflock/commit/3f6a96abe1dbb4405e4fb7fd0d16863f634b09fb>
* <https://github.com/dtjohnson/xlsx-populate>
