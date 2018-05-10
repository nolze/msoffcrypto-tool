# msoffcrypto-tool

[![Build Status](https://travis-ci.org/nolze/msoffcrypto-tool.svg?branch=master)](https://travis-ci.org/nolze/msoffcrypto-tool)

msoffcrypto-tool (formerly ms-offcrypto-tool) is a Python tool and library for decrypting encrypted MS Office files with password, intermediate key, or private key which generated its escrow key.

Older PoC version: <https://github.com/nolze/ms-offcrypto-tool/tree/v0.1.0> 

## Install/Uninstall

#### Install

```
pip install git+https://github.com/nolze/msoffcrypto-tool
```

#### Uninstall

```
pip uninstall msoffcrypto-tool
```

## Examples

### Password

```
msoffcrypto-tool -P Passw0rd encrypted.docx decrypted.docx
```

### Private key

```
msoffcrypto-tool -p priv.pem encrypted.docx decrypted.docx
```

### Intermediate key (secretKey)

```
msoffcrypto-tool -k AE8C36E68B4BB9EA46E5544A5FDB6693875B2FDE1507CBC65C8BCF99E25C2562 encrypted.pptx decrypted.pptx
```

### As a library

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

## Supported methods

* [x] ECMA-376
  * [x] MS-DOCX (OOXML) (Word 2007-2016)
  * [x] MS-XLSX (OOXML) (Excel 2007-2016)
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
* [ ] Upload to PyPI
* [ ] Merge to more comprehensive projects handling MS Office files (such as oletools?) if possible

## References

* "Backdooring MS Office documents with secret master keys" <http://secuinside.com/archive/2015/2015-1-9.pdf>
* [MS-OFFCRYPTO] Agile Encryption <https://msdn.microsoft.com/en-us/library/dd949735(v=office.12).aspx>
* LibreOffice/core <https://github.com/LibreOffice/core>
* LibreOffice/mso-dumper <https://github.com/LibreOffice/mso-dumper>

## Alternatives

* herumi/msoffice <https://github.com/herumi/msoffice>
* DocRecrypt <https://blogs.technet.microsoft.com/office_resource_kit/2013/01/23/now-you-can-reset-or-remove-a-password-from-a-word-excel-or-powerpoint-filewith-office-2013/>
