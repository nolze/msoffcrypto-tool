# ms-offcrypto-tool

[![Build Status](https://travis-ci.org/nolze/ms-offcrypto-tool.svg?branch=master)](https://travis-ci.org/nolze/ms-offcrypto-tool)

ms-offcrypto-tool is a Python tool and library for decrypting encrypted MS Office files with the password, or with the intermediate key (secretKey), or with the private key which generated its escrow key.

## Examples

### Password

~~~
python ms_offcrypto_tool.py -P Passw0rd encrypted.docx decrypted.docx
~~~

### Private key

~~~
python ms_offcrypto_tool.py -p priv.pem encrypted.docx decrypted.docx
~~~

### Intermediate key (secretKey)

~~~
python ms_offcrypto_tool.py -k AE8C36E68B4BB9EA46E5544A5FDB6693875B2FDE1507CBC65C8BCF99E25C2562 encrypted.pptx decrypted.pptx
~~~

## Todo

* [x] Add tests
* [x] Support decryption with passwords
* [ ] Merge to more comprehensive projects handling MS Office files (such as oletools?) if possible
* [ ] Support older encryption schemes

## References

* "Backdooring MS Office documents with secret master keys" <http://secuinside.com/archive/2015/2015-1-9.pdf>
* [MS-OFFCRYPTO] Agile Encryption <https://msdn.microsoft.com/en-us/library/dd949735(v=office.12).aspx>

## Alternatives

* herumi/msoffice <https://github.com/herumi/msoffice>
* DocRecrypt <https://blogs.technet.microsoft.com/office_resource_kit/2013/01/23/now-you-can-reset-or-remove-a-password-from-a-word-excel-or-powerpoint-filewith-office-2013/>
