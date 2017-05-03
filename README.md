# ms-offcrypto-tool

[![Build Status](https://travis-ci.org/nolze/ms-offcrypto-tool.svg?branch=master)](https://travis-ci.org/nolze/ms-offcrypto-tool)

ms-offcrypto-tool decrypts encrypted MS Office files with its intermediate key (secretKey) or the private key generated its escrow key.

## References

* "Backdooring MS Office documents with secret master keys" <http://secuinside.com/archive/2015/2015-1-9.pdf>
* [MS-OFFCRYPTO] Agile Encryption <https://msdn.microsoft.com/en-us/library/dd949735(v=office.12).aspx>

## Examples

~~~
python ms_offcrypto_tool.py -k AE8C36E68B4BB9EA46E5544A5FDB6693875B2FDE1507CBC65C8BCF99E25C2562 encrypted.pptx decrypted.pptx
~~~

~~~
python ms_offcrypto_tool.py -s priv.pem encrypted.docx decrypted.docx
~~~

## Todo

* Add tests
* Support decryption with passwords
* Merge to more comprehensive projects handling MS Office files (such as oletools?) if possible
