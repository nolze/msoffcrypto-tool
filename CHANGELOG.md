5.0.0 / 2022-01-20
==================

  * (dev) Add tests on Python 3.7 to 3.9 ([#71](https://github.com/nolze/msoffcrypto-tool/pull/71))
  * (dev) Track poetry.lock ([#71](https://github.com/nolze/msoffcrypto-tool/pull/71))
  * (BREAKING) Drop Python 2 support ([#71](https://github.com/nolze/msoffcrypto-tool/pull/71))
  * Raise exception if no encryption type is specified ([#70](https://github.com/nolze/msoffcrypto-tool/issues/70))
  * Support SHA256, SHA384 hash algorithm (@jackydo, [#67](https://github.com/nolze/msoffcrypto-tool/pull/67))
  * Fix errors for unencrypted documents
  * Use absolute imports ([#63](https://github.com/nolze/msoffcrypto-tool/pull/63))

4.12.0 / 2021-06-04
===================

  * Use custom exceptions ([#59](https://github.com/nolze/msoffcrypto-tool/pull/59))
  * (dev) Remove nose (thank you) ([#57](https://github.com/nolze/msoffcrypto-tool/pull/57))
  * (dev) Use poetry ([#55](https://github.com/nolze/msoffcrypto-tool/pull/55))

4.11.0 / 2020-09-03
===================

  * Improve hash calculation (suggested by @StanislavNikolov)
  * Add "verify\_passwd" and "verify\_integrity" option (@jeffli678)
  * Make _packUserEditAtom spec-compliant

4.10.2 / 2020-04-08
===================

  * Update \_makekey in rc4\_cryptoapi (@doracpphp)
  * Fix handling of optional field value in ppt97
  * Add tests for is_encrypted() (--test)
  * Make Doc97File.is_encrypted() return boolean
