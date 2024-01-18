
v5.3.1 / 2024-01-19
===================

  * Bug fixes

v5.3.0 / 2024-01-19
===================

  * Add support for OOXML encryption, a port from the C++ library https://github.com/herumi/msoffice (@stephane-rouleau, [#86](https://github.com/nolze/msoffcrypto-tool/pull/86))

v5.2.0 / 2024-01-06
===================

  * Support XOR Obfuscation decryption for .xls documents (@DissectMalware, [#80](https://github.com/nolze/msoffcrypto-tool/pull/80))
  * Bug fixes

v5.1.1 / 2023-07-20
===================

  * Drop Python 3.7 support as it reaches EOL, Add Python 3.11 to CI environments
  * Get the version in `__main__.py` instead of `__init__.py` to avoid a relevant error in PyInstaller/cx\_Freeze in which `pkg_resources` does not work by default

v5.1.0 / 2023-07-17
===================

  * Load plain OOXML as OfficeFile with type == plain. Fixes [#74](https://github.com/nolze/msoffcrypto-tool/issues/74)
  * Use importlib.metadata.version in Python >=3.8 ([#77](https://github.com/nolze/msoffcrypto-tool/issues/77))

5.0.1 / 2023-02-28
===================

  * (dev) Switch to GitHub Actions from Travis CI
  * Update dependencies, Drop Python 3.6 support

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
