"""Tests for streaming OOXML decryption.

The streaming entry points should produce byte-for-byte the same output as the
original, buffering-based implementations, without requiring a seekable output
destination.
"""

import unittest
from os.path import dirname, join

from msoffcrypto import exceptions
from msoffcrypto.format.ooxml import OOXMLFile
from msoffcrypto.method.ecma376_agile import ECMA376Agile
from msoffcrypto.method.ecma376_standard import ECMA376Standard

DATA_DIR = join(dirname(__file__), "inputs")
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"


class _Sink:
    """A write-only destination, similar to ``sys.stdout.buffer``."""

    def __init__(self):
        self.data = bytearray()

    def write(self, buf):
        self.data.extend(buf)
        return len(buf)


class OOXMLStreamingTest(unittest.TestCase):
    def test_agile_stream_matches_decrypt(self):
        with open(join(DATA_DIR, "example_password.docx"), "rb") as f:
            officefile = OOXMLFile(f)
            officefile.load_key(password=PASSWORD)

            with officefile.file.openstream("EncryptedPackage") as stream:
                expected = ECMA376Agile.decrypt(
                    officefile.secret_key,
                    officefile.info["keyDataSalt"],
                    officefile.info["keyDataHashAlgorithm"],
                    stream,
                )
            with officefile.file.openstream("EncryptedPackage") as stream:
                actual = b"".join(
                    ECMA376Agile.decrypt_stream(
                        officefile.secret_key,
                        officefile.info["keyDataSalt"],
                        officefile.info["keyDataHashAlgorithm"],
                        stream,
                    )
                )

        self.assertEqual(actual, expected)

    def test_standard_stream_matches_decrypt(self):
        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            officefile = OOXMLFile(f)
            officefile.load_key(password=PASSWORD)

            with officefile.file.openstream("EncryptedPackage") as stream:
                expected = ECMA376Standard.decrypt(officefile.secret_key, stream)
            with officefile.file.openstream("EncryptedPackage") as stream:
                actual = b"".join(
                    ECMA376Standard.decrypt_stream(officefile.secret_key, stream)
                )

        self.assertEqual(actual, expected)

    def test_decrypt_to_write_only_stream(self):
        with open(join(OUTPUT_DIR, "example.docx"), "rb") as f:
            expected = f.read()

        with open(join(DATA_DIR, "example_password.docx"), "rb") as f:
            officefile = OOXMLFile(f)
            officefile.load_key(password=PASSWORD)

            sink = _Sink()
            officefile.decrypt(sink)

        self.assertEqual(bytes(sink.data), expected)

    def test_decrypt_wrong_password_raises(self):
        with open(join(DATA_DIR, "example_password.docx"), "rb") as f:
            officefile = OOXMLFile(f)
            officefile.load_key(password="incorrect")

            sink = _Sink()
            with self.assertRaises(exceptions.InvalidKeyError):
                officefile.decrypt(sink)


if __name__ == "__main__":
    unittest.main()
