"""Agile encryption with a hash shorter than the AES block-padded values (SHA1)."""

import io
import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.ecma376_agile import ECMA376Agile

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: agile SHA1/AES-128 and agile SHA512/AES-256
EXAMPLE_FILES = (
    ("ecma376agile_sha1_password.xlsx", "example.xlsx"),
    ("example_password.xlsx", "example.xlsx"),
)


class ECMA376AgileTest(unittest.TestCase):
    """See module doc."""

    def test_verify_password_and_integrity(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD, verify_password=True)
                outfile = io.BytesIO()
                ofile.decrypt(outfile, verify_integrity=True)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())

    def test_wrong_password(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.load_key(password="Password1234", verify_password=True)

    def test_tampered_package(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD)
                with ofile.file.openstream("EncryptedPackage") as stream:
                    package = bytearray(stream.read())

            info = ofile.info
            args = (
                ofile.secret_key,
                info["keyDataSalt"],
                info["keyDataHashAlgorithm"],
                info["keyDataBlockSize"],
                info["encryptedHmacKey"],
                info["encryptedHmacValue"],
            )
            self.assertTrue(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

            package[100] ^= 0x01
            self.assertFalse(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))


if __name__ == "__main__":
    unittest.main()
