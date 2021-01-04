#!/usr/bin/env python

"""Compare output of msoffcrypto-tool for a few input files."""

import sys
import unittest
import os
from os.path import dirname, abspath, isfile, join as pjoin
from tempfile import mkstemp
from difflib import SequenceMatcher

try:
    import cryptography
except ImportError:
    cryptography = None

# add base dir to path so we always import local msoffcrypto
TEST_BASE_DIR = dirname(abspath(__file__))
MODULE_BASE_DIR = dirname(TEST_BASE_DIR)
if sys.path[0] != MODULE_BASE_DIR:
    sys.path.insert(0, MODULE_BASE_DIR)
import msoffcrypto


#: encryption password for files tested here
PASSWORD = "Password1234_"

#: input dir
INPUT_DIR = "inputs"

#: pairs of input/output files
EXAMPLE_FILES = (
    ("example_password.docx", "example.docx"),
    ("example_password.xlsx", "example.xlsx"),
    ("ecma376standard_password.docx", "ecma376standard_password_plain.docx"),
    ("rc4cryptoapi_password.doc", "rc4cryptoapi_password_plain.doc"),
    ("rc4cryptoapi_password.xls", "rc4cryptoapi_password_plain.xls"),
    ("rc4cryptoapi_password.ppt", "rc4cryptoapi_password_plain.ppt"),
)

#: output dir:
OUTPUT_DIR = "outputs"


@unittest.skipIf(
    cryptography is None, "Cryptography module not installed for python{}.{}".format(sys.version_info.major, sys.version_info.minor)
)
class KnownOutputCompare(unittest.TestCase):
    """See module doc."""

    def test_known_output(self):
        """See module doc."""
        for in_name, out_name in EXAMPLE_FILES:
            input_path = pjoin(TEST_BASE_DIR, INPUT_DIR, in_name)
            expect_path = pjoin(TEST_BASE_DIR, OUTPUT_DIR, out_name)

            # now run the relevant parts of __main__.main:
            with open(input_path, "rb") as input_handle:
                file = msoffcrypto.OfficeFile(input_handle)
                if file.format == "ooxml" and file.type in ["standard", "agile"]:
                    file.load_key(password=PASSWORD, verify_password=True)
                else:
                    file.load_key(password=PASSWORD)

                out_desc = None
                out_path = None
                output = []
                try:
                    # create temp file for output of decryption function
                    out_desc, out_path = mkstemp(prefix="msoffcrypto-test-", suffix=".txt", text=True)
                    with os.fdopen(out_desc, "wb") as out_handle:
                        out_desc = None  # out_handle now owns this

                        # run decryption, capture output
                        print("decrypting {}".format(in_name))
                        if file.format == "ooxml" and file.type in ["agile"]:
                            file.decrypt(out_handle, verify_integrity=True)
                        else:
                            file.decrypt(out_handle)

                    # read extracted output file into memory
                    with open(expect_path, "rb") as reader:
                        output = reader.read()
                finally:
                    # ensure we do not leak temp files. Always close & remove
                    if out_desc:
                        os.close(out_desc)
                    if out_path and isfile(out_path):
                        os.unlink(out_path)

            # read output file into memory
            with open(expect_path, "rb") as reader:
                expect = reader.read()

            # compare:
            print("comparing output to {}".format(out_name))
            similarity = SequenceMatcher(None, expect, output).ratio()
            self.assertGreater(similarity, 0.99)


if __name__ == "__main__":
    unittest.main()
