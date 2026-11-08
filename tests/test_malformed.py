"""Check that is_encrypted() raises ParseError on malformed legacy files."""

import io
import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")


class MalformedFileTest(unittest.TestCase):
    """See module doc."""

    def patched(self, name, offset, old, new):
        with open(join(DATA_DIR, name), "rb") as file_handle:
            data = bytearray(file_handle.read())
        self.assertEqual(data[offset : offset + len(old)], old)
        data[offset : offset + len(new)] = new
        return io.BytesIO(bytes(data))

    def test_xls_workbook_without_bof(self):
        file_handle = self.patched("plain.xls", 512, b"\x09\x08", b"\x00\x00")  # Workbook's first record id
        with self.assertRaises(exceptions.ParseError):
            OfficeFile(file_handle).is_encrypted()

    def test_ppt_current_user_bad_rec_ver(self):
        file_handle = self.patched("plain.ppt", 42496, b"\x00", b"\x01")  # CurrentUserAtom recVer
        with self.assertRaises(exceptions.ParseError):
            OfficeFile(file_handle).is_encrypted()


if __name__ == "__main__":
    unittest.main()
