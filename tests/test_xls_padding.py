"""Check is_encrypted() on an XLS file whose Workbook stream ends in padding."""

import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")


class XlsPaddingTest(unittest.TestCase):
    """See module doc."""

    def test_is_encrypted_with_padding_shorter_than_a_record_header(self):
        """xlwt pads the Workbook stream with zeros to 4096 bytes, so it can end in fewer than 4 bytes."""
        with open(join(DATA_DIR, "plain_xlwt_padding.xls"), "rb") as file_handle:
            self.assertEqual(OfficeFile(file_handle).is_encrypted(), False)


if __name__ == "__main__":
    unittest.main()
