"""Check is_encrypted() on an XLS file whose Workbook stream ends in padding."""

import io
import unittest
from os.path import dirname, join
from struct import pack

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.xls97 import _BIFFStream, recordNameNum

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")


class XlsPaddingTest(unittest.TestCase):
    """See module doc."""

    def test_is_encrypted_with_padding_shorter_than_a_record_header(self):
        """xlwt pads the Workbook stream with zeros to 4096 bytes, so it can end in fewer than 4 bytes."""
        with open(join(DATA_DIR, "plain_xlwt_padding.xls"), "rb") as file_handle:
            self.assertEqual(OfficeFile(file_handle).is_encrypted(), False)


class BiffSubstreamSearchTest(unittest.TestCase):
    """Encryption detection must respect the Globals substream boundary."""

    def search(self, records):
        # Start at a nonzero position to check restoration on every exit path.
        stream = io.BytesIO(b"prefix" + records)
        stream.seek(6)
        try:
            return _BIFFStream(stream).has_record(recordNameNum["FilePass"])
        finally:
            self.assertEqual(stream.tell(), 6)

    def test_does_not_search_past_eof(self):
        eof = pack("<HH", recordNameNum["EOF"], 0)
        filepass = pack("<HHH", recordNameNum["FilePass"], 2, 1)
        for tail in (b"", b"\x00", b"\x00\x00", b"\x00\x00\x00", b"\xff", filepass):
            with self.subTest(tail=tail):
                self.assertFalse(self.search(eof + tail))

    def test_finds_filepass_before_eof(self):
        records = pack("<HHH", recordNameNum["CodePage"], 2, 1200)
        records += pack("<HHH", recordNameNum["FilePass"], 2, 1)
        records += pack("<HH", recordNameNum["EOF"], 0)
        self.assertTrue(self.search(records))

    def test_rejects_missing_eof_and_partial_headers(self):
        for tail in (b"", b"\x00", b"\x00\x00", b"\x00\x00\x00", b"\xff"):
            with self.subTest(tail=tail):
                with self.assertRaisesRegex(exceptions.ParseError, "header.*before EOF"):
                    self.search(pack("<HHH", recordNameNum["CodePage"], 2, 1200) + tail)

    def test_rejects_truncated_payload(self):
        for record in ("CodePage", "FilePass"):
            with self.subTest(record=record):
                with self.assertRaisesRegex(exceptions.ParseError, "payload"):
                    self.search(pack("<HH", recordNameNum[record], 2) + b"\x01")


if __name__ == "__main__":
    unittest.main()
