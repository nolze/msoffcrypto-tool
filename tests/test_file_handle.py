"""Check that given file handles are not closed."""


import io
import unittest
from os.path import dirname, join

import olefile

from msoffcrypto import OfficeFile, exceptions

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")


class FileHandleTest(unittest.TestCase):
    """See module doc."""

    def test_file_handle_open(self):
        """Check that file handles are open after is_encrypted()."""
        for suffix in "doc", "ppt", "xls":
            path = join(DATA_DIR, "plain." + suffix)

            with open(path, "rb") as file_handle:
                ofile = OfficeFile(file_handle)

                # do something with ofile
                self.assertEqual(ofile.is_encrypted(), False)

                # check that file handle is still open
                self.assertFalse(file_handle.closed)

                # destroy OfficeFile, calls destructor
                del ofile

                # check that file handle is still open
                self.assertFalse(file_handle.closed)

            # just for completeness:
            # check that file handle is now closed
            self.assertTrue(file_handle.closed)


class MalformedFileTest(unittest.TestCase):
    """Check that is_encrypted() raises ParseError on malformed legacy files."""

    def corrupt(self, name, stream, original, replacement):
        """Return a copy of an input file with the first bytes of a stream replaced."""
        with open(join(DATA_DIR, name), "rb") as file_handle:
            data = bytearray(file_handle.read())
        with olefile.OleFileIO(bytes(data)) as ole:
            head = ole.openstream(stream).read(16)
        self.assertEqual(data.count(head), 1)
        self.assertTrue(head.startswith(original))
        pos = data.find(head)
        data[pos : pos + len(replacement)] = replacement
        return io.BytesIO(bytes(data))

    def test_xls_workbook_without_bof(self):
        """The Workbook stream must start with a BOF record (0x0809)."""
        file_handle = self.corrupt("plain.xls", "Workbook", b"\x09\x08", b"\x00\x00")
        with self.assertRaises(exceptions.ParseError):
            OfficeFile(file_handle).is_encrypted()

    def test_ppt_current_user_atom_bad_rec_ver(self):
        """The CurrentUserAtom recVer must be 0."""
        file_handle = self.corrupt("plain.ppt", "Current User", b"\x00", b"\x01")
        with self.assertRaises(exceptions.ParseError):
            OfficeFile(file_handle).is_encrypted()


# if someone calls this as script, run unittests
if __name__ == "__main__":
    unittest.main()
