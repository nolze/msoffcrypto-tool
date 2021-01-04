"""Check that given file handles are not closed."""


import unittest
from os.path import join, dirname

from msoffcrypto import OfficeFile


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


# if someone calls this as script, run unittests
if __name__ == "__main__":
    unittest.main()
