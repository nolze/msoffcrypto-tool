import sys
import unittest
from unittest.mock import patch

from msoffcrypto.__main__ import main


class MissingInputTest(unittest.TestCase):
    def test_test_flag_without_infile_exits_cleanly(self):
        with patch.object(sys, "argv", ["msoffcrypto", "-t"]):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 2)

    def test_decrypt_without_infile_exits_cleanly(self):
        with patch.object(sys, "argv", ["msoffcrypto", "-p", "secret"]):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
