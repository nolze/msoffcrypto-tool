import subprocess
import unittest


class CLITest(unittest.TestCase):
    def test_cli(self):
        # Python 3:
        # cp = subprocess.run("./tests/test_cli.sh", shell=True)
        # self.assertEqual(cp.returncode, 0)
        # For Python 2 compat:
        returncode = subprocess.call("./tests/test_cli.sh", shell=True)
        self.assertEqual(returncode, 0)


if __name__ == "__main__":
    unittest.main()
