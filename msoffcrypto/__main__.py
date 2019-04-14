from __future__ import print_function
import logging, sys
import argparse
import getpass

import olefile

from . import __version__
from . import OfficeFile

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def ifWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt, os
        msvcrt.setmode(io.fileno(), os.O_BINARY)


def is_encrypted(file):
    r'''
    Test if the file is encrypted.

        >>> f = open("tests/inputs/plain.doc", "rb")
        >>> file = OfficeFile(f)
        >>> is_encrypted(file)
        False
    '''
    # TODO: Validate file
    if not olefile.isOleFile(file):
        return False

    file = OfficeFile(file)

    return file.is_encrypted()


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--password', nargs='?', const='', dest='password', help='Password text.')
group.add_argument('-t', '--test', dest='test_encrypted', action='store_true', help='Test if the file is encrypted.')
parser.add_argument('-v', dest='verbose', action='store_true', help='Print verbose information.')
parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'), help='Input file.')
parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'), help='Output file. If blank, stdout is used.')


def main():
    args = parser.parse_args()

    if args.verbose:
        logger.removeHandler(logging.NullHandler())
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")
        logger.debug("Version: {}".format(__version__))

    if args.test_encrypted:
        if not is_encrypted(args.infile):
            print("{}: not encrypted".format(args.infile.name), file=sys.stderr)
            sys.exit(1)
        else:
            logger.debug("{}: encrypted".format(args.infile.name))
        return

    if not olefile.isOleFile(args.infile):
        raise Exception("Not OLE file")

    file = OfficeFile(args.infile)

    if args.password:
        file.load_key(password=args.password)
    else:
        password = getpass.getpass()
        file.load_key(password=password)

    if args.outfile is None:
        ifWIN32SetBinary(sys.stdout)
        if hasattr(sys.stdout, 'buffer'):  # For Python 2
            args.outfile = sys.stdout.buffer
        else:
            args.outfile = sys.stdout

    file.decrypt(args.outfile)


if __name__ == '__main__':
    main()
