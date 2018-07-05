from __future__ import print_function
import logging, sys
import argparse

import olefile

from . import OfficeFile

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def ifWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt, os
        msvcrt.setmode(io.fileno(), os.O_BINARY)


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--password', dest='password', help='Password text.')
group.add_argument('-e', '--protected', dest='protected', action='store_true', help='Check if the file is encrypted. If called, all other arguments, bar input, are ignored.')
parser.add_argument('-v', dest='verbose', action='store_true', help='Print verbose information.')
parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'), help='Input file.')
parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'), help='Output file. If blank, stdout is used.')


def main():
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError("No OLE file")

    if args.verbose:
        logger.removeHandler(logging.NullHandler())
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    file = OfficeFile(args.infile)

    if args.protected:
        if file.format == 'doc97' and not file.info.fib.base.fEncrypted:
            print("{}: not encrypted".format(args.infile.name), file=sys.stderr)
            sys.exit(1)
        else:
            logger.debug("{}: encrypted".format(args.infile.name))
    else:
        if args.password:
            # this will always raise an error for 2000-03 files, cannot be decrypted.
            # TODO: check and return output stating such, allowing safedocs to ignore file.
            file.load_key(password=args.password)
        else:
            raise AssertionError("Password is required")

        if args.outfile is None:
            ifWIN32SetBinary(sys.stdout)
            if hasattr(sys.stdout, 'buffer'):  # For Python 2
                args.outfile = sys.stdout.buffer
            else:
                args.outfile = sys.stdout

        file.decrypt(args.outfile)

if __name__ == '__main__':
    main()
