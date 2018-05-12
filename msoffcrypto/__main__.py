import logging, sys
import argparse

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

import olefile

from . import OfficeFile

def ifWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt, os
        msvcrt.setmode(io.fileno(), os.O_BINARY)

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--password', dest='password', help='Password text.')
parser.add_argument('-v', dest='verbose', action='store_true', help='Print verbose information.')
parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'), help='Input file.')
parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'), help='Output file. If blank, stdout is used.')

def main():
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError("No OLE file")

    file = OfficeFile(args.infile)

    if args.verbose:
        logger.removeHandler(logging.NullHandler())
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    if args.password:
        file.load_key(password=args.password)
    else:
        raise AssertionError("Password is required")
    
    if args.outfile == None:
        ifWIN32SetBinary(sys.stdout)
        if hasattr(sys.stdout, 'buffer'): ## For Python 2
            args.outfile = sys.stdout.buffer
        else:
            args.outfile = sys.stdout

    file.decrypt(args.outfile)

if __name__ == '__main__':
    main()
