import sys
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

import olefile

from .officefile import OfficeFile

def ifWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt, os
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-k', dest='secret_key', help='MS-OFFCRYPTO secretKey value (hex)')
    group.add_argument('-p', dest='private_key', type=argparse.FileType('rb'), help='RSA private key file')
    group.add_argument('-P', dest='password', help='Password ASCII')
    parser.add_argument('-v', dest='verbose', action='store_true', help='Print verbose information')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'))
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError("No OLE file")

    file = OfficeFile(args.infile)

    if args.verbose:
        logger.removeHandler(logging.NullHandler())
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    if args.secret_key:
        file.load_key(secret_key=binascii.unhexlify(args.secret_key))
    elif args.private_key:
        file.load_key(private_key=args.private_key)
    elif args.password:
        file.load_key(password=args.password)
    
    if args.outfile == None:
        ifWIN32SetBinary(sys.stdout)
        args.outfile = sys.stdout.buffer
    
    file.decrypt(args.outfile)

if __name__ == '__main__':
    main()
