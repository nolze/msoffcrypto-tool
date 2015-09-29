import argparse

import sys, hashlib, base64, binascii, functools
from struct import *

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

import olefile
from xml.dom.minidom import parseString

SEGMENT_LENGTH = 4096

def hashCalc(i):
    return hashlib.sha512(i).digest()

def decrypt(key, info, ifile, ofile):
    obuf = b''
    keyDataSalt = info['keyDataSalt']
    totalSize = unpack('<I', ifile.read(4))[0]
    sys.stderr.write("totalSize: {}\n".format(totalSize))
    ifile.seek(8)
    for i, ibuf in enumerate(iter(functools.partial(ifile.read, SEGMENT_LENGTH), b'')):
        saltWithBlockKey = keyDataSalt + pack('<I', i)
        iv = hashCalc(saltWithBlockKey)
        iv = iv[:16]
        aes = AES.new(key, AES.MODE_CBC, iv)
        dec = aes.decrypt(ibuf)
        obuf += dec
    ofile.write(obuf)
    return True

def generate_skey_from_privkey(privkey, info):
    privkey = PKCS1_v1_5.new(RSA.importKey(privkey))
    skey = privkey.decrypt(info['encryptedKeyValue'], None)
    return skey

def parseinfo(ole):
    ole.seek(8)
    xml = parseString(ole.read())
    saltValue = xml.getElementsByTagName('keyData')[0].getAttribute('saltValue')
    saltValue = base64.b64decode(saltValue)
    encryptedKeyValue = xml.getElementsByTagNameNS("http://schemas.microsoft.com/office/2006/keyEncryptor/certificate", 'encryptedKey')[0].getAttribute('encryptedKeyValue')
    encryptedKeyValue = base64.b64decode(encryptedKeyValue)
    info = {
        'keyDataSalt': saltValue,
        'encryptedKeyValue': encryptedKeyValue
    }
    return info

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-k', dest='secret_key', help='MS-OFFCRYPTO secretKey value (hex)')
    group.add_argument('-p', dest='private_key', type=argparse.FileType('rb'), help='RSA private key file')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'))
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError, "No OLE file"

    ole = olefile.OleFileIO(args.infile)
    ofile = args.outfile

    info = parseinfo(ole.openstream('EncryptionInfo'))
    if args.secret_key:
        secret_key = binascii.unhexlify(args.secret_key)
    elif args.private_key:
        secret_key = generate_skey_from_privkey(args.private_key, info)

    decrypt(secret_key, info, ole.openstream('EncryptedPackage'), ofile)

if __name__ == '__main__':
    main()
