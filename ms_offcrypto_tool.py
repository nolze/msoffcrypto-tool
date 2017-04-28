import sys, hashlib, base64, binascii, functools
from struct import *

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

import olefile
from xml.dom.minidom import parseString

SEGMENT_LENGTH = 4096

def hashCalc(i):
    return hashlib.sha512(i).digest()

def decrypt(key, keyDataSalt, ifile, ofile):
    obuf = b''
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

def generate_skey_from_privkey(privkey, encryptedKeyValue):
    privkey = PKCS1_v1_5.new(RSA.importKey(privkey))
    skey = privkey.decrypt(encryptedKeyValue, None)
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

class OfficeFile:
    def __init__(self, file):
        ole = olefile.OleFileIO(file)
        self.file = ole
        self.info = parseinfo(ole.openstream('EncryptionInfo'))
        self.secret_key = None
    def load_skey(self, secret_key):
        self.secret_key = secret_key
    def load_privkey(self, private_key):
        self.secret_key = generate_skey_from_privkey(private_key, self.info['encryptedKeyValue'])
    def decrypt(self, ofile):
        decrypt(self.secret_key, self.info['keyDataSalt'], self.file.openstream('EncryptedPackage'), ofile)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-k', dest='secret_key', help='MS-OFFCRYPTO secretKey value (hex)')
    group.add_argument('-p', dest='private_key', type=argparse.FileType('rb'), help='RSA private key file')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'))
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError("No OLE file")

    file = OfficeFile(args.infile)

    if args.secret_key:
        file.load_skey(binascii.unhexlify(args.secret_key))
    elif args.private_key:
        file.load_privkey(args.private_key)

    file.decrypt(args.outfile)

if __name__ == '__main__':
    main()
