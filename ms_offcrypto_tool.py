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

def generate_skey_from_password(password, saltValue, encryptedKeyValue, spinValue, blockkey):
    # Initial round sha1(salt + password)
    h = hashlib.sha1(saltValue.decode("base64") + password.encode("UTF-16LE"))

    # Iteration of 0 -> spincount-1; hash = sha1(iterator + hash)
    for i in range(0, spinValue, 1):
        h = hashlib.sha1(struct.pack("<I", i) + h.digest())

    h2 = hashlib.sha1(h.digest() + blockkey.decode("hex"))
    # Needed to truncate skey to bitsize
    a = h2.hexdigest()[:-8]
    skey3 = a.decode("hex")

    # AES encrypt the encryptedKeyValue with the skey and salt to get secret key
    aes = AES.new(skey3, AES.MODE_CBC, salt.decode("base64"))
    skey = aes.decrypt(encryptedKeyValue.decode("base64"))
    return skey

def parseinfo(ole):
    ole.seek(8)
    xml = parseString(ole.read())
    saltValue = xml.getElementsByTagName('keyData')[0].getAttribute('saltValue')
    saltValue = base64.b64decode(saltValue)
    spinValue = xml.getElementsByTagNameNS("http://schemas.microsoft.com/office/2006/keyEncryptor/password", 'encryptedKey')[0].getAttribute('spinCount')
    encryptedKeyValue = xml.getElementsByTagNameNS("http://schemas.microsoft.com/office/2006/keyEncryptor/password", 'encryptedKey')[0].getAttribute('encryptedKeyValue')
    encryptedKeyValue = base64.b64decode(encryptedKeyValue)
    blockkey = "146e0be7abacd0d6"
    blockkey = blockkey.decode("hex")
    info = {
        'keyDataSalt': saltValue,
        'encryptedKeyValue': encryptedKeyValue,
        'blockkey': blockkey,
        'spinValue': spinValue
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
    def load_password(self, password):
        self.secret_key = generate_skey_from_password(password, self.info['keyDataSalt'], self.info['encryptedKeyValue'], self.info['spinValue'], self.info['blockkey'])
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
    group.add_argument('-P', dest='password', help='Password ASCII')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'))
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))
    args = parser.parse_args()

    if not olefile.isOleFile(args.infile):
        raise AssertionError, "No OLE file"

    file = OfficeFile(args.infile)

    if args.secret_key:
        file.load_skey(binascii.unhexlify(args.secret_key))
    elif args.private_key:
        file.load_privkey(args.private_key)
    elif args.password:
        file.load_password(args.password)

    file.decrypt(args.outfile)

if __name__ == '__main__':
    main()
