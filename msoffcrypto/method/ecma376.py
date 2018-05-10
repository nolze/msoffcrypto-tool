import sys, hashlib, base64, binascii, functools, os, io
from struct import pack, unpack
from xml.dom.minidom import parseString
import logging

import olefile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def _hashCalc(i, algorithm):
    if algorithm == "SHA512":
        return hashlib.sha512(i)
    else:
        return hashlib.sha1(i)

class ECMA376:
    def __init__(self):
        pass

    @staticmethod
    def decrypt(key, keyDataSalt, hashAlgorithm, ifile):
        SEGMENT_LENGTH = 4096
        obuf = io.BytesIO()
        totalSize = unpack('<I', ifile.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        ifile.seek(8)
        for i, ibuf in enumerate(iter(functools.partial(ifile.read, SEGMENT_LENGTH), b'')):
            saltWithBlockKey = keyDataSalt + pack('<I', i)
            iv = _hashCalc(saltWithBlockKey, hashAlgorithm).digest()
            iv = iv[:16]
            aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            dec = decryptor.update(ibuf) + decryptor.finalize()
            obuf.write(dec)
        return obuf.getbuffer()

    @staticmethod
    def generate_skey_from_privkey(privkey, encryptedKeyValue):
        privkey = serialization.load_pem_private_key(privkey.read(), password=None, backend=default_backend())
        skey = privkey.decrypt(encryptedKeyValue, padding.PKCS1v15())
        return skey

    @staticmethod
    def generate_skey_from_password(password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits):
        block3 = bytearray([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6])
        # Initial round sha512(salt + password)
        h = _hashCalc(saltValue + password.encode("UTF-16LE"), hashAlgorithm)

        # Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, spinValue, 1):
            h = _hashCalc(pack("<I", i) + h.digest(), hashAlgorithm)

        h2 = _hashCalc(h.digest() + block3, hashAlgorithm)
        # Needed to truncate skey to bitsize
        skey3 = h2.digest()[:keyBits//8]

        # AES encrypt the encryptedKeyValue with the skey and salt to get secret key
        aes = Cipher(algorithms.AES(skey3), modes.CBC(saltValue), backend=default_backend())
        decryptor = aes.decryptor()
        skey = decryptor.update(encryptedKeyValue) + decryptor.finalize()
        return skey
