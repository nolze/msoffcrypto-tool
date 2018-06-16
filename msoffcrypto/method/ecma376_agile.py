import logging
import hashlib, functools, io
from struct import pack, unpack

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


class ECMA376Agile:
    def __init__(self):
        pass

    @staticmethod
    def decrypt(key, keyDataSalt, hashAlgorithm, ibuf):
        r'''
        Return decrypted data.

            >>> key = b'@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2'
            >>> keyDataSalt = b'\x8f\xc7x"+P\x8d\xdcL\xe6\x8c\xdd\x15<\x16\xb4'
            >>> hashAlgorithm = 'SHA512'
        '''
        SEGMENT_LENGTH = 4096

        obuf = io.BytesIO()
        totalSize = unpack('<I', ibuf.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        remaining = totalSize
        ibuf.seek(8)
        for i, buf in enumerate(iter(functools.partial(ibuf.read, SEGMENT_LENGTH), b'')):
            saltWithBlockKey = keyDataSalt + pack('<I', i)
            iv = _hashCalc(saltWithBlockKey, hashAlgorithm).digest()
            iv = iv[:16]
            aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            dec = decryptor.update(buf) + decryptor.finalize()
            if remaining < len(buf):
                dec = dec[:remaining]
            obuf.write(dec)
            remaining -= len(buf)
        return obuf.getvalue()  # return obuf.getbuffer()

    @staticmethod
    def makekey_from_privkey(privkey, encryptedKeyValue):
        privkey = serialization.load_pem_private_key(privkey.read(), password=None, backend=default_backend())
        skey = privkey.decrypt(encryptedKeyValue, padding.PKCS1v15())
        return skey

    @staticmethod
    def makekey_from_password(password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits):
        r'''
        Generate intermediate key from given password.

            >>> password = 'Password1234_'
            >>> saltValue = b'Lr]E\xdca\x0f\x93\x94\x12\xa0M\xa7\x91\x04f'
            >>> hashAlgorithm = 'SHA512'
            >>> encryptedKeyValue = b"\xa1l\xd5\x16Zz\xb9\xd2q\x11>\xd3\x86\xa7\x8c\xf4\x96\x92\xe8\xe5'\xb0\xc5\xfc\x00U\xed\x08\x0b|\xb9K"
            >>> spinValue = 100000
            >>> keyBits = 256
            >>> expected = b'@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2'
            >>> ECMA376Agile.makekey_from_password(password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits) == expected
            True
        '''
        block3 = bytearray([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6])
        # Initial round sha512(salt + password)
        h = _hashCalc(saltValue + password.encode("UTF-16LE"), hashAlgorithm)

        # Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, spinValue, 1):
            h = _hashCalc(pack("<I", i) + h.digest(), hashAlgorithm)

        h2 = _hashCalc(h.digest() + block3, hashAlgorithm)
        # Needed to truncate skey to bitsize
        skey3 = h2.digest()[:keyBits // 8]

        # AES encrypt the encryptedKeyValue with the skey and salt to get secret key
        aes = Cipher(algorithms.AES(skey3), modes.CBC(saltValue), backend=default_backend())
        decryptor = aes.decryptor()
        skey = decryptor.update(encryptedKeyValue) + decryptor.finalize()
        return skey
