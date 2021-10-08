import functools
import hmac
import io
import logging
from hashlib import sha1, sha256, sha384, sha512
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ALGORITHM_HASH = {
    "SHA1": sha1,
    "SHA256": sha256,
    "SHA384": sha384,
    "SHA512": sha512,
}

def _get_hash_func(algorithm):
    return ALGORITHM_HASH.get(algorithm, sha1)


def _decrypt_aes_cbc(data, key, iv):
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = aes.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return decrypted


class ECMA376Agile:
    def __init__(self):
        pass

    @staticmethod
    def _derive_iterated_hash_from_password(password, saltValue, hashAlgorithm, spinValue):
        r"""
        Do a partial password-based hash derivation.
        Note the block key is not taken into consideration in this function.
        """
        # TODO: This function is quite expensive and it should only be called once.
        # We need to save the result for later use.
        # This is not covered by the specification, but MS Word does so.

        hashCalc = _get_hash_func(hashAlgorithm)

        # NOTE: Initial round sha512(salt + password)
        h = hashCalc(saltValue + password.encode("UTF-16LE"))

        # NOTE: Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, spinValue, 1):
            h = hashCalc(pack("<I", i) + h.digest())

        return h

    @staticmethod
    def _derive_encryption_key(h, blockKey, hashAlgorithm, keyBits):
        r"""
        Finish the password-based key derivation by hashing last hash + blockKey.
        """
        hashCalc = _get_hash_func(hashAlgorithm)
        h_final = hashCalc(h + blockKey)

        # NOTE: Needed to truncate encryption key to bitsize
        encryption_key = h_final.digest()[: keyBits // 8]

        return encryption_key

    @staticmethod
    def decrypt(key, keyDataSalt, hashAlgorithm, ibuf):
        r"""
        Return decrypted data.

            >>> key = b'@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2'
            >>> keyDataSalt = b'\x8f\xc7x"+P\x8d\xdcL\xe6\x8c\xdd\x15<\x16\xb4'
            >>> hashAlgorithm = 'SHA512'
        """
        SEGMENT_LENGTH = 4096
        hashCalc = _get_hash_func(hashAlgorithm)

        obuf = io.BytesIO()
        totalSize = unpack("<I", ibuf.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        remaining = totalSize
        ibuf.seek(8)
        for i, buf in enumerate(iter(functools.partial(ibuf.read, SEGMENT_LENGTH), b"")):
            saltWithBlockKey = keyDataSalt + pack("<I", i)
            iv = hashCalc(saltWithBlockKey).digest()
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
    def verify_password(password, saltValue, hashAlgorithm, encryptedVerifierHashInput, encryptedVerifierHashValue, spinValue, keyBits):
        r"""
        Return True if the given password is valid.

            >>> password = 'Password1234_'
            >>> saltValue = b'\xcb\xca\x1c\x99\x93C\xfb\xad\x92\x07V4\x15\x004\xb0'
            >>> hashAlgorithm = 'SHA512'
            >>> encryptedVerifierHashInput = b'9\xee\xa5N&\xe5\x14y\x8c(K\xc7qM8\xac'
            >>> encryptedVerifierHashValue = b'\x147mm\x81s4\xe6\xb0\xffO\xd8"\x1a|g\x8e]\x8axN\x8f\x99\x9fL\x18\x890\xc3jK)\xc5\xb33`' + \
            ... b'[\\\xd4\x03\xb0P\x03\xad\xcf\x18\xcc\xa8\xcb\xab\x8d\xeb\xe3s\xc6V\x04\xa0\xbe\xcf\xae\\\n\xd0'
            >>> spinValue = 100000
            >>> keyBits = 256
            >>> ECMA376Agile.verify_password(password, saltValue, hashAlgorithm, encryptedVerifierHashInput, encryptedVerifierHashValue, spinValue, keyBits)
            True
        """
        # NOTE: See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/a57cb947-554f-4e5e-b150-3f2978225e92

        block1 = bytearray([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
        block2 = bytearray([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])

        h = ECMA376Agile._derive_iterated_hash_from_password(password, saltValue, hashAlgorithm, spinValue)

        key1 = ECMA376Agile._derive_encryption_key(h.digest(), block1, hashAlgorithm, keyBits)
        key2 = ECMA376Agile._derive_encryption_key(h.digest(), block2, hashAlgorithm, keyBits)

        hash_input = _decrypt_aes_cbc(encryptedVerifierHashInput, key1, saltValue)
        hashCalc = _get_hash_func(hashAlgorithm)
        acutal_hash = hashCalc(hash_input)
        acutal_hash = acutal_hash.digest()

        expected_hash = _decrypt_aes_cbc(encryptedVerifierHashValue, key2, saltValue)

        return acutal_hash == expected_hash

    @staticmethod
    def verify_integrity(secretKey, keyDataSalt, keyDataHashAlgorithm, keyDataBlockSize, encryptedHmacKey, encryptedHmacValue, stream):
        r"""
        Return True if the HMAC of the data payload is valid.
        """
        # NOTE: See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/63d9c262-82b9-4fa3-a06d-d087b93e3b00

        block4 = bytearray([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
        block5 = bytearray([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])

        hashCalc = _get_hash_func(keyDataHashAlgorithm)

        iv1 = hashCalc(keyDataSalt + block4).digest()
        iv1 = iv1[:keyDataBlockSize]
        iv2 = hashCalc(keyDataSalt + block5).digest()
        iv2 = iv2[:keyDataBlockSize]

        hmacKey = _decrypt_aes_cbc(encryptedHmacKey, secretKey, iv1)
        hmacValue = _decrypt_aes_cbc(encryptedHmacValue, secretKey, iv2)

        msg_hmac = hmac.new(hmacKey, stream.read(), hashCalc)
        actualHmac = msg_hmac.digest()
        stream.seek(0)

        return hmacValue == actualHmac

    @staticmethod
    def makekey_from_privkey(privkey, encryptedKeyValue):
        privkey = serialization.load_pem_private_key(privkey.read(), password=None, backend=default_backend())
        skey = privkey.decrypt(encryptedKeyValue, padding.PKCS1v15())
        return skey

    @staticmethod
    def makekey_from_password(password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits):
        r"""
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
        """
        block3 = bytearray([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])

        h = ECMA376Agile._derive_iterated_hash_from_password(password, saltValue, hashAlgorithm, spinValue)
        encryption_key = ECMA376Agile._derive_encryption_key(h.digest(), block3, hashAlgorithm, keyBits)

        skey = _decrypt_aes_cbc(encryptedKeyValue, encryption_key, saltValue)

        return skey
