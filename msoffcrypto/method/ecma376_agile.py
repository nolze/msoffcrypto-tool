import logging
from hashlib import sha1, sha512
import functools, io
from struct import pack, unpack
import hmac 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _hashCalc(i, algorithm):
    if algorithm == "SHA512":
        return sha512(i)
    else:
        return sha1(i)

def getHashFunc(algorithm):
    if algorithm == 'SHA512':
        return sha512
    else:
        return sha1

class ECMA376Agile:

    key_without_block_key = None
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
    def key_derivation_function_without_block_key(password, saltValue, hashAlgorithm, spinValue):
        r'''
        Do a partial password-based key derivation.
        Note the block key is not taken into consideration in this function. 

        This function is quite expensive and it should only be called once.
        We need to save the result for later use.
        This is not covered by the specification, but MS Word does so.
        '''

        h = _hashCalc(saltValue + password.encode("UTF-16LE"), hashAlgorithm)

        # Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, spinValue, 1):
            h = _hashCalc(pack("<I", i) + h.digest(), hashAlgorithm)

        key = h.digest()
        # save it for later use
        ECMA376Agile.key_without_block_key = key

        return key
    
    @staticmethod
    # def key_derivation_function(password, saltValue, blockKey, hashAlgorithm, spinValue, keyBits):
    def key_derivation_function_final(partialKey, blockKey, hashAlgorithm, keyBits):
        r'''
        Finish the password-based key derivation by hashing the partial_key + blockKey. 
        In Agile, three different constant blockKeys are involved in the decryption
        '''

        h = _hashCalc(partialKey + blockKey, hashAlgorithm)
        # Needed to truncate skey to bitsize
        key = h.digest()[:keyBits // 8]

        return key

    @staticmethod
    def aes_cbc_drcrypt(data, key, iv):
        aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        return decrypted

    @staticmethod
    def verifykey(saltValue, hashAlgorithm, keyBits, encryptedVerifierHashInput, encryptedVerifierHashValue):
        r'''
        Return True if the given intermediate key is valid.
        Note makekey_from_password() must be called before calling this function
        Otherwise, the ECMA376Agile.key_without_block_key is not initialized yet
        '''

        block1 = bytearray([0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79])
        block2 = bytearray([0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e])

        # note this will NOT do 2 * spinValue rounds of hash calculation, which is redundant
        # since we saved the key_without_block_key in the key_derivation_function()
        # only the last round hash with blockKey is carried out
        key1 = ECMA376Agile.key_derivation_function_final(ECMA376Agile.key_without_block_key, block1, hashAlgorithm, keyBits)
        key2 = ECMA376Agile.key_derivation_function_final(ECMA376Agile.key_without_block_key, block2, hashAlgorithm, keyBits)

        hash_input = ECMA376Agile.aes_cbc_drcrypt(encryptedVerifierHashInput, key1, saltValue)
        h = _hashCalc(hash_input, hashAlgorithm)
        acutal_hash = h.digest()

        expected_hash = ECMA376Agile.aes_cbc_drcrypt(encryptedVerifierHashValue, key2, saltValue)

        logging.debug([expected_hash, acutal_hash])

        return acutal_hash == expected_hash

    @staticmethod
    def verify_payload_integrity(secretKey, keyDataSalt, keyDataHashAlgorithm, keyDataBlockSize, 
                            encryptedHmacKey, encryptedHmacValue, stream):
        r'''
        Return True if the HMAC of the payload is valid.
        '''

        block4 = bytearray([0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6])
        block5 = bytearray([0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33])

        iv1 = _hashCalc(keyDataSalt + block4, keyDataHashAlgorithm).digest()
        iv1 = iv1[: keyDataBlockSize]
        iv2 = _hashCalc(keyDataSalt + block5, keyDataHashAlgorithm).digest()
        iv2 = iv2[: keyDataBlockSize]

        hmacKey = ECMA376Agile.aes_cbc_drcrypt(encryptedHmacKey, secretKey, iv1)
        hmacValue = ECMA376Agile.aes_cbc_drcrypt(encryptedHmacValue, secretKey, iv2)

        msg_hmac = hmac.new(hmacKey, stream.read(), getHashFunc(keyDataHashAlgorithm))
        actualHmac = msg_hmac.digest()

        return hmacValue == actualHmac

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
        partialKey = ECMA376Agile.key_derivation_function_without_block_key(password, saltValue, hashAlgorithm, spinValue)
        derivedKey = ECMA376Agile.key_derivation_function_final(partialKey, block3, hashAlgorithm, keyBits)
        # derived_key = ECMA376Agile.key_derivation_function(password, saltValue, block3, hashAlgorithm, spinValue, keyBits)
        skey = ECMA376Agile.aes_cbc_drcrypt(encryptedKeyValue, derivedKey, saltValue)

        return skey
