import functools
import logging
from collections.abc import Iterator
from hashlib import sha1
from struct import pack, unpack
from typing import BinaryIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

SEGMENT_LENGTH = 4096


class ECMA376Standard:
    def __init__(self):
        pass

    @staticmethod
    def decrypt(key: bytes, ibuf: BinaryIO) -> bytes:
        r"""
        Return decrypted data.

        """
        return b"".join(ECMA376Standard.decrypt_stream(key, ibuf))

    @staticmethod
    def decrypt_stream(key: bytes, ibuf: BinaryIO) -> Iterator[bytes]:
        r"""
        Yield decrypted data in chunks.

        Only the first 4 bytes (``totalSize``) describe the real length; the
        encrypted data is padded to the AES block size, so exactly ``totalSize``
        plaintext bytes are yielded.
        """
        totalSize = unpack("<I", ibuf.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        ibuf.seek(8)
        aes = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = aes.decryptor()
        remaining = totalSize
        for buf in iter(functools.partial(ibuf.read, SEGMENT_LENGTH), b""):
            dec = decryptor.update(buf)
            if remaining < len(dec):
                dec = dec[:remaining]
            yield dec
            remaining -= len(dec)
            if remaining <= 0:
                break
        dec = decryptor.finalize()
        if remaining > 0 and dec:
            yield dec[:remaining]

    @staticmethod
    def verifykey(key, encryptedVerifier, encryptedVerifierHash):
        r"""
        Return True if the given intermediate key is valid.

            >>> key = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> encryptedVerifier = b'Qos.\x96o\xac\x17\xb1\xc5\xd7\xd8\xcc6\xc9('
            >>> encryptedVerifierHash = b'+ah\xda\xbe)\x11\xad+\xd3|\x17Ft\\\x14\xd3\xcf\x1b\xb1@\xa4\x8fNo=#\x88\x08r\xb1j'
            >>> ECMA376Standard.verifykey(key, encryptedVerifier, encryptedVerifierHash)
            True
        """
        # TODO: For consistency with Agile, rename method to verify_password or the like
        logger.debug([key, encryptedVerifier, encryptedVerifierHash])
        # https://msdn.microsoft.com/en-us/library/dd926426(v=office.12).aspx
        aes = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = aes.decryptor()
        verifier = decryptor.update(encryptedVerifier)
        expected_hash = sha1(verifier).digest()
        decryptor = aes.decryptor()
        verifierHash = decryptor.update(encryptedVerifierHash)[: sha1().digest_size]
        return expected_hash == verifierHash

    @staticmethod
    def makekey_from_password(
        password, algId, algIdHash, providerType, keySize, saltSize, salt
    ):
        r"""
        Generate intermediate key from given password.

            >>> password = 'Password1234_'
            >>> algId = 0x660e
            >>> algIdHash = 0x8004
            >>> providerType = 0x18
            >>> keySize = 128
            >>> saltSize = 16
            >>> salt = b'\xe8\x82fI\x0c[\xd1\xee\xbd+C\x94\xe3\xf80\xef'
            >>> expected = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> ECMA376Standard.makekey_from_password(password, algId, algIdHash, providerType, keySize, saltSize, salt) == expected
            True
        """
        logger.debug(
            [
                password,
                hex(algId),
                hex(algIdHash),
                hex(providerType),
                keySize,
                saltSize,
                salt,
            ]
        )
        xor_bytes = lambda a, b: bytearray(
            [p ^ q for p, q in zip(bytearray(a), bytearray(b))]
        )  # bytearray() for Python 2 compat.

        # https://msdn.microsoft.com/en-us/library/dd925430(v=office.12).aspx
        ITER_COUNT = 50000

        password = password.encode("UTF-16LE")
        h = sha1(salt + password).digest()
        for i in range(ITER_COUNT):
            ibytes = pack("<I", i)
            h = sha1(ibytes + h).digest()
        block = 0
        blockbytes = pack("<I", block)
        hfinal = sha1(h + blockbytes).digest()
        cbRequiredKeyLength = keySize // 8
        cbHash = sha1().digest_size
        buf1 = b"\x36" * 64
        buf1 = xor_bytes(hfinal, buf1[:cbHash]) + buf1[cbHash:]
        x1 = sha1(buf1).digest()
        buf2 = b"\x5c" * 64
        buf2 = xor_bytes(hfinal, buf2[:cbHash]) + buf2[cbHash:]
        x2 = sha1(buf2).digest()  # In spec but unused
        x3 = x1 + x2
        keyDerived = x3[:cbRequiredKeyLength]
        logger.debug(keyDerived)
        return keyDerived
