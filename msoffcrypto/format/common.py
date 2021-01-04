import logging
from struct import unpack

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# https://msdn.microsoft.com/en-us/library/dd926359(v=office.12).aspx
def _parse_encryptionheader(blob):
    (flags,) = unpack("<I", blob.read(4))
    # if mode == 'strict': compare values with spec.
    (sizeExtra,) = unpack("<I", blob.read(4))
    (algId,) = unpack("<I", blob.read(4))
    (algIdHash,) = unpack("<I", blob.read(4))
    (keySize,) = unpack("<I", blob.read(4))
    (providerType,) = unpack("<I", blob.read(4))
    (reserved1,) = unpack("<I", blob.read(4))
    (reserved2,) = unpack("<I", blob.read(4))
    cspName = blob.read().decode("utf-16le")
    header = {
        "flags": flags,
        "sizeExtra": sizeExtra,
        "algId": algId,
        "algIdHash": algIdHash,
        "keySize": keySize,
        "providerType": providerType,
        "reserved1": reserved1,
        "reserved2": reserved2,
        "cspName": cspName,
    }
    return header


# https://msdn.microsoft.com/en-us/library/dd910568(v=office.12).aspx
def _parse_encryptionverifier(blob, algorithm):
    (saltSize,) = unpack("<I", blob.read(4))
    salt = blob.read(16)
    encryptedVerifier = blob.read(16)
    (verifierHashSize,) = unpack("<I", blob.read(4))
    if algorithm == "RC4":
        encryptedVerifierHash = blob.read(20)
    elif algorithm == "AES":
        encryptedVerifierHash = blob.read(32)
    verifier = {
        "saltSize": saltSize,
        "salt": salt,
        "encryptedVerifier": encryptedVerifier,
        "verifierHashSize": verifierHashSize,
        "encryptedVerifierHash": encryptedVerifierHash,
    }
    return verifier
