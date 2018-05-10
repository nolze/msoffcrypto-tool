import functools, io, logging
from hashlib import md5
from struct import pack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def _makekey(password, salt, block):   
    ## https://msdn.microsoft.com/en-us/library/dd920360(v=office.12).aspx
    password = password.encode("UTF-16LE")
    h0 = md5(password).digest()
    truncatedHash = h0[:5]
    intermediateBuffer = (truncatedHash + salt) * 16
    h1 = md5(intermediateBuffer).digest()
    truncatedHash = h1[:5]
    blockbytes = pack("<I", block)
    hfinal = md5(truncatedHash + blockbytes).digest()
    key = hfinal[:128//8]
    return key

class DocumentRC4:
    def __init__(self):
        pass
    
    @staticmethod
    def verifypw(password, salt, encryptedVerifier, encryptedVerifierHash):
        ## https://msdn.microsoft.com/en-us/library/dd952648(v=office.12).aspx
        block = 0
        key = _makekey(password, salt, block)
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        verifier = decryptor.update(encryptedVerifier)
        verfiferHash = decryptor.update(encryptedVerifierHash)
        hash = md5(verifier).digest()
        logging.debug([verfiferHash, hash])
        return hash == verfiferHash
    
    @staticmethod
    def decrypt(password, salt, ifile):
        obuf = io.BytesIO()
    
        block = 0
        key = _makekey(password, salt, block)
    
        for c, ibuf in enumerate(iter(functools.partial(ifile.read, 0x200), b'')):
            cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()

            dec = decryptor.update(ibuf) + decryptor.finalize()
            obuf.write(dec)
            
            ## From wvDecrypt:
            ## at this stage we need to rekey the rc4 algorithm
            ## Dieter Spaar <spaar@mirider.augusta.de> figured out
            ## this rekeying, big kudos to him 
            block += 1
            key = _makekey(password, salt, block)
    
        obuf.seek(0)
        return obuf
