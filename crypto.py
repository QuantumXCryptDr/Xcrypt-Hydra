import hashlib
import hmac
from Crypto.Protocol.KDF import PBKDF2

def hash_entropy(entropy):
    return hashlib.sha256(entropy.encode()).hexdigest()

def derive_key_and_mask(entropy, length):
    salt = b"AI-Hydra-Salt"
    key_material = PBKDF2(entropy, salt, dkLen=length * 2, count=100000)
    return key_material[:length], key_material[length:]
