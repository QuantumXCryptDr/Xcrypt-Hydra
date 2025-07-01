# xcrypt_hydra/utils.py

import hmac
import hashlib
import base64

# --- Padding ---
def pad_data(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding.")
    return data[:-pad_len]

# --- HMAC MAC Generation ---
def generate_mac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_mac(data: bytes, key: bytes, mac: bytes) -> bool:
    return hmac.compare_digest(generate_mac(data, key), mac)

# --- Base64 Encoding ---
def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded: str) -> bytes:
    return base64.b64decode(encoded)
