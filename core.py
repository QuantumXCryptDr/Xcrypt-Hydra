# xcrypt_hydra/core.py

import numpy as np
from .chaos import generate_invertible_matrix, mod_matrix_inverse
from .crypto import derive_key_and_mask, hash_entropy
from .utils import (
    pad_data, unpad_data,
    generate_mac, verify_mac,
    encode_base64, decode_base64
)

def apply_matrix(data, matrix):
    return np.dot(matrix, data) % 256

def xor_mask(data, mask):
    return np.bitwise_xor(data, np.frombuffer(mask, dtype=np.uint8))

def generate_key_pair(entropy, dim=4):
    entropy_hash = hash_entropy(entropy)
    chaos_seed = int(entropy_hash[:16], 16) / 2**64
    stream_dim = dim * dim * 10

    matrix_A = generate_invertible_matrix(chaos_seed, dim, stream_dim)
    matrix_A_inv = mod_matrix_inverse(matrix_A, mod=256)

    _, quantum_mask = derive_key_and_mask(entropy, dim * dim)

    public_key = {
        "matrix_seed": matrix_A.tolist(),
        "quantum_mask": list(quantum_mask),
        "hash_fingerprint": entropy_hash
    }

    private_key = {
        "matrix_inverse": matrix_A_inv.tolist(),
        "quantum_mask": list(quantum_mask),
        "chaos_seed": chaos_seed,
        "entropy_hash": entropy_hash
    }

    return public_key, private_key

def encrypt(data, public_key):
    dim = len(public_key["matrix_seed"])
    block_size = dim * dim
    data = pad_data(data, block_size)

    matrix = np.array(public_key["matrix_seed"], dtype=np.uint8)
    mask = bytes(public_key["quantum_mask"])

    encrypted_blocks = []
    for i in range(0, len(data), block_size):
        block = np.frombuffer(data[i:i + block_size], dtype=np.uint8).reshape((dim, dim))
        transformed = apply_matrix(matrix, block)
        masked = xor_mask(transformed.flatten(), mask)
        encrypted_blocks.append(masked.tobytes())

    ciphertext = b''.join(encrypted_blocks)
    mac = generate_mac(ciphertext, mask)
    return encode_base64(ciphertext + mac)

def decrypt(encoded_ciphertext, private_key):
    dim = int(len(private_key["quantum_mask"]) ** 0.5)
    block_size = dim * dim
    matrix_inv = np.array(private_key["matrix_inverse"], dtype=np.uint8)
    mask = bytes(private_key["quantum_mask"])

    raw = decode_base64(encoded_ciphertext)
    ciphertext, mac = raw[:-32], raw[-32:]

    if not verify_mac(ciphertext, mask, mac):
        raise ValueError("MAC verification failed. Data may be tampered.")

    decrypted_blocks = []
    for i in range(0, len(ciphertext), block_size):
        block = np.frombuffer(ciphertext[i:i + block_size], dtype=np.uint8)
        unmasked = xor_mask(block, mask)
        reshaped = unmasked.reshape((dim, dim))
        recovered = apply_matrix(matrix_inv, reshaped)
        decrypted_blocks.append(recovered.tobytes())

    return unpad_data(b''.join(decrypted_blocks))
