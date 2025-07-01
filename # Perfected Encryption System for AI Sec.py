# Perfected Encryption System for AI Secure Communication

import numpy as np
import hashlib
import base64
import os
from sympy import Matrix
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hmac

# --- Chaos Utilities ---

def logistic_map(seed, r=3.99, size=1000):
    stream = []
    x = seed
    for _ in range(size):
        x = r * x * (1 - x)
        stream.append(x)
    return stream

def chaos_matrix(stream, dim):
    flat_vals = [int(s * 256) % 256 for s in stream[:dim * dim]]
    return np.array(flat_vals, dtype=np.uint8).reshape((dim, dim))

def generate_invertible_matrix(stream, dim):
    mat = chaos_matrix(stream, dim)
    while np.gcd(int(round(np.linalg.det(mat))) % 256, 256) != 1:
        mat = ((mat.astype(np.uint16) + np.eye(dim, dtype=np.uint16)) % 256).astype(np.uint8)
    return mat

def mod_matrix_inverse(matrix, mod=256):
    sympy_matrix = Matrix(matrix.tolist())
    mod_inv = sympy_matrix.inv_mod(mod)
    return np.array(mod_inv.tolist(), dtype=np.uint8)

# --- Secure Mask and Entropy Derivation ---

def derive_key_and_mask(entropy, length):
    salt = b"AI-Hydra-Salt"
    key_material = PBKDF2(entropy, salt, dkLen=length * 2, count=100000)
    return key_material[:length], key_material[length:]

def hash_entropy(entropy):
    return hashlib.sha256(entropy.encode()).hexdigest()

# --- Key Pair Generation ---
def generate_key_pair(entropy, dim=4):
    entropy_hash = hash_entropy(entropy)
    chaos_seed = int(entropy_hash[:16], 16) / 2**64
    stream = logistic_map(chaos_seed, size=dim * dim * 10)

    matrix_A = generate_invertible_matrix(stream, dim)
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

# --- Padding & MAC ---
def pad_data(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    pad_len = data[-1]
    return data[:-pad_len]

def generate_mac(data, key):
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_mac(data, key, mac):
    return hmac.compare_digest(generate_mac(data, key), mac)

# --- Core Engine ---
def apply_matrix(data, matrix):
    return np.dot(matrix, data) % 256

def xor_mask(data, mask):
    return np.bitwise_xor(data, np.frombuffer(mask, dtype=np.uint8))

def encrypt(data, public_key):
    dim = len(public_key["matrix_seed"])
    block_size = dim * dim
    data = pad_data(data, block_size)

    matrix = np.array(public_key["matrix_seed"], dtype=np.uint8)
    mask = bytes(public_key["quantum_mask"])

    encrypted_blocks = []
    for i in range(0, len(data), block_size):
        block = np.frombuffer(data[i:i+block_size], dtype=np.uint8).reshape((dim, dim))
        transformed = apply_matrix(matrix, block)
        masked = xor_mask(transformed.flatten(), mask)
        encrypted_blocks.append(masked.tobytes())

    ciphertext = b''.join(encrypted_blocks)
    mac = generate_mac(ciphertext, mask)
    return base64.b64encode(ciphertext + mac).decode()

def decrypt(encoded_ciphertext, private_key):
    dim = int(len(private_key["quantum_mask"]) ** 0.5)
    block_size = dim * dim
    matrix_inv = np.array(private_key["matrix_inverse"], dtype=np.uint8)
    mask = bytes(private_key["quantum_mask"])

    raw = base64.b64decode(encoded_ciphertext)
    ciphertext, mac = raw[:-32], raw[-32:]

    if not verify_mac(ciphertext, mask, mac):
        raise ValueError("MAC verification failed. Data may be tampered.")

    decrypted_blocks = []
    for i in range(0, len(ciphertext), block_size):
        block = np.frombuffer(ciphertext[i:i+block_size], dtype=np.uint8)
        unmasked = xor_mask(block, mask)
        reshaped = unmasked.reshape((dim, dim))
        recovered = apply_matrix(matrix_inv, reshaped)
        decrypted_blocks.append(recovered.tobytes())

    return unpad_data(b''.join(decrypted_blocks))

# --- Digital Signatures ---
def sign_data(private_key, data):
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(public_key, data, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- Example ---
if __name__ == "__main__":
    entropy = "AI-X-Crypt-Entropy-Seed"
    public_key, private_key = generate_key_pair(entropy)

    message = b"This is confidential AI data."
    encrypted = encrypt(message, public_key)
    decrypted = decrypt(encrypted, private_key)

    print("Original:", message)
    print("Encrypted (b64):", encrypted)
    print("Decrypted:", decrypted)

    # Signature Test
    rsa_key = RSA.generate(2048)
    signature = sign_data(rsa_key.export_key(), message)
    is_valid = verify_signature(rsa_key.publickey().export_key(), message, signature)
    print("Signature Valid:", is_valid)

# --- File Encryption & Decryption Test ---
def encrypt_file(input_path, output_path, public_key):
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = encrypt(data, public_key)
    with open(output_path, "w") as f:
        f.write(encrypted)

def decrypt_file(input_path, output_path, private_key):
    with open(input_path, "r") as f:
        encrypted = f.read()
    decrypted = decrypt(encrypted, private_key)
    with open(output_path, "wb") as f:
        f.write(decrypted)

# Encrypt and Decrypt Example
encrypt_file("secret.txt", "encrypted.txt", public_key)
decrypt_file("encrypted.txt", "decrypted.txt", private_key)

print("✔️ File encrypted to 'encrypted.txt' and decrypted to 'decrypted.txt'")