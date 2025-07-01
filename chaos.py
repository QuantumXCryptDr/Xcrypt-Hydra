# chaos.py
import numpy as np
from sympy import Matrix

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
