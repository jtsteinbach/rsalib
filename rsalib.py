#!/usr/bin/env python3
#   RSA-Lib             v1.2.0
#   Author    umbra.one/rsalib

import os, random

def keypair(bits: int = 2048):
# Generate an RSA keypair.

    e = 65537  # exponent
    
    # Miller–Rabin primality test for checking if n is prime
    def is_prime(n):
        if n < 2 or n & 1 == 0:
            return n == 2
        # write n-1 = 2^r * d
        r, d = 0, n - 1
        while d & 1 == 0:
            r += 1
            d >>= 1
        # repeat test 5 times for good confidence
        for _ in range(5):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            # square repeatedly to check nontrivial roots of unity
            for _ in range(r - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    # Generate a prime number of approximately b bits
    def gen_prime(b):
        while True:
            # ensure high bit set and odd
            p = random.getrandbits(b) | (1 << (b - 1)) | 1
            if is_prime(p):
                return p

    # Extended Euclidean Algorithm (iterative) to compute gcd and coefficients
    def egcd(a, b):
        x0, y0, x1, y1 = 1, 0, 0, 1
        while b:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    # Compute modular inverse of a modulo m
    def modinv(a, m):
        g, x, _ = egcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse exists")
        return x % m

    # Split bit-length roughly in half for p and q
    half = bits // 2
    p = gen_prime(half)
    q = gen_prime(half)
    while q == p:  # ensure p and q are distinct
        q = gen_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)  # private exponent

    return (n, d), (n, e)


def save_key(key, path: str):
# Save a key tuple (n, exponent) to a file in compact binary form:
# [4-byte n_length][n_bytes][4-byte v_length][v_bytes]
    n, v = key
    # convert numbers to big-endian byte sequences
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    vb = v.to_bytes((v.bit_length() + 7) // 8, "big")
    with open(path, "wb") as f:
        f.write(len(nb).to_bytes(4, "big") + nb
                + len(vb).to_bytes(4, "big") + vb)


def load_key(path: str):
# Load a key tuple (n, exponent) from the binary format written by save_key.
    data = open(path, "rb").read()
    # first 4 bytes = length of n
    nl = int.from_bytes(data[0:4], "big")
    n  = int.from_bytes(data[4:4+nl], "big")
    offset = 4 + nl
    # next 4 bytes = length of exponent
    vl = int.from_bytes(data[offset:offset+4], "big")
    v  = int.from_bytes(data[offset+4:offset+4+vl], "big")
    return (n, v)


def encrypt(pub, plaintext: bytes):
# RSA encrypt using raw modular exponentiation (m^e mod n).
# plaintext must be shorter than the modulus in bytes.
# Returns a fixed‐length ciphertext.
    n, e = pub
    m = int.from_bytes(plaintext, "big")
    if m >= n:
        raise ValueError("Plaintext too long for this modulus")
    c = pow(m, e, n)
    length = (n.bit_length() + 7) // 8
    return c.to_bytes(length, "big")


def decrypt(priv, ciphertext: bytes):
# RSA decrypt using raw modular exponentiation (c^d mod n).
# Returns the original plaintext bytes.
    n, d = priv
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    # restore message length
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")
