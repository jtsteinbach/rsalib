#!/usr/bin/env python3
#   RSA-Lib             v1.3.1
#   Author    umbra.one/rsalib

import os, random
from concurrent.futures import ThreadPoolExecutor

def keypair(bits: int = 2048):
# Generate an RSA keypair.
    e = 65537  # exponent

    # Miller–Rabin primality test for checking if n is prime
    def is_prime(n):
        if n < 2 or n & 1 == 0:
            return n == 2
        # write n-1 = 2^r * d
        r, d0 = 0, n - 1
        while d0 & 1 == 0:
            r += 1
            d0 >>= 1
        # repeat test 5 times for good confidence
        for _ in range(5):
            a = random.randrange(2, n - 1)
            x = pow(a, d0, n)
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


def encrypt(pub, plaintext):
# RSA encrypt using raw modular exponentiation (m^e mod n).
# Splits data into chunks, pads, and parallelizes for high throughput.
    # parse pub if string
    if isinstance(pub, str):
        n_str, e_str = pub.strip("()").split(",")
        n, e = int(n_str), int(e_str)
    else:
        n, e = pub
    # accept plaintext as str or bytes
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        data = plaintext
    else:
        raise TypeError("plaintext must be bytes or str")
    k = (n.bit_length() + 7) // 8       # RSA block size
    max_chunk = k - 1                  # ensure m < n
    def _enc_chunk(chunk: bytes) -> bytes:
        m = int.from_bytes(chunk, "big")
        c = pow(m, e, n)
        return c.to_bytes(k, "big")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor() as exe:
        futures = [exe.submit(_enc_chunk, data[i:i+max_chunk])
                   for i in range(0, len(data), max_chunk)]
        return b"".join(f.result() for f in futures)


def decrypt(priv, ciphertext):
# RSA decrypt using raw modular exponentiation (c^d mod n).
# Reassembles plaintext chunks in parallel and returns UTF-8 text.
    n, d = priv
    k = (n.bit_length() + 7) // 8
    def _dec_block(block: bytes) -> bytes:
        c = int.from_bytes(block, "big")
        m = pow(c, d, n)
        m_bytes = m.to_bytes(k, "big")
        return m_bytes.lstrip(b"\x00") or b"\x00"
    from concurrent.futures import ThreadPoolExecutor
    blocks = [ciphertext[i:i+k] for i in range(0, len(ciphertext), k)]
    with ThreadPoolExecutor() as exe:
        futures = [exe.submit(_dec_block, b) for b in blocks]
        data = b"".join(f.result() for f in futures)
    return data.decode("utf-8")
