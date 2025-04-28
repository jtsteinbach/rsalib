# RSA-Lib

**Version:** v1.2.1\
**Author:** umbra.one/rsalib

A pure‑Python, zero‑dependency RSA library optimized for simplicity and speed. All operations use built‑in Python integer arithmetic and `pow()`, with no external requirements.

---

## Features

- **Key Generation** (`keypair`) using Miller–Rabin primality testing
- **Key Persistence** (`save_key` / `load_key`) in compact binary format
- **Encryption** (`encrypt`) via raw modular exponentiation (mⁿ mod e)
- **Decryption** (`decrypt`) via raw modular exponentiation (cᵈ mod n)

---

## Quick Start

1. **Clone or download** this repository into your project directory.
2. **Ensure** `rsalib.py` is alongside your scripts.
3. **Run** your Python code

---

## API Reference

Import the library:

```python
import rsalib
```

### `keypair(bits: int = 2048) -> (priv, pub)`

Generate an RSA keypair with a modulus of `bits` length (default 2048).

- **Returns:**
  - `priv`: tuple `(n, d)` — modulus and private exponent
  - `pub`:  tuple `(n, e)` — modulus and public exponent

```python
priv, pub = rsalib.keypair(2048)
```

### `save_key(key, path: str)`

Save a key tuple (`(n, exponent)`) to `path` in a compact binary form.

```python
rsalib.save_key(priv, "private.key")
rsalib.save_key(pub,  "public.key")
```

### `load_key(path: str) -> key`

Load a key tuple from the binary file written by `save_key`.

```python
priv = rsalib.load_key("private.key")
pub  = rsalib.load_key("public.key")
```

### `encrypt(pub, plaintext: bytes) -> bytes`

Encrypt a byte string `plaintext` using the public key.\
**Note:** `len(plaintext)` must be less than the byte‐length of the modulus.

```python
message    = b"Secret Message"
ciphertext = rsalib.encrypt(pub, message)
```

### `decrypt(priv, ciphertext: bytes) -> bytes`

Decrypt a ciphertext produced by `encrypt`, returning the original plaintext.

```python
plaintext = rsalib.decrypt(priv, ciphertext)
```

---

## Example Usage

```python
#!/usr/bin/env python3
import os
import rsalib

# 1) Generate keys
priv, pub = rsalib.keypair(2048)

# 2) Persist keys
rsalib.save_key(priv, "private.key")
rsalib.save_key(pub,  "public.key")

# 3) Reload keys
priv = rsalib.load_key("private.key")
pub  = rsalib.load_key("public.key")

# 4) Encrypt & decrypt
msg = b"Hello, RSA!"
ct  = rsalib.encrypt(pub, msg)
pt  = rsalib.decrypt(priv, ct)
print(pt)  # b"Hello, RSA!"

# 5) Clean up
os.remove("private.key")
os.remove("public.key")
```

---

## Performance

- **Pure‑Python**: uses built‑in `pow()` for modular exponentiation (GIL‑released in C).
- **No external libs**: minimal overhead, ideal for lightweight scripting.

---

## License

MIT © umbra.one
