# ODJ File Encryption

**Decryption methodology for Tesla Odin diagnostic job files.**

---

## Overview

Odin job files (.odj) use Fernet encryption with a hardcoded password.

| Parameter | Value |
|-----------|-------|
| Encryption | Fernet (symmetric) |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 123456 |
| Password | `cmftubxi7wlvmh1wmbzz00vf1ziqezf6` |
| Salt | First 16 bytes of file |

---

## File Format

### Structure

```
Offset   Size    Field
─────────────────────────────────────────
0x00     16      Salt (random per file)
0x10     N       Fernet token (encrypted data)
```

### Fernet Token Format

```
Version (1 byte) || Timestamp (8 bytes) || IV (16 bytes) || Ciphertext || HMAC (32 bytes)
```

---

## Decryption Algorithm

### Key Derivation

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

PASSWORD = b"cmftubxi7wlvmh1wmbzz00vf1ziqezf6"
ITERATIONS = 123456

def derive_key(salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = kdf.derive(PASSWORD)
    return base64.urlsafe_b64encode(key)
```

### Decryption

```python
from cryptography.fernet import Fernet

def decrypt_odj(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    encrypted = data[16:]
    
    key = derive_key(salt)
    fernet = Fernet(key)
    
    return fernet.decrypt(encrypted)
```

---

## Complete Decryption Script

```python
#!/usr/bin/env python3
"""Decrypt Tesla Odin ODJ files."""

import base64
import json
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PASSWORD = b"cmftubxi7wlvmh1wmbzz00vf1ziqezf6"
ITERATIONS = 123456

def decrypt_odj(input_path: str, output_path: str = None):
    with open(input_path, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    encrypted = data[16:]
    
    # Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = base64.urlsafe_b64encode(kdf.derive(PASSWORD))
    
    # Decrypt
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    
    # Parse JSON
    try:
        parsed = json.loads(decrypted)
        result = json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        result = decrypted.decode('utf-8', errors='replace')
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(result)
        print(f"Decrypted to: {output_path}")
    else:
        print(result)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.odj> [output.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    decrypt_odj(input_file, output_file)
```

---

## Usage

### Decrypt Single File

```bash
python3 scripts/decrypt_odj.py input.odj output.json
```

### Decrypt All Files in Directory

```bash
for f in *.odj; do
    python3 scripts/decrypt_odj.py "$f" "${f%.odj}.json"
done
```

---

## Credential Source

The password was extracted from decompiled Odin Python bytecode:

```python
# From odin_decompiled/core/crypto.py
ENCRYPTION_PASSWORD = "cmftubxi7wlvmh1wmbzz00vf1ziqezf6"
PBKDF2_ITERATIONS = 123456
```

---

## Security Analysis

### Why This Is Insecure

1. **Hardcoded password** - Same for all vehicles
2. **Password in bytecode** - Easily extracted
3. **No unique key per vehicle** - Universal decryption
4. **Standard algorithm** - Fernet is well-documented

### What This Enables

- Decrypt any ODJ file without Tesla access
- Analyze diagnostic job definitions
- Understand test procedures
- Extract calibration data

---

## Cross-References

- [Odin Architecture](README.md) - How Odin uses ODJ files
- [Config Decoder](config-decoder.md) - Related hashing system
- [scripts/decrypt_odj.py](https://github.com/talas9/tesla/blob/master/scripts/decrypt_odj.py) - Decryption tool

---

**Status:** COMPLETE ✅  
**Evidence:** Working decryption, decompiled source  
**Last Updated:** 2026-02-07
