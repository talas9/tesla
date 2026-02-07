# Odin Diagnostic System

**Reverse engineering of Tesla's Odin service tool.**

---

## Overview

Odin is Tesla's internal diagnostic and service tool. This research documents:

- **Config Hashing**: SHA256 algorithm for obfuscating config names
- **ODJ Encryption**: Fernet encryption for diagnostic job files
- **Routines Database**: 2,988 Python scripts with access levels
- **Decompiled Source**: Python 3.6 bytecode extraction

---

## Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | How Odin works, component overview |
| [config-decoder.md](config-decoder.md) | SHA256 hashing algorithm (COMPLETE) |
| [odj-encryption.md](odj-encryption.md) | Fernet decryption methodology |
| [routines-database.md](routines-database.md) | Access levels, secure config flags |

---

## Quick Facts

| Metric | Value |
|--------|-------|
| Python Scripts | 2,988 files |
| Config Hashing | SHA256 |
| ODJ Encryption | Fernet (PBKDF2-HMAC-SHA256) |
| Decryption Password | `cmftubxi7wlvmh1wmbzz00vf1ziqezf6` |
| PBKDF2 Iterations | 123456 |
| Decoded Configs | 62-64 (varies by model) |

---

## Key Findings

### 1. Config Hashing Algorithm ✅ COMPLETE

```python
# Key hash
key_hash = SHA256(key + salt)

# Value hash (note: value comes FIRST)
value_hash = SHA256(value + key + salt)
```

- Salt varies per firmware version
- Algorithm decompiled from `gen3/config_options.py`
- All public configs (62-64) successfully decoded

### 2. ODJ File Encryption ✅ CRACKED

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = b"cmftubxi7wlvmh1wmbzz00vf1ziqezf6"
salt = file_contents[:16]  # First 16 bytes
iterations = 123456

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=iterations
)
key = base64.urlsafe_b64encode(kdf.derive(password))
fernet = Fernet(key)
decrypted = fernet.decrypt(file_contents[16:])
```

### 3. Access Level Flags ✅ DOCUMENTED

| Flag | Meaning | Example |
|------|---------|---------|
| `accessLevel: "UDP"` | Insecure, no auth | ecuMapVersion |
| `accessLevel: "GTW"` | Hardware locked | devSecurityLevel |
| No flag + paid feature | Secure, Hermes auth | superchargingAccess |

---

## Tools

| Tool | Purpose |
|------|---------|
| [decode_gateway_config.py](https://github.com/talas9/tesla/blob/master/scripts/decode_gateway_config.py) | Decode hashed config names |
| [decrypt_odj.py](https://github.com/talas9/tesla/blob/master/scripts/decrypt_odj.py) | Decrypt Odin job files |

---

## File Locations

| Path | Description |
|------|-------------|
| `/opt/odin/` | Odin installation directory |
| `/opt/odin/data/Model3/config-options.json` | Model 3 config database |
| `/opt/odin/data/ModelY/config-options.json` | Model Y config database |
| `/opt/odin/routines/` | Diagnostic routine scripts |

---

## Related Research

- [Gateway Config System](../2-gateway/config-system.md) - Uses Odin access levels
- [Gateway Security Model](../2-gateway/security-model.md) - Secure/insecure classification

---

**Status:** COMPLETE ✅  
**Last Updated:** 2026-02-07
