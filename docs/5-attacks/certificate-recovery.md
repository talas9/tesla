# Certificate Recovery

**Analysis of orphan vehicle certificate issues and Hermes authentication.**

---

## Overview

Tesla vehicles use Hermes mTLS certificates for backend authentication. When certificates expire without renewal, vehicles become "orphans" with limited functionality.

| Component | Value |
|-----------|-------|
| Certificate Path | `/var/lib/car_creds/car.crt` |
| Key Path | `/var/lib/hermes/car.key` |
| Validity Period | ~2 years |
| Renewal | Automatic, 30-90 days before expiry |

---

## Hermes Certificate System

### Purpose

Hermes provides mutual TLS authentication between vehicle and Tesla backend:

1. **Vehicle → Backend**: Proves vehicle identity
2. **Backend → Vehicle**: Confirms Tesla server authenticity
3. **Encrypted Channel**: All communications protected

### Certificate Chain

```
Tesla Root CA
    └── Intermediate CA
        └── Vehicle Certificate (per-VIN)
```

---

## Orphan Vehicle Scenario

### Causes

| Cause | Description |
|-------|-------------|
| Extended offline | No backend connectivity for renewal |
| Connectivity issues | Modem failure, cellular dropout |
| Account issues | Payment problems, account suspension |
| Import vehicles | Moved to unsupported region |

### Impact

| Feature | Status |
|---------|--------|
| Driving | ✅ Still works |
| Basic UI | ✅ Still works |
| Local features | ✅ Still works |
| OTA updates | ❌ Fails |
| Supercharging billing | ❌ Fails |
| Service access | ❌ Fails |
| Remote commands | ❌ Fails |
| Premium connectivity | ❌ Fails |

---

## Certificate Renewal Process

### Normal Flow

```
1. hermes_client monitors certificate expiry
2. 30-90 days before expiry → renewal request
3. Backend validates vehicle → issues new certificate
4. hermes_client installs new certificate
5. Service continues uninterrupted
```

### Renewal Failure

```
1. Certificate approaches expiry
2. No backend connectivity
3. Renewal request fails repeatedly
4. Certificate expires
5. Backend connections fail (certificate rejected)
6. Vehicle becomes "orphan"
```

---

## Certificate Storage

### File Locations

| File | Path | Purpose |
|------|------|---------|
| Certificate | `/var/lib/car_creds/car.crt` | Vehicle identity |
| Private Key | `/var/lib/hermes/car.key` | Signing/authentication |
| CA Bundle | `/etc/ssl/certs/ca-certificates.crt` | Chain validation |

### Certificate Format

```
-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIJAKxxxxxxxxxxxxxxxx
...
-----END CERTIFICATE-----
```

Standard X.509 format, PEM encoded.

---

## Recovery Options

### Option 1: Tesla Service Center

| Step | Description |
|------|-------------|
| 1 | Visit authorized service center |
| 2 | Technician connects via Toolbox |
| 3 | Backend issues new certificate |
| 4 | hermes_client installs certificate |

**Status:** ✅ VERIFIED (standard procedure)

### Option 2: Restore Connectivity

| Step | Description |
|------|-------------|
| 1 | Fix cellular/WiFi connectivity |
| 2 | Vehicle requests renewal |
| 3 | If within grace period → renewed |
| 4 | If expired → may require service visit |

**Status:** ⚠️ CONDITIONAL (depends on expiry state)

### Option 3: Manual Certificate Installation

| Step | Description |
|------|-------------|
| 1 | Obtain valid certificate (how?) |
| 2 | Access MCU filesystem (root required) |
| 3 | Replace certificate files |
| 4 | Restart hermes_client |

**Status:** ❌ THEORETICAL (requires certificate issuance)

---

## Hermes Client Analysis

### Binary Location

```
/usr/bin/hermes_client
```

### Key Functions

```cpp
HermesServiceClient::SendStreamMessageFinished()
HermesServiceClient::asyncSendStreamMessageWithByteArray()
ComTeslaHermesServiceInterface::SendCommandMessage()
```

### Certificate Handling

```cpp
hermes_client::loadCertificate()
hermes_client::validateChain()
hermes_client::renewCertificate()
```

---

## Security Considerations

### Certificate Forgery

**Is it possible?**

| Requirement | Status |
|-------------|--------|
| Tesla private key | ❌ Not available |
| Valid CA chain | ❌ Cannot forge |
| Backend bypass | ❌ Certificate pinning |

**Conclusion:** Certificate forgery is not practical.

### Man-in-the-Middle

| Attack | Feasibility |
|--------|-------------|
| Intercept renewal | ❌ mTLS prevents |
| Fake backend | ❌ Certificate pinning |
| DNS hijacking | ❌ Certificate validation |

---

## AWS Integration

### Certificate Delivery

```
Tesla Backend → AWS S3 presigned URL → Vehicle downloads certificate
```

**Evidence:** String analysis shows AWS S3 URL generation patterns.

### S3 URL Format

```
https://s3.amazonaws.com/tesla-xxx/certs/VIN-xxx.crt?
AWSAccessKeyId=xxx&Signature=xxx&Expires=xxx
```

---

## Outstanding Questions

### Unknown

1. Exact renewal trigger timing (30, 60, or 90 days?)
2. Grace period after expiry
3. Recovery process for long-expired certificates
4. Regional variations in certificate handling

### Needs Testing

1. Certificate extraction from running vehicle
2. Renewal packet capture
3. Backend API for certificate issuance

---

## Cross-References

- [Service Mode Authentication](service-mode.md) - Related authentication
- [Gateway Security Model](../2-gateway/security-model.md) - Hermes integration

---

**Status:** ⚠️ PARTIAL  
**Evidence:** Binary analysis, string extraction  
**Last Updated:** 2026-02-07
