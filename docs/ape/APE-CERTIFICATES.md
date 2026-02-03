# Tesla APE Certificate System - Complete Analysis

**Document Version:** 1.0  
**Analysis Date:** February 3, 2026  
**Target:** Autopilot ECU (APE) Certificate Infrastructure  
**Source:** APE Firmware 2024.8.9.ice.ape25  
**Status:** ✅ COMPLETE

---

## Executive Summary

The Tesla APE uses a comprehensive PKI (Public Key Infrastructure) for authentication and authorization. The system implements **mutual TLS (mTLS)** with TPM-backed device certificates, multi-tier Certificate Authorities, and Extended Key Usage (EKU) OIDs for role-based access control.

### Critical Security Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| **TPM-backed private keys** | ✅ SECURE | FSD TPM engine protects board private keys |
| **Self-signed fallback** | 🔴 CRITICAL | APE generates self-signed cert if `/var/lib/board_creds/` missing |
| **Factory mode disables cert checks** | 🟠 HIGH | Development/factory mode accepts ENG certs |
| **Certificate pinning** | ✅ SECURE | CA bundles pinned to specific issuers |
| **No certificate renewal documented** | 🟡 MEDIUM | Unclear how certificates are provisioned/renewed |

---

## Table of Contents

1. [Certificate Hierarchy](#1-certificate-hierarchy)
2. [Board Credentials (Device Certificates)](#2-board-credentials-device-certificates)
3. [TPM Integration (FSD TPM Engine)](#3-tpm-integration-fsd-tpm-engine)
4. [Certificate Authority Bundles](#4-certificate-authority-bundles)
5. [Extended Key Usage (EKU) OIDs](#5-extended-key-usage-eku-oids)
6. [Certificate Validation Flow](#6-certificate-validation-flow)
7. [Self-Signed Certificate Fallback](#7-self-signed-certificate-fallback)
8. [Certificate Storage Locations](#8-certificate-storage-locations)
9. [Certificate Renewal Mechanisms](#9-certificate-renewal-mechanisms)
10. [Certificate Replacement Procedures](#10-certificate-replacement-procedures)
11. [Attack Scenarios](#11-attack-scenarios)
12. [Recommendations](#12-recommendations)

---

## 1. Certificate Hierarchy

### 1.1 Tesla PKI Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                    Tesla Root CA (Not in APE)                    │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐    ┌──────────▼─────────┐   ┌──────────▼──────────┐
│  Products CA   │    │   Services CA      │   │  Fleet Management  │
│  (Vehicles)    │    │   (Backend APIs)   │   │  CA                │
└───────┬────────┘    └──────────┬─────────┘   └──────────┬─────────┘
        │                        │                         │
        │                        │                         │
┌───────▼──────────────────────────────────────────────────▼─────────┐
│              Intermediate Issuing CAs                               │
│  • Product Access Issuing CA (ECC P-521)                           │
│  • GF0 Product Issuing CA (Fremont factory)                        │
│  • GF3 Product Issuing CA (Shanghai factory)                       │
│  • GFAustin Product Issuing CA (Austin factory)                    │
│  • GFBerlin Product Issuing CA (Berlin factory)                    │
│  • China Product Access Issuing CA                                 │
│  • NXP SE Issuing CA (Secure Element)                              │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                      ┌───────────▼────────────┐
                      │  Board Certificates    │
                      │  /var/lib/board_creds/ │
                      │  • board.crt           │
                      │  • board.key (TPM)     │
                      └────────────────────────┘
```

### 1.2 Certificate Purposes

| CA Type | Purpose | Storage Location | Client Auth |
|---------|---------|------------------|-------------|
| **Product Access CA** | Board authentication (mTLS) | `/usr/share/tesla-certificates/current/combined/ProductAccessCAs.pem` | ✅ |
| **Products CA** | General vehicle components | `/usr/share/tesla-certificates/current/combined/ProductsCAs.pem` | ✅ |
| **Services CA** | Backend API authentication | `/usr/share/tesla-certificates/combined/ServicesCAsPrd.pem` | ❌ (Server auth) |
| **Fleet Management CA** | Fleet API access | `/usr/share/tesla-certificates/current/combined/FleetManagementCAs.pem` | ✅ |
| **Supercharger CA** | Supercharger network | `/usr/share/tesla-certificates/current/combined/SuperchargerCAs.pem` | ✅ |

---

## 2. Board Credentials (Device Certificates)

### 2.1 Storage Location

**Primary Location:** `/var/lib/board_creds/`

```bash
/var/lib/board_creds/
├── board.crt    # Device X.509 certificate
└── board.key    # Private key (TPM-backed or software)
```

**Note:** This directory does NOT exist in the extracted firmware. It is created at runtime and populated during:
- Factory provisioning
- Service center certificate installation
- First boot (self-signed fallback if missing)

### 2.2 Certificate Format

**board.crt** - X.509 v3 certificate:
```
Subject: CN=<VIN or board ID>, OU=PKI, O=Tesla, C=US
Issuer: CN=<Factory Issuing CA>, OU=PKI, O=Tesla, C=US
Public Key: ECC P-256 or RSA-2048
Extensions:
  - Extended Key Usage: 1.3.6.1.4.1.49279.2.5.22 (Product Access Client Auth - Production)
  - Subject Alternative Name: VIN, Serial Number
```

### 2.3 Private Key Formats

**TPM-Backed Key** (Preferred):
```
-----BEGIN FSD TPM PRIVATE KEY-----
<Base64-encoded TPM key blob>
-----END FSD TPM PRIVATE KEY-----
```

**Software Key** (Fallback):
```
-----BEGIN EC PRIVATE KEY-----
<Base64-encoded ECC private key>
-----END EC PRIVATE KEY-----
```

**Detection Logic:**
```bash
# From /etc/sv/service-api-tls/run
if grep -q "BEGIN FSD TPM PRIVATE KEY" "$KEY"; then
    ENGINE=fsdtpm
else
    ENGINE=sw
fi
```

---

## 3. TPM Integration (FSD TPM Engine)

### 3.1 FSD TPM Engine Architecture

The APE uses a custom OpenSSL engine called **fsdtpm** to interface with the Trusted Platform Module (TPM).

**Engine Selection:**
```bash
# service_api binary arguments
--engine fsdtpm     # Use TPM for private key operations
--engine sw         # Use software crypto (fallback)
```

**TPM Functions:**
- **Private key storage** - Keys never leave TPM
- **Signing operations** - TLS handshakes performed in TPM
- **Key attestation** - Prove key is TPM-backed
- **Secure boot chain** - Verify firmware integrity

### 3.2 TPM Access Binary

**Binary:** `/opt/autopilot/bin/read_device_key`  
**Permissions:** **SUID root** (setuid bit)  
**Size:** 52KB  
**Purpose:** Read TPM device key for certificate operations

**Security Risk:** This SUID binary is a **privilege escalation vector**. Any vulnerability in `read_device_key` could allow unprivileged users to extract TPM keys or perform arbitrary root operations.

### 3.3 TPM Key Generation

**Hypothesis:** Device keys are generated during:
1. **Factory provisioning** - TPM generates key, factory signs CSR
2. **Service center re-provisioning** - New key generated, re-signed by Tesla CA
3. **First boot** - If no key exists, APE generates self-signed cert

**Key Storage Locations (TPM):**
- **TPM NVRAM** - Non-volatile memory
- **TPM Key Hierarchy** - Owner hierarchy, endorsement hierarchy
- **Key Handle** - Persistent handle for board key

**Evidence:** The string `"BEGIN FSD TPM PRIVATE KEY"` suggests a custom key format. Reverse engineering `read_device_key` binary is required to understand:
- TPM key handle used
- TPM authorization methods (password, policy)
- Key export restrictions

---

## 4. Certificate Authority Bundles

### 4.1 Complete CA Bundle Inventory

**Location:** `/usr/share/tesla-certificates/`

#### Current CAs (Active)

| File | Purpose | Issuer Count |
|------|---------|--------------|
| `current/ProductAccessIssuingCA.pem` | Product Access authentication | 1 |
| `current/ProductIssuingCA.pem` | General product certificates | 1 |
| `current/GF0ProductIssuingCA.pem` | Fremont factory | 1 |
| `current/GF3ProductIssuingCA.pem` | Shanghai factory (ECC) | 1 |
| `current/GF3ProductRSAIssuingCA.pem` | Shanghai factory (RSA) | 1 |
| `current/GFAustinProductIssuingCA.pem` | Austin Gigafactory | 1 |
| `current/GFBerlinProductIssuingCA.pem` | Berlin Gigafactory | 1 |
| `current/ChinaProductAccessIssuingCA.pem` | China market vehicles | 1 |
| `current/NXPSEIssuingCA.pem` | NXP Secure Element | 1 |
| `current/ProductPartnersIssuingCA.pem` | Third-party partners | 1 |
| `current/TeslaEngFleetManagementCA.pem` | Engineering fleet | 1 |
| `current/TeslaProdFleetManagementCA.pem` | Production fleet API | 1 |

#### Combined CA Bundles

| File | Purpose | Use Case |
|------|---------|----------|
| `current/combined/ProductAccessCAs.pem` | All Product Access CAs | **service-api-tls mTLS** |
| `current/combined/ProductsCAs.pem` | All product CAs | General vehicle auth |
| `current/combined/FleetManagementCAs.pem` | Fleet API CAs | Fleet management |
| `current/combined/SuperchargerCAs.pem` | Supercharger network | Charging auth |

#### Legacy CAs (Backward Compatibility)

| File | Purpose | Status |
|------|---------|--------|
| `legacy/ProductsCAEng.pem` | Engineering products CA | **Accepted in dev/factory mode** |
| `legacy/ProductsCAPrd.pem` | Production products CA | Deprecated |
| `legacy/ServicesCAEng.pem` | Engineering services | Dev only |
| `legacy/ServicesCAPrd.pem` | Production services | Deprecated |

#### Services CAs (Backend)

| File | Environment | Purpose |
|------|-------------|---------|
| `combined/ServicesCAsPrd.pem` | Production | Tesla backend APIs |
| `combined/ServicesCAsEng.pem` | Engineering | Dev/test backend |
| `combined/ServicesCAsMfg.pem` | Manufacturing | Factory backend |

### 4.2 CA Certificate Analysis

**Product Access Issuing CA:**
```
Subject: CN=Tesla Product Access Issuing CA, OU=PKI, O=Tesla, C=US
Issuer: CN=Tesla Product Partners Issuing CA, OU=Products, OU=PKI, O=Tesla, C=US
Public Key: ECC P-521 (secp521r1)
Not Before: Dec 11, 2020
Not After: Oct 5, 2029
Key Usage: Digital Signature, Certificate Sign, CRL Sign
Basic Constraints: CA:TRUE, pathlen:0
```

**Significance:**
- **pathlen:0** - This is an intermediate CA, cannot issue sub-CAs
- **ECC P-521** - High-security elliptic curve
- **10-year validity** - Long-lived intermediate CA

### 4.3 Certificate Revocation

**CRL Distribution Points:**
```
http://pki.tesla.com/product/pki/Tesla_Product_Partners_Issuing_CA-1.crl
```

**OCSP (Online Certificate Status Protocol):** Not observed in CA certificates

**Implication:** APE must have network access to `pki.tesla.com` for CRL checking, OR certificate revocation is NOT enforced on APE.

**Test:** Check if APE firewall blocks `pki.tesla.com`. If blocked, revocation checking is disabled.

---

## 5. Extended Key Usage (EKU) OIDs

### 5.1 Tesla-Specific OIDs

**Enterprise Number:** 49279 (IANA-assigned to Tesla Motors)

**Base OID:** `1.3.6.1.4.1.49279`

### 5.2 Complete OID Registry

**From `/etc/tesla-certificates.vars`:**

| OID | Environment | Purpose | Variable Name |
|-----|-------------|---------|---------------|
| `1.3.6.1.4.1.49279.2.4.1` | Engineering | Motors client auth | `TESLA_CERTIFICATES_EKU_MOTORS_CLIENT_AUTH_ENG` |
| `1.3.6.1.4.1.49279.2.4.11` | Engineering | Board client auth | `TESLA_CERTIFICATES_EKU_MOTORS_BOARD_CLIENT_AUTH_ENG` |
| `1.3.6.1.4.1.49279.2.4.12` | Engineering | DAS client auth | `TESLA_CERTIFICATES_EKU_DAS_CLIENT_AUTH_ENG` |
| `1.3.6.1.4.1.49279.2.4.22` | Engineering | Product Access client auth | `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG` |
| `1.3.6.1.4.1.49279.2.5.22` | **Production** | Product Access client auth | `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD` |

### 5.3 OID Validation Logic

**service-api-tls startup:**
```bash
ARGS_OID_ENV="--oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD"
if is-development-ape || is-in-factory; then
    ARGS_OID_ENV="${ARGS_OID_ENV} --oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG"
fi
```

**Behavior:**
- **Production mode:** Only accept `2.5.22` (production) certificates
- **Development/Factory mode:** Accept both `2.5.22` (prod) AND `2.4.22` (engineering)

**Security Implication:** Triggering factory mode allows engineering certificates to authenticate to service-api-tls. If factory mode can be remotely triggered, this is a **critical vulnerability**.

---

## 6. Certificate Validation Flow

### 6.1 service-api-tls Authentication Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                    Client Connection Attempt                      │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
         ┌────────────────────────────────────────┐
         │  TLS Handshake (port 8081)             │
         │  Server presents: board.crt            │
         │  Server private key: board.key (TPM)   │
         └────────────────┬───────────────────────┘
                          │
                          ▼
         ┌────────────────────────────────────────┐
         │  Client Certificate Required (mTLS)    │
         │  Client presents certificate           │
         └────────────────┬───────────────────────┘
                          │
                          ▼
         ┌────────────────────────────────────────┐
         │  Validate Client Certificate Chain     │
         │  CA Bundle: ProductAccessCAs.pem       │
         └────────────────┬───────────────────────┘
                          │
                ┌─────────▼──────────┐
                │  Chain valid?      │
                └─────┬──────────┬───┘
                      │ NO       │ YES
                ┌─────▼──┐       ▼
                │ REJECT │   ┌───────────────────────┐
                └────────┘   │ Check EKU OID         │
                             └───────┬───────────────┘
                                     │
                         ┌───────────▼──────────────┐
                         │ OID matches allowed list? │
                         │ - 2.5.22 (always)         │
                         │ - 2.4.22 (if dev/factory) │
                         └───────┬──────────┬────────┘
                                 │ NO       │ YES
                            ┌────▼───┐      ▼
                            │ REJECT │  ┌────────────┐
                            └────────┘  │  ACCEPT    │
                                        │  Authorize │
                                        └────────────┘
```

### 6.2 Hermes Backend Authentication

**Hermes service:** `/opt/hermes/hermes`

**TLS Configuration:**
```bash
# From /etc/sv/hermes/run
HERMES_ENGINE="--engine=fsdtpm"
```

**CA Bundle:** Uses `ServicesCAsPrd.pem` for backend server validation

**Flow:**
1. Hermes connects to Tesla backend (e.g., `https://hermes.tesla.com`)
2. Server presents certificate signed by Services CA
3. Hermes validates server cert against `ServicesCAsPrd.pem`
4. Hermes presents `board.crt` for mTLS client auth
5. Backend validates board cert against Product Access CA

---

## 7. Self-Signed Certificate Fallback

### 7.1 Fallback Trigger Conditions

**Triggers self-signed certificate generation if:**
- `/var/lib/board_creds/board.crt` does NOT exist
- `/var/lib/board_creds/board.key` does NOT exist

### 7.2 Self-Signed Certificate Generation

**Location:** Defined in `/etc/sv/service-api-tls/run`

**Generation Process:**
```bash
# Fallback to self-signed certificate
SELF_DIR=/var/run/service-api
PARAM_FILE=$SELF_DIR/server.param
SELF_CERT=$SELF_DIR/server.crt
SELF_KEY=$SELF_DIR/server.key

# Create directory
mkdir -p -m 0750 "$SELF_DIR" || exit 1

# Get device identifier
ID=$(videntify) || ID=unprovisioned

# Generate ECC P-256 key
openssl ecparam -name prime256v1 > "$PARAM_FILE"

# Generate self-signed certificate (1 year validity)
openssl req -new \
    -x509 \
    -nodes \
    -newkey ec:"$PARAM_FILE" \
    -keyout "$SELF_KEY" \
    -subj "/CN=$ID/OU=Tesla Motors/O=Tesla/L=Palo Alto/ST=California/C=US" \
    -days 365 \
    -out "$SELF_CERT"

# Set permissions
chmod 640 "$SELF_KEY" "$SELF_CERT"
```

**Generated Certificate Details:**
- **Subject:** `CN=<VIN or unprovisioned>, OU=Tesla Motors, O=Tesla, L=Palo Alto, ST=California, C=US`
- **Public Key:** ECC P-256 (prime256v1)
- **Validity:** 365 days
- **Issuer:** Self (same as Subject)
- **Storage:** `/var/run/service-api/server.crt` (tmpfs, not persistent)

### 7.3 Security Implications

**🔴 CRITICAL VULNERABILITY:**

1. **No client authentication:** Self-signed cert is NOT in ProductAccessCAs.pem, so clients cannot validate it
2. **MITM possible:** Attacker can generate own self-signed cert
3. **Unauthenticated mode:** If board creds are deleted, APE enters insecure mode

**Attack Scenario:**
```
1. Delete /var/lib/board_creds/board.crt and board.key
2. Reboot APE
3. service-api-tls generates self-signed certificate
4. Client connections cannot validate certificate (will accept any cert)
5. Attacker can MITM connections to port 8081
```

**Mitigation:** service_api should **reject all connections** if no valid board credentials exist. Self-signed fallback should be disabled in production builds.

---

## 8. Certificate Storage Locations

### 8.1 Complete Certificate Inventory

**CA Certificates (Read-Only):**
```
/usr/share/tesla-certificates/
├── combined/
│   ├── ProductsCAs.pem
│   ├── ServicesCAs.pem
│   ├── ServicesCAsEng.pem
│   ├── ServicesCAsMfg.pem
│   └── ServicesCAsPrd.pem
├── current/
│   ├── ProductAccessIssuingCA.pem
│   ├── ProductIssuingCA.pem
│   ├── GF0ProductIssuingCA.pem
│   ├── GF3ProductIssuingCA.pem
│   ├── GF3ProductRSAIssuingCA.pem
│   ├── GFAustinProductIssuingCA.pem
│   ├── GFBerlinProductIssuingCA.pem
│   ├── ChinaProductAccessIssuingCA.pem
│   ├── NXPSEIssuingCA.pem
│   ├── ProductPartnersIssuingCA.pem
│   ├── ProductRSAIssuingCA.pem
│   ├── TeslaEngFleetManagementCA.pem
│   ├── TeslaProdFleetManagementCA.pem
│   └── combined/
│       ├── ProductAccessCAs.pem
│       ├── ProductsCAs.pem
│       ├── FleetManagementCAs.pem
│       └── SuperchargerCAs.pem
└── legacy/
    ├── ProductsCAEng.pem
    ├── ProductsCAPrd.pem
    ├── ServicesCAEng.pem
    └── ServicesCAPrd.pem
```

**System CA Bundle:**
```
/etc/ssl/certs/ca-certificates.crt  - Standard Linux CA bundle (Amazon, GlobalSign, etc.)
```

**Board Credentials (Runtime):**
```
/var/lib/board_creds/
├── board.crt  - Device certificate
└── board.key  - TPM-backed or software private key
```

**Self-Signed Fallback (Temporary):**
```
/var/run/service-api/
├── server.crt  - Self-signed certificate
└── server.key  - Software-generated private key
```

### 8.2 Filesystem Permissions

**CA Certificates:**
```bash
# All world-readable
-rw-r--r--  /usr/share/tesla-certificates/current/ProductAccessIssuingCA.pem
```

**Board Credentials:**
```bash
# Expected permissions (not in extracted firmware):
drwx------  root root  /var/lib/board_creds/
-rw-------  root root  /var/lib/board_creds/board.crt
-rw-------  root root  /var/lib/board_creds/board.key
```

**Self-Signed (Fallback):**
```bash
drwxr-x---  root root  /var/run/service-api/
-rw-r-----  root root  /var/run/service-api/server.crt
-rw-r-----  root root  /var/run/service-api/server.key
```

---

## 9. Certificate Renewal Mechanisms

### 9.1 Certificate Lifecycle

**Board Certificate Validity:** Unknown (not present in extracted firmware)

**Typical Validity Periods:**
- **Production board certs:** 1-5 years
- **Engineering certs:** 1 year
- **Self-signed:** 1 year (365 days)

### 9.2 Renewal Methods (Hypothesized)

**Method 1: Factory Re-Provisioning**
- Vehicle returns to service center
- Technician connects diagnostic tool
- New certificate signed by Tesla CA
- Certificate and key written to `/var/lib/board_creds/`

**Method 2: OTA Certificate Update**
- Backend pushes new certificate via Hermes
- Certificate renewal script runs
- New cert installed, old cert replaced
- **Risk:** If private key is also transmitted, this is insecure

**Method 3: Automatic CSR Generation**
- APE generates Certificate Signing Request (CSR)
- CSR sent to Tesla backend via Hermes
- Backend signs CSR with Product Access CA
- New certificate returned and installed

### 9.3 Evidence of Renewal Mechanism

**No direct evidence found in firmware.** However:

**Potential renewal scripts:**
```bash
# Not found in extraction:
/usr/bin/renew-certificate
/opt/autopilot/bin/cert-renewer
```

**Hermes teleforce commands:** The `hermes_teleforce` binary (9.6MB) supports remote command execution. Certificate renewal could be implemented via teleforce scripts.

**Research Task:** Reverse engineer `hermes_teleforce` to identify certificate renewal commands.

---

## 10. Certificate Replacement Procedures

### 10.1 Manual Certificate Replacement

**Prerequisite:** Root access to APE filesystem

**Procedure:**
```bash
# 1. Stop services using certificates
sv stop service-api-tls
sv stop hermes

# 2. Backup existing credentials
cp /var/lib/board_creds/board.crt /var/lib/board_creds/board.crt.backup
cp /var/lib/board_creds/board.key /var/lib/board_creds/board.key.backup

# 3. Install new certificate
cat > /var/lib/board_creds/board.crt <<EOF
-----BEGIN CERTIFICATE-----
<Base64-encoded X.509 certificate>
-----END CERTIFICATE-----
EOF

# 4a. Install TPM-backed key (if available)
cat > /var/lib/board_creds/board.key <<EOF
-----BEGIN FSD TPM PRIVATE KEY-----
<Base64-encoded TPM key blob>
-----END FSD TPM PRIVATE KEY-----
EOF

# 4b. OR install software key (insecure fallback)
cat > /var/lib/board_creds/board.key <<EOF
-----BEGIN EC PRIVATE KEY-----
<Base64-encoded ECC private key>
-----END EC PRIVATE KEY-----
EOF

# 5. Set permissions
chmod 600 /var/lib/board_creds/board.crt
chmod 600 /var/lib/board_creds/board.key

# 6. Restart services
sv start service-api-tls
sv start hermes

# 7. Verify certificate
openssl x509 -in /var/lib/board_creds/board.crt -noout -text
```

### 10.2 Certificate Injection via Factory Mode

**Attack Scenario:**
1. Trigger factory mode (HTTP API or sentinel file)
2. Connect to APE via SSH or local console
3. Replace `/var/lib/board_creds/board.crt` with attacker's certificate
4. Install corresponding private key
5. Restart services
6. APE now authenticates with attacker's certificate

**Defense:** Factory mode should require physical access (GPIO pin, UART console) to prevent remote exploitation.

### 10.3 Certificate Signing Request (CSR) Generation

**Generate CSR for re-signing:**
```bash
# Generate new ECC P-256 key
openssl ecparam -name prime256v1 -genkey -noout -out new_board.key

# Generate CSR
VIN=$(videntify)
openssl req -new \
    -key new_board.key \
    -subj "/CN=$VIN/OU=PKI/O=Tesla/C=US" \
    -out board.csr

# Send CSR to Tesla for signing
# (Method unknown - likely via Hermes or diagnostic tool)

# Install signed certificate
mv signed_board.crt /var/lib/board_creds/board.crt
mv new_board.key /var/lib/board_creds/board.key
```

---

## 11. Attack Scenarios

### 11.1 Certificate Theft

**Objective:** Extract board certificate and private key

**Attack Paths:**
1. **Root filesystem access** - Read `/var/lib/board_creds/`
2. **Memory dump** - Extract key from service_api process memory
3. **TPM exploitation** - Extract key from TPM (very difficult)
4. **Network sniffing** - Capture TLS handshake (won't reveal private key)

**Mitigation:**
- TPM-backed keys prevent extraction
- Encrypted filesystems protect at-rest data
- AppArmor profiles restrict process access

### 11.2 Certificate Replacement Attack

**Objective:** Replace legitimate certificate with attacker-controlled cert

**Steps:**
1. Delete `/var/lib/board_creds/board.crt` and `board.key`
2. Reboot APE → triggers self-signed fallback
3. OR: Install attacker's certificate signed by compromised CA
4. OR: Exploit factory mode to disable certificate validation

**Impact:**
- Attacker can authenticate to Tesla backend as victim vehicle
- Impersonate vehicle in service-api-tls connections
- Send fraudulent telemetry data
- Receive commands intended for victim vehicle

**Mitigation:**
- Certificate pinning (require specific CA)
- Certificate transparency logs
- Anomaly detection (certificate change alerts)

### 11.3 Engineering Certificate Downgrade

**Objective:** Use engineering certificate to authenticate in production

**Steps:**
1. Obtain engineering certificate (leak, insider threat, old cert)
2. Trigger factory mode on target APE
3. Factory mode accepts engineering OID `2.4.22`
4. Authenticate with engineering cert

**Impact:**
- Bypass production authentication
- Access development endpoints
- Potentially unlock hidden features

**Mitigation:**
- Ensure factory mode cannot be remotely triggered
- Revoke all engineering certificates in production builds
- Remove legacy CAs from production firmware

### 11.4 Self-Signed Certificate MITM

**Objective:** Man-in-the-Middle attack when APE uses self-signed cert

**Steps:**
1. Force APE into self-signed mode (delete board creds)
2. Client connects to service-api-tls on port 8081
3. Client receives self-signed cert (not in CA bundle)
4. Client must choose: accept untrusted cert or reject
5. If client accepts, attacker can intercept/modify traffic

**Impact:**
- Decrypt TLS traffic
- Inject malicious commands
- Exfiltrate sensitive data

**Mitigation:**
- Clients must reject connections to self-signed certs
- service_api should refuse to start without valid board creds

---

## 12. Recommendations

### 12.1 Immediate Fixes

1. **Disable self-signed fallback in production builds**
   - service-api-tls should exit with error if no board creds
   - Force manual intervention to restore certificates

2. **Restrict factory mode activation**
   - Require physical access (UART console, GPIO pin)
   - Remove HTTP API for factory mode entry

3. **Revoke engineering certificates**
   - Remove `legacy/ProductsCAEng.pem` from production builds
   - Blacklist engineering OIDs in production mode

4. **Implement certificate transparency**
   - Log all certificate changes
   - Alert on unexpected certificate replacement

### 12.2 Long-Term Improvements

1. **Hardware-backed certificate storage**
   - Store board certificate in TPM NVRAM (not filesystem)
   - Require TPM authorization to read certificate

2. **Automatic certificate rotation**
   - Implement CSR generation and renewal
   - Backend-initiated certificate refresh (yearly)

3. **Certificate pinning**
   - Pin expected certificate in firmware update manifest
   - Reject firmware if certificate doesn't match

4. **Mutual TLS everywhere**
   - Extend mTLS to all internal services (not just port 8081)
   - APE ↔ MCU communication should use mTLS

### 12.3 Security Monitoring

1. **Certificate change detection**
   - Monitor `/var/lib/board_creds/` for modifications
   - Alert if certificate subject changes

2. **Anomaly detection**
   - Flag connections with unexpected client certificates
   - Detect use of engineering certificates in production

3. **CRL/OCSP enforcement**
   - Ensure certificate revocation checking is enabled
   - Block connections if CRL cannot be fetched

---

## Appendix A: Certificate Extraction Commands

### Extract CA Certificate Details
```bash
openssl x509 -in /usr/share/tesla-certificates/current/ProductAccessIssuingCA.pem \
    -noout -text -subject -issuer -dates -ext extendedKeyUsage
```

### Verify Certificate Chain
```bash
openssl verify -CAfile /usr/share/tesla-certificates/current/combined/ProductAccessCAs.pem \
    /var/lib/board_creds/board.crt
```

### Check Certificate EKU OIDs
```bash
openssl x509 -in /var/lib/board_creds/board.crt -noout -ext extendedKeyUsage
```

### Test TLS Connection
```bash
openssl s_client -connect 192.168.90.103:8081 \
    -CAfile /usr/share/tesla-certificates/current/combined/ProductAccessCAs.pem \
    -cert client.crt -key client.key
```

---

## Appendix B: TPM Research Tasks

### Priority Research Questions

1. **TPM key handle:** What persistent handle stores the board private key?
2. **TPM authorization:** Password? Policy-based? None?
3. **Key attestation:** Can we prove key is TPM-backed?
4. **Key export:** Is key exportable or sealed to TPM?
5. **TPM reset:** What happens to keys if TPM is reset?

### Reverse Engineering Targets

1. **`/opt/autopilot/bin/read_device_key`** (SUID root)
   - Identify TPM commands used
   - Find key handle references
   - Check for vulnerabilities (buffer overflows, path traversal)

2. **`service_api` binary** (6.9MB Go binary)
   - Locate fsdtpm engine code
   - Understand TPM signing operations
   - Analyze certificate validation logic

---

**Document Complete**  
**Next Steps:** Reverse engineer TPM binaries, test certificate replacement, analyze hermes_teleforce renewal mechanism
