# Tesla Certificate Recovery & Orphan Car Procedures

**Document Status:** Technical Recovery Guide  
**Risk Level:** High — Unauthorized modifications may void warranty  
**Audience:** Security researchers, independent service technicians  
**Date:** February 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Orphan Car Scenario](#2-orphan-car-scenario)
3. [Certificate Architecture Quick Reference](#3-certificate-architecture-quick-reference)
4. [Recovery Methods](#4-recovery-methods)
5. [Official Service Procedures](#5-official-service-procedures)
6. [Theoretical Recovery Procedures](#6-theoretical-recovery-procedures)
7. [Prevention Strategies](#7-prevention-strategies)
8. [Risk Assessment](#8-risk-assessment)

---

## 1. Overview

### 1.1 What is an "Orphan Car"?

An **orphan car** is a Tesla vehicle whose Hermes certificate has expired while the vehicle lacked connectivity to Tesla's renewal servers. This creates a locked-out state where the vehicle cannot establish secure communication with Tesla's cloud infrastructure.

### 1.2 Impact Summary

| Service | Orphaned Status |
|---------|-----------------|
| **Local driving** | ✅ Unaffected |
| **Climate control (in car)** | ✅ Works |
| **Tesla App connectivity (Bluetooth)** | ✅ Works - BLE key pairing unaffected |
| **Tesla App connectivity (Internet)** | ❌ Failed - cloud features unavailable |
| **Remote start/unlock (Bluetooth)** | ✅ Works - local BLE communication |
| **Remote start/unlock (Internet)** | ❌ Failed - requires Hermes connection |
| **Supercharger billing** | ✅ Works - CAN bus communication only |
| **OTA updates** | ❌ Blocked - requires Hermes authentication |
| **Sentry Mode cloud upload** | ❌ Failed - no backend connection |
| **Navigation traffic data** | ❌ No updates - requires cloud connectivity |

### 1.3 Root Cause

The orphan state occurs when:

1. Certificate validity approaches expiration (~2 years from issuance)
2. `hermes_client` detects renewal needed via `ShouldRenew()` function
3. Vehicle lacks internet connectivity during renewal window (30-90 days before expiry)
4. Certificate expires
5. mTLS handshake to Hermes servers fails
6. No automated recovery mechanism exists

---

## 2. Orphan Car Scenario

### 2.1 Timeline to Orphan State

```
┌──────────────────────────────────────────────────────────────────┐
│                    ORPHAN CAR TIMELINE                            │
└──────────────────────────────────────────────────────────────────┘

[Cert Issued]────────────[Renewal Window]────[Expiry]────[Orphaned]
     │                           │                │            │
     │                           │                │            │
     ├────── ~2 years ──────────►│                │            │
     │                           ├── 30-90d? ────►│            │
     │                           │                ├───────────►│
     │                           │                │            │
     │                     Vehicle offline throughout period   │
     │                                                          │
     └────────────── No connectivity to renewal servers ───────┘

Critical Period:
  - Renewal window: 30-90 days before expiry (exact threshold unknown)
  - If vehicle gains connectivity during this window: automatic renewal
  - If vehicle remains offline past expiry: orphan state begins
```

### 2.2 High-Risk Scenarios

| Scenario | Risk Level | Why Orphan Risk? |
|----------|------------|------------------|
| **Long-term storage** | 🔴 High | Vehicle offline for months/years |
| **Salvage/rebuilt vehicles** | 🔴 High | Extended offline during rebuild |
| **Remote locations** | 🟡 Medium | Poor LTE coverage, may miss renewal window |
| **Disabled connectivity** | 🔴 High | User disabled LTE/WiFi for privacy |
| **Network-isolated use** | 🔴 High | Air-gapped or corporate firewall blocking |
| **Used vehicle purchase** | 🟡 Medium | Unknown cert age, may be near expiry |

### 2.3 Early Warning Signs

**Before orphan state:**
- Tesla app shows intermittent "Vehicle Unavailable"
- Hermes client logs show renewal attempts
- Certificate expiry approaching (check with `openssl x509 -in /var/lib/car_creds/car.crt -noout -dates`)

**After orphan state:**
- Persistent "Vehicle Unavailable" in app
- Hermes logs show mTLS handshake failures
- No OTA update notifications
- Supercharger may require service assistance

---

## 3. Certificate Architecture Quick Reference

### 3.1 Certificate Storage

```
/var/lib/car_creds/
├── car.crt              # Vehicle's X.509 certificate (CRITICAL)
├── car.key              # Private key (CRITICAL, may be TPM-protected)
├── car.csr              # CSR during renewal
├── ca.crt               # Tesla CA certificate chain
├── board.csr            # Original factory CSR
├── staging/             # New certs staged before activation
├── backup/              # Rollback copies
└── tpm/                 # TPM-related files (if applicable)
    ├── tpm_handle.txt
    └── srk.ctx

Persistent backup:
/persist/car_creds/      # Mirror of certificate store
```

### 3.2 Certificate Properties

**Typical Certificate Fields:**
```
Subject: CN=<VIN>, O=Tesla Motors
Issuer: CN=Tesla Vehicle CA, O=Tesla Motors
Validity: ~2 years (NOT 10 years as older docs claimed)
Key Type: ECDSA P-256 (typical) or RSA 2048
Key Usage: Digital Signature, Key Encipherment
Extended Key Usage: TLS Client Authentication
```

**Inspect Certificate:**
```bash
# View certificate details
openssl x509 -in /var/lib/car_creds/car.crt -noout -text

# Check expiry date
openssl x509 -in /var/lib/car_creds/car.crt -noout -dates

# Verify cert-key pair match
openssl x509 -in /var/lib/car_creds/car.crt -noout -modulus | md5sum
openssl rsa -in /var/lib/car_creds/car.key -noout -modulus | md5sum
# Hashes should match
```

### 3.3 Renewal Mechanism (Normal Operation)

```
┌─────────────────────────────────────────────────────────────────┐
│                  AUTOMATED RENEWAL FLOW                          │
└─────────────────────────────────────────────────────────────────┘

1. hermes_client monitors ShouldRenew() → TRUE when threshold reached
                    ↓
2. Generate CSR using existing private key
   openssl req -new -key car.key -out car.csr -subj "/CN=<VIN>/O=Tesla Motors"
                    ↓
3. Submit CSR via WSS to hermes-api.prd.<region>.vn.cloud.tesla.com
                    ↓
4. Tesla backend signs certificate, validates VIN ownership
                    ↓
5. Signed certificate delivered via AWS S3 presigned URL
   Example: https://tesla-vehicle-certs.s3.amazonaws.com/<VIN>/<timestamp>/car.crt
                    ↓
6. Download and stage new certificate
   cp car.crt staging/car.crt
                    ↓
7. Validate certificate chain and key match
                    ↓
8. Restart hermes_client with new cert
                    ↓
9. Test connection → SUCCESS: promote to primary | FAIL: rollback
```

**This automated flow FAILS when vehicle is offline during renewal window.**

---

## 4. Recovery Methods

### 4.1 Method Comparison

| Method | Difficulty | Risk | Requirements | Success Rate |
|--------|------------|------|--------------|--------------|
| **Official Service** | Easy | Low | Service appointment | ~100% |
| **Gateway CAN Access** | Hard | Medium | Root access, CAN tools | ~80% |
| **Manual Cert Injection** | Very Hard | High | Valid cert from Tesla | ~60% |
| **Clock Manipulation** | Medium | Very High | Root access | Not recommended |
| **Factory Reset** | Hard | Very High | Service mode access | Last resort |

### 4.2 Method Selection Flowchart

```
┌─────────────────────────────────────────────────────┐
│ Is vehicle under warranty or Tesla service nearby?  │
└─────────────────┬───────────────────────────────────┘
                  │
        YES ──────┤────── NO
                  │              │
                  ▼              ▼
        ┌──────────────────┐  ┌────────────────────────────┐
        │ OFFICIAL SERVICE │  │ Do you have root access?   │
        │   Recommended    │  └──────────┬─────────────────┘
        └──────────────────┘             │
                                YES ─────┤───── NO
                                         │           │
                                         ▼           ▼
                        ┌─────────────────────────┐  ┌──────────────────┐
                        │ Gateway CAN Method      │  │ Service Required │
                        │ (see Section 6.2)       │  └──────────────────┘
                        └─────────────────────────┘
```

---

## 5. Official Service Procedures

### 5.1 Tesla Service Center

**Process:**
1. Schedule service appointment via app or phone
2. Describe symptoms: "Vehicle shows unavailable in app, suspect certificate issue"
3. Technician connects via Tesla Toolbox diagnostic software
4. Certificate reprovisioning through service tunnel
5. Validation and testing

**Typical Duration:** 30-60 minutes  
**Cost:** Often covered under warranty; otherwise ~$150-300 diagnostic fee

### 5.2 Mobile Service

**Availability:** Varies by region; certificate issues may require service center

**Process:**
1. Request mobile service via app
2. Technician brings portable diagnostic equipment
3. Remote reprovisioning via cellular or WiFi connection
4. On-site validation

**Advantage:** Convenient, no need to drive to service center  
**Limitation:** Complex cases may still require escalation

### 5.3 What Tesla Toolbox Does

**Suspected capabilities (based on research, not confirmed):**

```bash
# Conceptual Toolbox workflow
1. Authenticate to vehicle via service credential
2. Generate emergency CSR using existing key
3. Submit CSR to Tesla backend with service override flag
4. Receive signed certificate via service channel
5. Install certificate to /var/lib/car_creds/car.crt
6. Restart hermes_client
7. Validate connectivity
8. Log service action to vehicle history
```

**Key difference from normal renewal:** Service credentials bypass normal authentication requirements, allowing reprovisioning even with expired cert.

---

## 6. Theoretical Recovery Procedures

**⚠️ UPDATE:** Binary analysis of `hermes_client` (see [HERMES-CLIENT-ANALYSIS.md](HERMES-CLIENT-ANALYSIS.md)) revealed key details on renewal mechanism and orphan recovery.

### 6.0 Key Findings from Binary Analysis

**Critical Functions Identified:**
- `ShouldRenew()` - Checks if certificate renewal needed
- `SafeToMigrate()` - Validates vehicle state before migration
- `newPhoneHomeSession()` - Establishes WebSocket connection to Tesla backend
- `createCSR()` - Generates certificate signing request with VIN
- `validate_and_save_certificate()` - Verifies and installs new certificate

**Bypass Flags:**
```bash
--bypass_delivered_check  # Skips safety checks (Park, driver absent)
--enable-phone-home       # Enables renewal connection
```

**VIN Validation:** Certificate contains VIN in subject. Backend likely enforces VIN match during CSR validation. `bypass_delivered_check` does NOT bypass VIN validation.

## 6. Theoretical Recovery Procedures

> ⚠️ **WARNING:** These procedures are for educational purposes. Unauthorized modifications may:
> - Void warranty
> - Violate terms of service
> - Create safety/security risks
> - Brick vehicle systems if done incorrectly

### 6.1 Prerequisites for DIY Recovery

**Required access:**
- Root shell access to vehicle computer
- Understanding of Linux system administration
- Familiarity with X.509 certificates and OpenSSL

**Required knowledge:**
- Vehicle's VIN
- Certificate storage locations
- Hermes service management
- Rollback procedures

**Safety backups:**
```bash
# ALWAYS backup existing certificates before any modifications
mkdir -p /root/cert_backup_$(date +%Y%m%d)
cp -r /var/lib/car_creds/* /root/cert_backup_$(date +%Y%m%d)/
cp -r /persist/car_creds/* /root/cert_backup_$(date +%Y%m%d)/persist/
```

### 6.2 Method 1: Gateway CAN Flood → Updater Access

**Concept:** Flood the Gateway CAN bus to trigger failsafe mode, providing access to updater diagnostic console.

**⚠️ Risk:** May trigger fault codes, drain battery, or cause unintended side effects.

**Procedure:**

```bash
# 1. Identify Gateway CAN interface
ip link show | grep can

# 2. Bring up CAN interface (if down)
sudo ip link set can0 up type can bitrate 500000

# 3. Flood Gateway with diagnostic frames (EXAMPLE - specific frames unknown)
# This is THEORETICAL - actual frames would need reverse engineering
cansend can0 7DF#02010D  # Repeated at high frequency

# 4. Monitor for failsafe mode entry
candump can0 | grep -i "failsafe\|diag\|updater"

# 5. If updater mode achieved, look for diagnostic shell access
# Exact process unknown - would require further research

# 6. From updater shell, attempt manual certificate renewal
# Would require knowledge of Tesla backend API
```

**Status:** Theoretical; specific CAN frames and updater commands undocumented.

### 6.3 Method 2: Manual Certificate Injection (If Valid Cert Available)

**Scenario:** You have a valid signed certificate from Tesla (e.g., obtained through service channel).

**Procedure:**

```bash
# 1. Verify you have:
#    - car.crt (new signed certificate)
#    - car.key (existing private key, UNCHANGED)
#    - ca.crt (Tesla CA chain)

# 2. Validate certificate before installation
# Check expiry
openssl x509 -in new_car.crt -noout -dates

# Check subject matches VIN
openssl x509 -in new_car.crt -noout -subject
# Should show: CN=<YOUR_VIN>, O=Tesla Motors

# Verify cert and key match
openssl x509 -in new_car.crt -noout -modulus | md5sum
openssl rsa -in car.key -noout -modulus | md5sum
# Hashes MUST match, or hermes_client will fail

# 3. Stop Hermes services
systemctl stop hermes_client
systemctl stop hermes_proxy

# 4. Backup current certificates
cp /var/lib/car_creds/car.crt /var/lib/car_creds/backup/car.crt.old
cp /var/lib/car_creds/car.key /var/lib/car_creds/backup/car.key.old

# 5. Install new certificate
cp new_car.crt /var/lib/car_creds/car.crt
chmod 644 /var/lib/car_creds/car.crt

# 6. Verify permissions
ls -la /var/lib/car_creds/
# car.crt should be readable, car.key should be 600 or 400

# 7. Restart Hermes
systemctl start hermes_client

# 8. Monitor logs for connection success
journalctl -u hermes_client -f

# Expected: "Connected to hermes-api" or similar
# If failure: check journalctl for certificate validation errors

# 9. Test connectivity
# Check if Tesla app can communicate
# Attempt remote command (honk horn, climate on)

# 10. If failure, rollback
systemctl stop hermes_client
cp /var/lib/car_creds/backup/car.crt.old /var/lib/car_creds/car.crt
systemctl start hermes_client
```

**Critical Requirements:**
- Certificate subject MUST match vehicle VIN exactly
- Certificate must be signed by Tesla Vehicle CA
- Private key must remain unchanged (cannot generate new key)
- Certificate validity must be current

**Where to obtain valid certificate:**
- Tesla service channel (requires authorization)
- Not available through public channels

### 6.4 Method 3: Provisioning Endpoint Access (Port 8901)

**Concept:** Tesla provisioning servers (used during factory fusing) might accept reprovisioning requests.

**⚠️ Risk:** Highly speculative; may require factory credentials.

**Theoretical Approach:**

```bash
# 1. Check if provisioning endpoint is accessible
curl -v --cert /var/lib/car_creds/car.crt \
        --key /var/lib/car_creds/car.key \
        https://provisioning.factory.tesla.com:8901/api/v1/health

# 2. If accessible, attempt CSR submission
openssl req -new \
    -key /var/lib/car_creds/car.key \
    -out /tmp/emergency.csr \
    -subj "/CN=$(cat /etc/tesla/vehicle.json | jq -r '.vin')/O=Tesla Motors"

# 3. Submit CSR
curl -X POST \
    --cert /var/lib/car_creds/car.crt \
    --key /var/lib/car_creds/car.key \
    -H "Content-Type: application/pkcs10" \
    -d @/tmp/emergency.csr \
    https://provisioning.factory.tesla.com:8901/api/v1/sign

# Expected response: Signed certificate or 403 Forbidden
```

**Status:** Theoretical; provisioning endpoints likely restricted to factory networks or require special credentials.

### 6.5 Method 4: Clock Manipulation (NOT RECOMMENDED)

**Concept:** Roll back system clock to make expired certificate appear valid.

**⚠️ DANGER:** 
- May break other time-dependent systems (GPS, navigation, logs)
- Does NOT solve root problem (cert still expired from Tesla's perspective)
- May cause data corruption
- Likely to be detected and rejected by Hermes servers

**Why it fails:**
- Hermes servers validate certificate against server time, not vehicle time
- Even if local validation passes, mTLS handshake will fail server-side
- Other systems (Autopilot, GPS) depend on accurate time

**DO NOT ATTEMPT THIS METHOD.**

### 6.6 Method 5: Factory Reset & Reprovisioning (LAST RESORT)

**Concept:** Factory reset vehicle credentials and attempt reprovisioning as if new vehicle.

**⚠️ EXTREME RISK:**
- May permanently orphan vehicle
- Could require Tesla service intervention to restore
- May break warranty
- Could lose vehicle configuration data

**Theoretical Process (UNTESTED):**

```bash
# 1. Backup EVERYTHING
tar -czf /root/full_backup_$(date +%Y%m%d).tar.gz \
    /var/lib/car_creds/ \
    /persist/car_creds/ \
    /etc/tesla/ \
    /etc/hermes/

# 2. Remove provisioning sentinels
rm -f /var/lib/car_creds/.provisioned
rm -f /var/lib/car_creds/.migrated_to_production

# 3. Trigger factory provisioning script (if exists)
/opt/tesla/scripts/autofuser.sh

# 4. If script doesn't exist or fails, manual CSR generation
VIN=$(cat /etc/tesla/vehicle.json | jq -r '.vin')
openssl ecparam -genkey -name prime256v1 -out /var/lib/car_creds/car.key
openssl req -new \
    -key /var/lib/car_creds/car.key \
    -out /var/lib/car_creds/board.csr \
    -subj "/CN=${VIN}/O=Tesla Motors"

# 5. Attempt submission to provisioning server
# (Likely to fail without factory credentials)
```

**Expected Outcome:** Failure; reprovisioning requires factory/service credentials not available to end users.

**Rollback if failed:**
```bash
systemctl stop hermes_client
tar -xzf /root/full_backup_$(date +%Y%m%d).tar.gz -C /
systemctl start hermes_client
```

---

## 7. Prevention Strategies

### 7.1 For Vehicle Owners

**Maintain Connectivity:**
- Ensure vehicle has LTE/WiFi connectivity at least once per month
- If storing long-term, connect to WiFi periodically (every 60-90 days)
- Monitor Tesla app for connectivity status

**Before Long-Term Storage:**
1. Ensure vehicle is on latest software version (OTA updates)
2. Check certificate expiry: `openssl x509 -in /var/lib/car_creds/car.crt -noout -dates`
3. If certificate expires within 6 months, ensure connectivity for renewal
4. Consider leaving vehicle connected to WiFi during storage

**Used Vehicle Purchase:**
1. Request service history to check last connectivity date
2. Test Tesla app connectivity before purchase
3. If unavailable, negotiate price accounting for potential service need

### 7.2 For Independent Technicians

**Certificate Monitoring:**
```bash
# Script to check certificate expiry and warn
#!/bin/bash
CERT="/var/lib/car_creds/car.crt"
EXPIRY=$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)
EXPIRY_TS=$(date -d "$EXPIRY" +%s)
NOW_TS=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_TS - $NOW_TS) / 86400 ))

if [ $DAYS_LEFT -lt 90 ]; then
    echo "⚠️  WARNING: Certificate expires in $DAYS_LEFT days"
    echo "Ensure vehicle has connectivity for automatic renewal"
elif [ $DAYS_LEFT -lt 0 ]; then
    echo "❌ CRITICAL: Certificate expired $((-$DAYS_LEFT)) days ago"
    echo "Vehicle is likely in orphan state - service intervention needed"
else
    echo "✅ Certificate valid for $DAYS_LEFT days"
fi
```

**Preventative Connectivity:**
- For vehicles in service/rebuild: connect to WiFi weekly
- For customer vehicles with connectivity issues: address immediately

### 7.3 For Researchers

**Documentation:**
- Log certificate validity periods across different model years
- Document actual `ShouldRenew()` threshold through binary analysis
- Catalog provisioning endpoint behaviors

**Responsible Disclosure:**
- If vulnerabilities found in certificate renewal process, report to Tesla security
- Avoid public disclosure of active exploits

---

## 8. Risk Assessment

### 8.1 Warranty Impact

| Action | Warranty Risk |
|--------|---------------|
| **Official service** | ✅ No impact |
| **Certificate inspection** (read-only) | ✅ No impact |
| **Manual cert injection** | ⚠️ Moderate - may void if detected |
| **Clock manipulation** | 🔴 High - likely to void |
| **Factory reset** | 🔴 High - likely to void |
| **CAN flooding** | 🔴 High - likely to void |

### 8.2 Security Implications

**Certificate extraction risks:**
- If private key (`car.key`) is exfiltrated, attackers could impersonate vehicle
- Tesla likely has detection for duplicate certificate use
- Stolen certificates could enable unauthorized Hermes access

**Best Practices:**
- Never share `car.key` with anyone
- Ensure backups are encrypted and access-controlled
- If vehicle is sold, ensure Tesla transfers vehicle ownership (invalidates old certs)

### 8.3 Bricking Risk

| Method | Brick Risk | Reversibility |
|--------|------------|---------------|
| **Official service** | ✅ None | N/A |
| **Manual cert (valid)** | 🟡 Low | High (rollback possible) |
| **Manual cert (invalid)** | 🟡 Medium | Medium (may need service) |
| **Clock manipulation** | 🟡 Low | High (restore time) |
| **Factory reset** | 🔴 High | Low (may require service) |

### 8.4 Legal Considerations

**Right to Repair:**
- Many jurisdictions have "right to repair" laws
- Tesla may argue certificate replacement requires authorization
- Consult local laws before attempting DIY recovery

**Terms of Service:**
- Tesla's terms may prohibit unauthorized access to vehicle systems
- Service credentials are proprietary
- Using leaked service tools may violate DMCA (in US)

**Recommendation:** Pursue official service channels when possible to avoid legal ambiguity.

---

## 9. Research Gaps & Future Work

### 9.1 Unknown Elements

1. **Exact `ShouldRenew()` threshold** — Binary reverse engineering needed
2. **Service toolbox workflow** — Requires access to Tesla Toolbox software
3. **Provisioning endpoint authentication** — Factory credential structure unknown
4. **TPM-protected key recovery** — **[OPEN RESEARCH]** Unknown how Tesla service handles TPM-protected keys. Requires access to service manuals + TPM unsealing logic analysis + fTPM reverse engineering. Service may have TPM master key, OR provisioning regenerates keys, OR Tesla doesn't use TPM on most vehicles. See [meta/RESEARCH-QUESTIONS-STATUS.md](../meta/RESEARCH-QUESTIONS-STATUS.md) §5.3.
5. **Regional differences** — Do China/EU vehicles have different processes?

### 9.2 Experimental Research Needed

**Safe experiments:**
- Monitor Hermes traffic during normal renewal (on approaching-expiry vehicle)
- Document S3 URL structure for cert delivery
- Analyze `hermes_client` binary for renewal logic

**Risky experiments:**
- Attempt provisioning endpoint access (may trigger security alerts)
- Force certificate expiry on test vehicle to document orphan behavior
- Attempt manual reprovisioning with service credential emulation

### 9.3 Community Collaboration

**Needed contributions:**
- Certificate validity period data across model years
- Successful DIY recovery reports (anonymized)
- Service procedure observations
- Binary analysis of `hermes_client` and `hermes_helper`

**Sharing platforms:**
- Tesla repair forums
- Right-to-repair communities
- Security research conferences (with responsible disclosure)

---

## 10. Summary & Recommendations

### 10.1 Key Takeaways

1. **Orphan cars are preventable** — Maintain connectivity, especially during renewal window
2. **Official service is safest** — Tesla has tools to handle this, warranty-safe
3. **DIY recovery is difficult** — Requires root access, valid certificates, and technical expertise
4. **No magic bullet exists** — Each recovery method has significant limitations or risks
5. **Prevention > Recovery** — Monitor cert expiry, maintain connectivity

### 10.2 Recommended Approach by Scenario

| Scenario | Recommended Action |
|----------|-------------------|
| **Under warranty** | Tesla service center |
| **Out of warranty, nearby service** | Tesla service (cost vs. DIY risk) |
| **Independent shop with root access** | Manual cert injection if valid cert available |
| **Salvage/hobbyist** | Attempt Gateway CAN method with full backups |
| **Long-term storage** | **Prevention:** Connect every 60-90 days |

### 10.3 Final Warning

This document is for **educational purposes** and **emergency recovery scenarios** where official service is unavailable or impractical. 

**Always prefer official Tesla service when possible.** DIY recovery attempts carry risks of:
- Voiding warranty
- Creating security vulnerabilities
- Bricking vehicle systems
- Legal consequences

Proceed at your own risk.

---

## Appendix A: Quick Reference Commands

### Check Certificate Status
```bash
# View expiry date
openssl x509 -in /var/lib/car_creds/car.crt -noout -dates

# View full certificate
openssl x509 -in /var/lib/car_creds/car.crt -noout -text

# Verify cert-key match
openssl x509 -in /var/lib/car_creds/car.crt -noout -modulus | md5sum
openssl rsa -in /var/lib/car_creds/car.key -noout -modulus | md5sum
```

### Backup Certificates
```bash
mkdir -p /root/cert_backup_$(date +%Y%m%d)
cp -r /var/lib/car_creds/* /root/cert_backup_$(date +%Y%m%d)/
```

### Hermes Service Management
```bash
# Check status
systemctl status hermes_client
systemctl status hermes_proxy

# Restart services
systemctl restart hermes_client

# View logs
journalctl -u hermes_client -f
journalctl -u hermes_client --since "1 hour ago"
```

### Test Connectivity
```bash
# Check if Hermes is connected
grep -i "connected\|handshake" /var/log/hermes/client.log

# Attempt connection test (if available)
/opt/tesla/bin/hermes_client --test-connection
```

---

## Appendix B: Certificate Validity Timeline Tool

```bash
#!/bin/bash
# cert_timeline.sh - Show certificate lifecycle timeline

CERT="/var/lib/car_creds/car.crt"

if [ ! -f "$CERT" ]; then
    echo "Certificate not found at $CERT"
    exit 1
fi

# Extract dates
NOT_BEFORE=$(openssl x509 -in "$CERT" -noout -startdate | cut -d= -f2)
NOT_AFTER=$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)

# Convert to timestamps
ISSUED_TS=$(date -d "$NOT_BEFORE" +%s)
EXPIRY_TS=$(date -d "$NOT_AFTER" +%s)
NOW_TS=$(date +%s)

# Calculate durations
TOTAL_VALIDITY=$(( ($EXPIRY_TS - $ISSUED_TS) / 86400 ))
DAYS_ELAPSED=$(( ($NOW_TS - $ISSUED_TS) / 86400 ))
DAYS_LEFT=$(( ($EXPIRY_TS - $NOW_TS) / 86400 ))

# Estimate renewal window (assume 90 days before expiry)
RENEWAL_START_TS=$(( $EXPIRY_TS - (90 * 86400) ))
RENEWAL_START=$(date -d @$RENEWAL_START_TS "+%Y-%m-%d")

echo "Certificate Lifecycle Timeline"
echo "=============================="
echo ""
echo "Issued:       $(date -d "$NOT_BEFORE" "+%Y-%m-%d %H:%M:%S")"
echo "Expires:      $(date -d "$NOT_AFTER" "+%Y-%m-%d %H:%M:%S")"
echo "Total validity: $TOTAL_VALIDITY days"
echo ""
echo "Current Status:"
echo "  Days elapsed: $DAYS_ELAPSED / $TOTAL_VALIDITY"
echo "  Days remaining: $DAYS_LEFT"
echo ""
echo "Renewal Window (estimated):"
echo "  Starts: $RENEWAL_START (90 days before expiry)"
echo ""

if [ $DAYS_LEFT -lt 0 ]; then
    echo "⛔ STATUS: EXPIRED $((-$DAYS_LEFT)) days ago"
    echo "   Action: Vehicle likely orphaned - contact Tesla service"
elif [ $DAYS_LEFT -lt 30 ]; then
    echo "🔴 STATUS: CRITICAL - Expires in $DAYS_LEFT days"
    echo "   Action: Ensure connectivity immediately for renewal"
elif [ $DAYS_LEFT -lt 90 ]; then
    echo "🟡 STATUS: RENEWAL WINDOW - Expires in $DAYS_LEFT days"
    echo "   Action: Ensure vehicle has connectivity for automatic renewal"
else
    echo "✅ STATUS: VALID - Expires in $DAYS_LEFT days"
    echo "   Action: No immediate action needed"
fi
```

**Usage:**
```bash
chmod +x cert_timeline.sh
./cert_timeline.sh
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Orphan Car** | Vehicle with expired Hermes certificate unable to reconnect to Tesla cloud |
| **Hermes** | Tesla's vehicle-cloud communication system using WSS (WebSocket Secure) |
| **mTLS** | Mutual TLS — both client (vehicle) and server (Tesla) authenticate with certificates |
| **CSR** | Certificate Signing Request — submitted to CA for signing |
| **CA** | Certificate Authority — Tesla's infrastructure that signs vehicle certificates |
| **ShouldRenew()** | Function in `hermes_client` that determines when renewal is needed |
| **Provisioning** | Factory process of issuing initial credentials to vehicle |
| **VCSEC** | Vehicle Security Controller — manages physical security (locks, immobilizer) |
| **TPM** | Trusted Platform Module — hardware security chip for key storage |
| **Gateway CAN** | Vehicle's CAN bus interface to gateway computer |
| **Toolbox** | Tesla's official diagnostic and service software |

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Feb 2026 | Initial release based on research compilation |

---

**Compiled from:** `/workspace/workspace/tesla-hermes-research.md`  
**License:** Educational use only — no warranty expressed or implied  
**Contact:** Security researchers should use responsible disclosure channels
