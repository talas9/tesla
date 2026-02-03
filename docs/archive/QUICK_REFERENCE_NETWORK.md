# MCU2 Network Security - Quick Reference Card

## 🔴 Top 3 Critical Risks

1. **Port 20564 - Firmware Updates** (APE → MCU)
   - Needs signature verification audit immediately
   - Full compromise if bypassable

2. **Multicast 224.0.0.155 - Camera Streams**
   - No encryption (likely)
   - Privacy risk: Sentry mode, dashcam, backup camera

3. **Port 8081 - service-shell**
   - Remote shell access
   - Accessible from 192.168.90.0/24
   - Protected by TLS cert (needs audit)

---

## 📍 Network Map

```
192.168.90.100 - MCU (you are here)
192.168.90.103 - APE (Autopilot A) ⚠️  Highest threat if compromised
192.168.90.105 - APEB (Autopilot B)
192.168.90.104 - AURIX (GPS gateway)
192.168.90.102 - GTW (CAN gateway)
```

---

## 🔑 Key Ports

| Port  | Service          | Risk | Access          |
|-------|------------------|------|-----------------|
| 8081  | service-shell    | 🔴   | 192.168.90.0/24 |
| 20564 | updater          | 🔴   | APE only        |
| 4030  | toolbox-api      | 🟡   | APE + others    |
| 8443+ | autopilot-api    | 🟡   | APE only        |
| 13400 | doip-gateway     | 🟡   | Link-local      |
| 4xxx  | qtcar (many)     | 🟢   | Localhost       |

---

## 🛡️ Firewall Chains

- **INTERNET**: Blocks RFC1918, allows DNS
  - ⚠️  Exception: Port 8080 in factory mode
- **APE_INPUT**: Controls APE → MCU
  - Default: DROP + log
- **SERVICE-SHELL-INPUT**: Port 8081 access
  - Rejects: .30, .60, .101-.107
- **TOOLBOX-API-INPUT**: Diagnostic API
  - APE: port 4030 only

---

## 🎯 Attack Vectors

1. **APE Compromise** → Full MCU access via multiple ports
2. **Factory Mode** → Port 8080 bypass of INTERNET chain
3. **Multicast Join** → Camera/UI eavesdropping

---

## 📝 Files to Analyze Next

- `/usr/bin/ape-deliver` - Update mechanism (CRITICAL)
- `/usr/bin/service-shell` - Remote shell (12 MB, 11 variants)
- `/usr/bin/toolbox-api` - Diagnostics API
- `/sbin/firewall` - Main firewall script
- `/etc/firewall.d/*.iptables` - 82 service configs

---

## 🔍 Commands for Further Analysis

```bash
# List all iptables rules
iptables -L -v -n
iptables -t nat -L -v -n

# Check firewall log
journalctl -t iptables

# List network namespaces
ip netns list

# Show all listening ports
netstat -tulpn

# Monitor multicast traffic
tcpdump -i eth0 'dst net 224.0.0.0/4'
```

---

**Full Analysis:** `/research/44-mcu-networking-deep-dive.md` (1916 lines)

**Summary:** `/research/NETWORK_ANALYSIS_SUMMARY.txt`
