# MCU2 Network Security Deep Dive
**Complete networking analysis of Tesla MCU2 firmware**
**Source:** `/firmware/mcu2-extracted`
**Analysis Date:** 2025-02-03

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Network Architecture](#network-architecture)
3. [Firewall Analysis](#firewall-analysis)
4. [Port Inventory](#port-inventory)
5. [Service Mappings](#service-mappings)
6. [Access Control Matrix](#access-control-matrix)
7. [Attack Surface Analysis](#attack-surface-analysis)
8. [Security Findings](#security-findings)

---

## Executive Summary

- **Total Services Analyzed:** 219
- **Firewall Rules:** 82 service-specific configurations
- **Unique Ports Identified:** 139
- **Firewall Chains:** APE_INPUT, INTERNET

## Network Architecture

### Subnet Map

```
┌─────────────────────────────────────────────────┐
│  Tesla MCU2 Network Architecture               │
├─────────────────────────────────────────────────┤
│                                                 │
│  192.168.90.100 - MCU (Media Control Unit)     │
│       ├─ eth0: Internal APE network            │
│       ├─ wlan0: WiFi (NAT to internet)         │
│       ├─ eth0.2: Cellular (NAT to internet)    │
│       └─ lo: Localhost services                │
│                                                 │
│  192.168.90.103 - APE (Autopilot A)            │
│  192.168.90.105 - APEB (Autopilot B)           │
│  192.168.90.104 - AURIX (Gateway/GPS)          │
│  192.168.90.102 - GTW (CAN Gateway)            │
│                                                 │
│  Multicast Groups:                              │
│    224.0.0.154 - UI Server messages            │
│    224.0.0.155 - Dashcam streams               │
│    224.0.1.129 - PTP (Precision Time Protocol) │
│                                                 │
│  NAT Subnet: 192.168.10.0/24                   │
│  Link-Local: 169.254.0.0/16 (DoIP/UDS)         │
└─────────────────────────────────────────────────┘
```

## Firewall Analysis

### Main Firewall Chains

#### APE_INPUT

**Purpose:** Controls incoming traffic from Autopilot computers

**Allowed Services:**
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100 --dport 123 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p tcp -s $APE_LIST -d 192.168.90.100 --dport 20564 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p tcp -s $APE_LIST -d 192.168.90.100 -m multiport --dports 8443,8444,8900 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p tcp -s $APE_LIST -d 192.168.90.100 -m multiport --dports 9892,9893,9894,9898,9897,9896,9900 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100 -m multiport --dports 5353,5354 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 224.0.0.155 -m multiport --dports 9892,9893,9894,9895,9896,9897,9898,9900,9901,9902,9903 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 224.0.0.154 --dport 5424 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100 --dport 8906 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p tcp -s $APE_LIST -d 192.168.90.100 --match multiport --dports 20565,20566 -j ACCEPT"`
- `-A APE_INPUT -i eth0 -p udp -s 192.168.90.103/32 -d 224.0.1.129/32 --sport 319 --dport 319 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s 192.168.90.103/32 -d 224.0.1.129/32 --sport 320 --dport 320 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100 -m multiport --dports 8610,8611 -j ACCEPT`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100 --dport 9899 -j ACCEPT"`
- `-A APE_INPUT -i eth0 -p udp -s 192.168.90.104 -d 192.168.90.100,192.168.90.255 --dport 63277 -j ACCEPT"`
- `-A APE_INPUT -i eth0 -p udp -s $APE_LIST -d 192.168.90.100,192.168.90.255 --dport 63277 -j ACCEPT"`

#### INTERNET

**Purpose:** Sandbox for services needing internet access

**Key Rules:**
- Blocks all RFC1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks multicast (224.0.0.0/4)
- Allows DNS to 127.0.0.1:53
- REJECTS local network access (logged)
- In FACTORY mode: Opens port 8080 for debug

## Port Inventory

### All Listening Ports

| Port | Service | Protocol | Interface | Allowed Sources | Auth |
|------|---------|----------|-----------|-----------------|------|
| 53 | connmand | TCP |  |  | ? |
| 53 | dnsmasq | TCP |  |  | ? |
| 53 | dnsmasq | TCP |  |  | ? |
| 53 | ntpd | TCP |  |  | ? |
| 53 | ntpd | TCP |  |  | ? |
| 53 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 53 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 53 | qtcar-gpsmanager | TCP |  |  | ? |
| 53 | qtcar-mediaserver | TCP |  |  | ? |
| 53 | qtcar-radioserver | TCP |  |  | ? |
| 53 | qtcar-spotifyserver | TCP |  |  | ? |
| 53 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 67 | connmand | TCP |  |  | ? |
| 69 | harman-tuner | TCP | eth0, eth0 | 192.168.90.30/32, 192.168.90.30/32 | ? |
| 69 | harman-tuner | TCP | eth0, eth0 | 192.168.90.30/32, 192.168.90.30/32 | ? |
| 80 | connmand | TCP |  |  | ? |
| 80 | connmand | TCP |  |  | ? |
| 80 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 80 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 80 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 123 | modem | TCP | eth0, eth0 | 192.168.90.60, 192.168.90.60 | ? |
| 443 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 443 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 443 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 443 | qtcar-radioserver | TCP |  |  | ? |
| 443 | qtcar-radioserver | TCP |  |  | ? |
| 443 | qtcar-radioserver | TCP |  |  | ? |
| 443 | qtcar-radioserver | TCP |  |  | ? |
| 1234 | service-ui | TCP |  |  | ? |
| 1235 | service-ui | TCP |  |  | ? |
| 1666 | hermes-livestream | TCP |  |  | ? |
| 1667 | hermes-livestream | TCP |  |  | ? |
| 3500 | hermes-livestream | TCP |  |  | ? |
| 3500 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4029 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4030 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 4030 | drmlog | TCP |  | 127.0.0.1 | ? |
| 4030 | qtcar-audiod | TCP |  |  | ? |
| 4030 | qtcar-monitor | TCP |  |  | ? |
| 4030 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4030 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4030 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4030 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4030 | videod | TCP |  |  | ? |
| 4030 | webcam | TCP |  |  | ? |
| 4031 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4032 | chromium-app | TCP |  |  | ? |
| 4032 | qtcar-audiod | TCP |  |  | ? |
| 4032 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4032 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4032 | qtcar-monitor | TCP |  |  | ? |
| 4032 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4033 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4034 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4035 | mounterd | TCP |  | 127.0.0.1 | ? |
| 4035 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4035 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4035 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4040 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4050 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4050 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4050 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4050 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4051 | qtcar-audiod | TCP |  |  | ? |
| 4051 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4051 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4060 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4060 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4060 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4061 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4061 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4070 | qtcar-audiod | TCP |  |  | ? |
| 4070 | qtcar-bluetooth | TCP |  |  | ? |
| 4070 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4070 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4070 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4071 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4071 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4072 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4073 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4080 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4082 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4083 | qtcar-mediaserver | TCP |  |  | ? |
| 4090 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4090 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4090 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4091 | qtcar-bluetooth | TCP |  |  | ? |
| 4091 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4093 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4094 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4094 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4094 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 4095 | qtcar-bluetooth | TCP |  |  | ? |
| 4095 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4096 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4096 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4097 | qtcar-bluetooth | TCP |  |  | ? |
| 4097 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4110 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4111 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4130 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4131 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4131 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4146 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4148 | qtcar-mediaserver | TCP |  |  | ? |
| 4160 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4161 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4161 | qtcar-gpsmanager | TCP |  |  | ? |
| 4163 | qtcar-gpsmanager | TCP |  |  | ? |
| 4165 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4165 | qtcar-gpsmanager | TCP |  |  | ? |
| 4171 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4181 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4181 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4201 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4210 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4211 | qtcar-spotifyserver | TCP |  |  | ? |
| 4220 | qtcar-spotifyserver | TCP |  |  | ? |
| 4241 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4251 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4251 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4280 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4280 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4281 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4400 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 4400 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4400 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4401 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4500 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4501 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4504 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4505 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4505 | qtcar-radioserver | TCP |  |  | ? |
| 4506 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4508 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4509 | qtcar-bluetooth | TCP |  |  | ? |
| 4509 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4512 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4513 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4520 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4522 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4524 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4525 | qtcar-energymonitor | TCP |  |  | ? |
| 4525 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4531 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4541 | chromium-adapter | TCP |  |  | ? |
| 4567 | owners-manual-download | TCP |  |  | ? |
| 4567 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4567 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4567 | release-notes-download | TCP |  |  | ? |
| 4567 | tesla-tts-service | TCP |  |  | ? |
| 4570 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4599 | harman-tuner | TCP | eth0, eth0 | 192.168.90.30/32, 192.168.90.30/32 | ? |
| 4599 | harman-tuner | TCP | eth0, eth0 | 192.168.90.30/32, 192.168.90.30/32 | ? |
| 4600 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4601 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4998 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4998 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4999 | chromium-adapter | TCP |  |  | ? |
| 4999 | qtcar-audiod | TCP |  |  | ? |
| 4999 | qtcar-bluetooth | TCP |  |  | ? |
| 4999 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4999 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 4999 | qtcar-connman | TCP |  | 192.168.90.100/32, 192.168.90.100/32 | ? |
| 4999 | qtcar-dvserver | TCP |  |  | ? |
| 4999 | qtcar-energymonitor | TCP |  |  | ? |
| 4999 | qtcar-gpsmanager | TCP |  |  | ? |
| 4999 | qtcar-mediaserver | TCP |  |  | ? |
| 4999 | qtcar-radioserver | TCP |  |  | ? |
| 4999 | qtcar-spotifyserver | TCP |  |  | ? |
| 4999 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4999 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 4999 | valhalla | TCP |  |  | ? |
| 5161 | qtcar-gpsmanager | TCP |  |  | ? |
| 5165 | qtcar-gpsmanager | TCP |  |  | ? |
| 5354 | dashcam | TCP |  |  | ? |
| 5424 | qtcar-cluster | TCP |  | 127.0.0.1/32, 192.168.90.100/32 | ? |
| 5424 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 5555 | harman-tuner | TCP | eth0, eth0 | 192.168.90.30/32, 192.168.90.30/32 | ? |
| 5555 | qtcar-radioserver | TCP |  |  | ? |
| 5801 | modem | TCP | eth0, eth0 | 192.168.90.60, 192.168.90.60 | ? |
| 5801 | modem | TCP | eth0, eth0 | 192.168.90.60, 192.168.90.60 | ? |
| 7654 | qtcar-monitor | TCP |  |  | ? |
| 7654 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 7654 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 7654 | toolbox-api | TCP | eth0 | 192.168.90.100, 127.0.0.1 | ? |
| 8000 | chromium-odin | TCP |  |  | ? |
| 8000 | chromium-odin | TCP |  |  | ? |
| 8002 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8080 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8080 | service-ui | TCP |  |  | ? |
| 8081 | service-shell | TCP | eth0, lo | 192.168.90.30,192.168.90.60, 192.168.90.101,192.168.90.102,192.168.90.103,192.168.90.104,192.168.90.105,192.168.90.106,192.168.90.107 | ? |
| 8082 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 8088 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 8443 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8444 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8610 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 8611 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |
| 8885 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8888 | autopilot-api | TCP | eth0 | 192.168.90.100, 192.168.90.103,192.168.90.105 | ? |
| 8888 | qtcar-radioserver | TCP |  |  | ? |
| 8888 | qtcar | TCP |  | 192.168.90.100/32, 127.0.0.1/32 | ? |

## Service Mappings

### Runit Services with Network Access

#### alertd

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### ape-deliver

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### audiod

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### autopilot-api

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### bwlogger

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### cadmium

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### calico

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### carbonado

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### cerulean

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### cgdo

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### chromium

- **User:** `chromium`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** False
- **Ports:** 49508

#### chromium-adapter

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### chromium-app

- **User:** `chromium-app`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True
- **Ports:** 9000

#### chromium-card

- **User:** `chromium`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** False
- **Ports:** 49508

#### chromium-card-webapp-adapter

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** False
- **Ports:** 49508

#### chromium-card-webapp-http

- **User:** `root`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** False
- **Ports:** 49508, 49509

#### chromium-fullscreen

- **User:** `chromium-fullscreen`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True

#### chromium-odin

- **User:** `chromium-odin`
- **Sandboxed:** True
- **Network Namespace:** False
- **Firewall Rules:** True
- **Ports:** 8000

## Access Control Matrix

### Critical Services

| Service | Ports | Allowed From | Purpose |
|---------|-------|--------------|----------|
| autopilot-api | 8443, 8444, 8885, 8888, 8900, 19004 | APE | API/Service |
| qtcar | 4070, 4080, 4220, 23001 | APE | API/Service |
| toolbox-api | 4030, 4035, 4050, 4060, 4090, 4094, 7654 | APE | API/Service |
| service-shell | 8081 | APE | API/Service |
| updater | 20564 | ? | API/Service |

## Attack Surface Analysis

### External Attack Surface (from APE network)

**Ports accessible from 192.168.90.103/105 (Autopilot computers):**

```
APE-Accessible Ports:
  - 20564
  - 5424
  - 20565,20566
  - 320
  - 8443,8444,8900
  - 319
  - 8610,8611
  - 9892,9893,9894,9895,9896,9897,9898,9900,9901,9902,9903
  - 123
  - 8906
  - 5353,5354
  - 63277
  - 9892,9893,9894,9898,9897,9896,9900
  - 9899
```

### Localhost-Only Services

Services bound to 127.0.0.1 (not accessible from network):

- qtcar-spotifyserver
- service-ui
- bwlogger
- service-shell
- chromium-app
- qtcar-gpsmanager
- qtcar-mediaserver
- audiod
- qtcar-cluster
- owners-manual-adapter
- linuxvm-logger
- ntpd
- owners-manual
- ubloxd
- release-notes-adapter
- dashcam
- qtcar-audiod
- toolbox-api
- qtcar-radioserver
- chromium-adapter

## Security Findings

### High-Risk Services

1. **service-shell (port 8081)**
   - Shell access service
   - Needs analysis for authentication

2. **toolbox-api (multiple ports)**
   - Diagnostic/debug API
   - Accessible from APE in some modes

3. **autopilot-api (ports 8443, 8444, etc)**
   - Critical AP communication
   - Limited to APE IPs (good)

### Network Isolation

**INTERNET Chain Effectiveness:**
- ✅ Blocks RFC1918 networks
- ✅ Logs violations before dropping
- ✅ Prevents services from accessing internal APIs via internet
- ⚠️ Factory mode opens port 8080 (debug backdoor)

**RunSandbox Usage:**
- 107/219 services use RunSandbox
- RunSandbox enforces cgroup-based firewall rules

### Key Vulnerabilities & Misconfigurations

1. **Factory Debug Mode**
   - If `FACTORY_DEBUG=1` and unfused: port 8080 exposed
   - Allows internal API access from internet-connected services
   - File: `/sbin/firewall` lines ~95-100

2. **Multicast Exposure**
   - 224.0.0.154, 224.0.0.155 used for UI/dashcam
   - Any device on 192.168.90.x can join multicast groups
   - Potential for eavesdropping on internal messages

3. **DoIP Gateway (port 13400)**
   - Link-local 169.254.0.0/16 access
   - Used for UDS diagnostics
   - NAT rules redirect to 192.168.93.82 namespace

### Recommendations

1. Audit all services listening on `0.0.0.0`
2. Verify authentication on APE-accessible ports
3. Review factory mode conditions (`is-in-factory`, `is-factory-gated`)
4. Analyze RunSandbox cgroup assignments for privilege escalation
5. Map all multicast subscribers and message formats

---

## Appendix: Raw Firewall Rules

### Main Firewall Script

```bash
#!/bin/sh

die () 
{ 
    echo "ERROR: $*" 1>&2;
    exit 1
}

APE_ADDR=192.168.90.103
APEB_ADDR=192.168.90.105
APE_LIST=$APE_ADDR

CHASSIS="$(cat /var/etc/chassistype)"
case "$CHASSIS" in 
    Model3)
        FACTORY_DEBUG=1
    ;;
    ModelY)
        FACTORY_DEBUG=1
    ;;
esac

DASHW="$(cat /var/etc/dashw)"
case "$DASHW" in 
    '' | *[!0-9]*)
        echo "WARNING: dashw file corrupted or does not exist" 1>&2; DASHW=3
    ;;
esac

if [ "$DASHW" -ge 3 ]; then
    APE_LIST="$APE_ADDR,$APEB_ADDR";
fi

cat <<EOF |
# First, let's set our nat rules.
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0.2 -s 192.168.10.0/24 -j MASQUERADE
-A POSTROUTING -o wlan0  -s 192.168.10.0/24 -j MASQUERADE
# nat rules for re-directing UDS traffic between doip-gateway and GTW
-A PREROUTING -i eth0 -s gw -p tcp --sport 10001 -d 192.168.90.100 -j DNAT --to-destination 192.168.93.82
-A POSTROUTING -s 192.168.93.82 -p tcp -o eth0 -d gw --dport 10001 -j SNAT --to-source 192.168.90.100

COMMIT

# Set the default policies.  No filtering on outgoing packets.
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Create the rest of our chains
:APE_INPUT - [0:0]

#
# Install input chain rules for doip-gateway.
#
# TCP and UDP data within link-local range:
-A INPUT -i eth0 -p tcp -s 169.254.0.0/16 -d 169.254.0.0/16 --dport 13400 -j ACCEPT
-A INPUT -i eth0 -p udp -s 169.254.0.0/16 -d 169.254.0.0/16 --dport 13400 -j ACCEPT

# forward icmp traffic inbound/outbound
-A FORWARD -i veth0 -p icmp -s 169.254.0.0/16 -o eth0  -d 169.254.0.0/16 -j ACCEPT
-A FORWARD -i eth0  -p icmp -s 169.254.0.0/16 -o veth0 -d 169.254.0.0/16 -j ACCEPT

# forward tcp traffic inbound/outbound
-A FORWARD -i eth0  -p tcp -s 169.254.0.0/16 -o veth0 -d 169.254.0.0/16 --dport 13400 -j ACCEPT
-A FORWARD -i veth0 -p tcp -s 169.254.0.0/16 --sport 13400 -o eth0  -d 169.254.0.0/16 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# forward udp traffic inbound/outbound (I know it is dull to copy this way.)
-A FORWARD -i eth0  -p udp -s 169.254.0.0/16 -o veth0 -d 169.254.0.0/16 --dport 13400 -j ACCEPT
-A FORWARD -i veth0 -p udp -s 169.254.0.0/16 --sport 13400 -o eth0  -d 169.254.0.0/16 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# forward TCP traffic between GTW for UDS.
-A FORWARD -i veth20 -s 192.168.93.82 -p tcp -o eth0 -d gw --dport 10001 -j ACCEPT
-A FORWARD -i eth0 -s gw -p tcp --sport 10001 -o veth20 -d 192.168.93.82 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# == Start INTERNET chain ==

:INTERNET - [0:0]

# If we're in the factory, allow debug access.
# We verify this by checking if we're unfused, and have production certs.
$( if [ "$FACTORY_DEBUG" ] && ! is-factory-gated && ! is-development-car ; then
    printf "%s\n" "
    -A INTERNET -p tcp --dport 8080 -d 127.0.0.1/32 -j ACCEPT
    -A INTERNET -p tcp --dport 8080 -d 192.168.90.100/32 -j ACCEPT"
fi )

# Block connections to internal address spaces (internal API, VPN & Multicast), allow DNS
-A INTERNET -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INTERNET -d 127.0.0.1/32 -p udp -m udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INTERNET -d 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.0.0.0/8 -m limit --limit 1/min -j NFLOG --nflog-prefix iptables-sandbox=INTERNET --nflog-group 30
-A INTERNET -d 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.0.0.0/8 -j REJECT --reject-with icmp-port-unreachable
-A INTERNET -o lo -j REJECT --reject-with icmp-port-unreachable
-A INTERNET -o eth0 -j REJECT --reject-with icmp-port-unreachable

# == End INTERNET chain ==

# SW-229515: Do not allow internal subnet traffic to ingress/egress via wlan0
-A INPUT -i wlan0 -s 192.168.90.0/24 -j DROP
-A OUTPUT -o wlan0 -d 192.168.90.0/24 -j DROP

# SW-500857: Instate sane forwarding defaults to protect the internal network
-A FORWARD -s 192.168.90.0/24 -j DROP
-A FORWARD -d 192.168.90.0/24 -j DROP

# Install package specific firewall rules.
$( for f in /etc/firewall.d/*.iptables ; do
    . "$f" 2>/dev/null
done )

# SW-74649: The kernel short-circuits packets to addresses configured on
# local interfaces through the loopback interface. E.g. if a globally-
# routable address is configured on ppp0, then packets to that address will
# be sent through the loopback interface. So packets to loopback must be to &
# from the addresses we configured, or sandboxed users/processes will be able
# to access our internal APIs using a globally-routable address configured on
# a cellular interface.
-A INPUT -i lo -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
-A INPUT -i lo -s 192.168.90.100 -d 192.168.90.100 -j ACCEPT
-A INPUT -i lo -j DROP

# If a connection is already established then accept it.
# Note that this rule should be located before other drop rules
-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT

# ==
...(truncated)
```

# MCU2 Network Security - Enhanced Analysis

## Service → Binary → Port Mapping

| Service | Binary | User | Ports | Bind Addr | Sandboxed | NetNS |
|---------|--------|------|-------|-----------|-----------|-------|
| 2048 | `N/A` | game2048 | - | - | ✓ | - |
| 2048-input | `N/A` | root | - | - | - | - |
| a2dpbridge | `alsaloop` | root | - | - | ✓ | - |
| alertd | `alertd` | root | - | - | ✓ | - |
| alsaloop-chromium | `alsaloop` | root | - | - | ✓ | - |
| alsaloop-usb-mic | `alsaloop` | root | - | - | ✓ | - |
| ape-deliver | `ape-deliver` | root | - | - | ✓ | - |
| apviz | `N/A` | root | - | - | - | - |
| apviz-assetgen | `N/A` | root | - | - | - | - |
| apviz-controls | `N/A` | root | - | - | - | - |
| audio_watchdog | `audio_watchdog` | root | - | - | ✓ | - |
| audiod | `audiod` | root | - | - | ✓ | - |
| audiorecord | `N/A` | root | - | - | - | - |
| autopilot-api | `autopilot-api` | root | - | - | ✓ | - |
| backgammon | `N/A` | backgammon | - | - | ✓ | - |
| backgammon-input | `N/A` | root | - | - | - | - |
| backup-camera | `videod` | root | - | - | ✓ | - |
| backup-camera-setup | `backup-camera-setup` | root | - | - | - | - |
| backup-settings-db | `N/A` | root | - | - | - | - |
| boot-alerts | `N/A` | root | - | - | - | - |
| bsa_server | `bsa_server` | root | - | - | ✓ | - |
| btd | `btd` | root | - | - | ✓ | - |
| bwlogger | `bwlogger` | root | - | - | ✓ | - |
| cadmium | `N/A` | root | - | - | ✓ | - |
| cadmium-input | `N/A` | root | - | - | - | - |
| calico | `gamescope-calico` | root | - | - | ✓ | - |
| calico-compositor | `N/A` | root | - | - | - | - |
| camp-mode | `tvideo` | root | - | - | ✓ | - |
| camp-mode-holiday | `tvideo` | root | - | - | ✓ | - |
| carbonado | `N/A` | root | - | - | ✓ | - |
| carbonado-input | `N/A` | root | - | - | - | - |
| cerulean | `gamescope-cerulean` | root | - | - | ✓ | - |
| cerulean-input | `N/A` | root | - | - | - | - |
| cgdo | `cgdo` | root | - | - | ✓ | - |
| cgroup-event-monitor | `cgroup-event-monitor` | root | - | - | ✓ | - |
| cgroup-monitor | `cg-monitor` | root | - | - | ✓ | - |
| chess | `N/A` | chess | - | - | ✓ | - |
| chess-input | `N/A` | root | - | - | - | - |
| chromium | `tesla-chromium` | chromium | - | - | ✓ | - |
| chromium-adapter | `N/A` | root | - | - | ✓ | - |
| chromium-app | `tesla-chromium` | chromium-app | - | - | ✓ | - |
| chromium-app-input | `N/A` | root | - | - | - | - |
| chromium-card | `tesla-chromium` | chromium | - | - | ✓ | - |
| chromium-card-input | `N/A` | root | - | - | - | - |
| chromium-card-webapp-adapter | `N/A` | root | - | - | ✓ | - |
| chromium-card-webapp-http | `simple-http-server` | root | - | 127.0.0.1 | ✓ | - |
| chromium-fullscreen | `tesla-chromium` | chromium-fullscreen | - | - | ✓ | - |
| chromium-fullscreen-input | `N/A` | root | - | - | - | - |
| chromium-input | `N/A` | root | - | - | - | - |
| chromium-odin | `tesla-chromium` | chromium-odin | - | - | ✓ | - |
| chromium-odin-input | `N/A` | root | - | - | - | - |
| chromium-webapp-adapter | `N/A` | root | - | - | ✓ | - |
| chromium-webapp-http | `simple-http-server` | root | - | 127.0.0.1 | ✓ | - |
| cobalt | `N/A` | root | - | - | ✓ | - |
| cobalt-compositor | `N/A` | root | - | - | - | - |
| cobalt-input | `N/A` | root | - | - | - | - |
| connman | `connmand` | root | - | - | ✓ | - |
| crashloghelper | `crashloghelper` | root | - | - | - | - |
| crashlognotify | `crashlognotify` | root | - | - | - | - |
| crit-backup-monitor | `crit-backup-monitor` | root | - | - | ✓ | - |
| dashcam | `dashcamd` | root | - | - | ✓ | - |
| dashcam-back | `N/A` | root | - | - | - | - |
| dashcam-front | `N/A` | root | - | - | - | - |
| dashcam-left-rep | `N/A` | root | - | - | - | - |
| dashcam-right-rep | `N/A` | root | - | - | - | - |
| dashcam-track-front | `N/A` | root | - | - | - | - |
| dashcam-viewer | `N/A` | root | - | - | ✓ | - |
| dashcam-wide | `N/A` | root | - | - | - | - |
| dbus | `dbus-daemon` | root | - | - | - | - |
| dbus-session-chromium | `run-session-bus` | root | - | - | - | - |
| dbus-session-chromium-app | `run-session-bus` | root | - | - | - | - |
| dbus-session-chromium-card | `run-session-bus` | root | - | - | - | - |
| dbus-session-chromium-fullscreen | `run-session-bus` | root | - | - | - | - |
| dbus-session-chromium-fullscreen-rear | `run-session-bus` | root | - | - | - | - |
| dbus-session-chromium-odin | `run-session-bus` | root | - | - | - | - |
| dbus-session-mediaserver | `run-session-bus` | root | - | - | - | - |
| dbus-session-owners-manual | `run-session-bus` | root | - | - | - | - |
| dbus-session-release-notes | `run-session-bus` | root | - | - | - | - |
| dbus-session-tesla | `run-session-bus` | root | - | - | - | - |
| dlt-daemon | `N/A` | root | - | - | - | - |
| dlt-log | `N/A` | root | - | - | - | - |
| dmesg-alert | `N/A` | root | - | - | - | - |
| dnsmasq | `dnsmasq` | root | - | - | ✓ | - |
| dnsproxy | `N/A` | root | - | - | - | - |
| dog-mode | `tvideo` | root | - | - | ✓ | - |
| doip-autoip | `doip-autoip` | root | - | - | ✓ | ✓ |
| doip-gateway | `doip-gateway` | root | - | - | ✓ | - |
| drmlog | `drmlog` | root | - | - | ✓ | - |
| drmlognotify | `drmlognotify` | root | - | - | ✓ | - |
| emmc-monitor | `emmc-monitor` | root | - | - | ✓ | - |
| escalator | `escalator` | root | - | - | - | - |
| fireplace | `tvideo` | root | - | - | ✓ | - |
| firewall | `N/A` | root | - | - | - | - |
| fs-monitor | `fs-monitor` | root | - | - | - | - |
| fstrim | `N/A` | root | - | - | - | - |
| fusehelper | `fusehelper` | root | - | - | - | - |
| gadget-updater | `gadget-updater` | root | - | - | ✓ | - |
| gamepad-to-virtual | `gamepad-to-virtual` | root | - | - | ✓ | - |
| gem-watcher | `gem-watcher` | root | - | - | - | - |
| getty | `getty` | root | - | - | - | - |

## Port Accessibility Matrix

| Port | Service | Accessible From | Risk Level |
|------|---------|-----------------|------------|
| 123 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 319 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 320 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 4030 | toolbox-api | Localhost only | 🟢 LOW |
| 4035 | toolbox-api | Localhost only | 🟢 LOW |
| 4050 | toolbox-api | Localhost only | 🟢 LOW |
| 4060 | toolbox-api | Localhost only | 🟢 LOW |
| 4090 | toolbox-api | Localhost only | 🟢 LOW |
| 4094 | toolbox-api | Localhost only | 🟢 LOW |
| 5353 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 5354 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 5424 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 7654 | toolbox-api | Localhost only | 🟢 LOW |
| 8081 | service-shell | Localhost only | 🟢 LOW |
| 8443 | autopilot-api | APE (192.168.90.103/105), Localhost only | 🟢 LOW |
| 8444 | autopilot-api | APE (192.168.90.103/105), Localhost only | 🟢 LOW |
| 8610 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 8611 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 8885 | autopilot-api | Localhost only | 🟢 LOW |
| 8888 | autopilot-api | Localhost only | 🟢 LOW |
| 8900 | autopilot-api | APE (192.168.90.103/105), Localhost only | 🟢 LOW |
| 8906 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9892 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9893 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9894 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9895 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9896 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9897 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9898 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9899 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9900 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9901 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9902 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 9903 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 19004 | autopilot-api | Localhost only | 🟢 LOW |
| 20564 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 20565 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 20566 | ? | APE (192.168.90.103/105) | ⚪ UNKNOWN |
| 63277 | ? | APE (192.168.90.103/105), APE (192.168.90.103/105) | ⚪ UNKNOWN |

## Authentication Analysis

### service-shell

- **Port:** 8081
- **Auth Type:** TLS certificate
- **CA Certificate:** `$CA`
- **Requires Car Certificate:** ✓
- **OID Restrictions:** $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD", $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG";


## Firewall Chain Analysis

### APE_INPUT

**Total Rules:** 17

*(Too many rules to display - 17 total)*

### INTERNET

**Total Rules:** 8

```
-A INTERNET -p tcp --dport 8080 -d 127.0.0.1/32 -j ACCEPT
-A INTERNET -p tcp --dport 8080 -d 192.168.90.100/32 -j ACCEPT"
-A INTERNET -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INTERNET -d 127.0.0.1/32 -p udp -m udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INTERNET -d 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.0.0.0/8 -m limit --limit 1/min -j NFLOG --nflog-prefix iptables-sandbox=INTERNET --nflog-group 30
-A INTERNET -d 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.0.0.0/8 -j REJECT --reject-with icmp-port-unreachable
-A INTERNET -o lo -j REJECT --reject-with icmp-port-unreachable
-A INTERNET -o eth0 -j REJECT --reject-with icmp-port-unreachable
```


---

## Deep Dive: Critical Services

### Port 8081 - service-shell

**Binary:** `/usr/bin/service-shell` (12.2 MB, hardlinked 11 times)

**Authentication Mechanism:**
- TLS mutual authentication required
- Client must present certificate signed by Tesla Product Access CA
- Certificate must contain specific OID (Extended Key Usage)
  - Production: Tesla Product Access Client Auth (Prod)
  - Engineering: Tesla Product Access Client Auth (Eng) 
- Domain-based authorization (prd vs eng)
- Device ID restrictions via `authorized-principals`
- Session monitoring enabled
- Principal-based access control

**Access Control:**
```
REJECT from:
  - 192.168.90.30, 192.168.90.60 (specific blocked IPs)
  - 192.168.90.101-107 (other MCU instances/clusters)

ACCEPT from:
  - Any device on 192.168.90.0/24 (except above)
  - localhost (127.0.0.1)
```

**Variants:** Multiple hardlinked variants with different AppArmor profiles:
- `service-shell-autodiag` - Auto diagnostic mode
- `service-shell-backend` - Backend services access
- `service-shell-engineering` - Engineering/factory mode
- `service-shell-external` - External (customer?) access
- `service-shell-macgyver` - Emergency/recovery mode?
- `service-shell-mothership` - Tesla backend connection
- `service-shell-service` - Service mode
- `service-shell-tesla` - Tesla internal access
- `service-shell-service-ui` - UI service access

**Attack Surface:**
- ❌ Direct credential theft unlikely (certificate + OID checking)
- ⚠️  Potentially vulnerable if car certificate compromised
- ⚠️  Self-signed certificate fallback if provisioning fails
- ⚠️  `is-development-car` || `!is-factory-gated` enables engineering domain
- ✅ AppArmor profiles restrict file access per variant

**Critical Code Path:**
```bash
# From /etc/sv/service-shell/run
exec /usr/bin/service-shell \
  --address 0.0.0.0 \          # ⚠️ LISTENS ON ALL INTERFACES
  --port 8081 \
  --ca "$TESLA_CERTIFICATES_COMBINED_PRODUCTS" \
  --cert /var/lib/car_creds/car.crt \
  --key /var/lib/car_creds/car.key \
  --principal-public-key /etc/service-shell/principal-{prd|eng}.pub \
  --domain {prd|eng} \
  --monitor-sessions \
  {--fused} {--factory-gated} {--delivered}
```

---

### Port 4030-4094, 7654 - toolbox-api

**Binary:** `/usr/bin/toolbox-api` (6.2 MB)

**Sandboxing:**
- Runs via RunSandbox (minijail + cgroups)
- Kafel seccomp policy: `/etc/kafel/toolbox-api.kafel`
- AppArmor profile enforced
- Dedicated user: `toolbox-api`

**Access Control:**
```
APE-accessible (192.168.90.103/105):
  - Port 4030 ONLY

REJECT from:
  - 192.168.90.30, 192.168.90.60
  - 192.168.90.100 (self)
  - 192.168.90.101, 192.168.90.102, 192.168.90.104

ACCEPT from:
  - Everything else on 192.168.90.0/24

Localhost access:
  - Ports 4030, 4050, 4060, 4090, 4094, 7654
```

**Firewall Logging:**
- Rejected packets logged to NFLOG group 30
- Prefix: `iptables-sandbox=TOOLBOX-API`
- Rate limit: 1/min

**Attack Surface:**
- 🟡 Port 4030 exposed to APE computers
- 🟡 API likely allows diagnostic commands
- ✅ Strong sandboxing (minijail + seccomp + AppArmor)
- ❓ Need to reverse-engineer binary for API endpoints

---

### Ports 8443, 8444, 8885, 8888, 8900, 19004 - autopilot-api

**Binary:** `/usr/bin/autopilot-api`

**Purpose:** Communication bridge between MCU and Autopilot computers

**Access Control:**
```
INPUT (listening):
  - Sources: 192.168.90.103, 192.168.90.105 ONLY
  - All other sources: REJECT

OUTPUT (connections):
  - Can connect TO APE on ports above (ESTABLISHED state)
  - Localhost access: 4030, 4400, 8080, 8002
  - Factory mode: Can connect to 10.0.0.0/8:443 over wlan0
```

**Sandboxing:**
- Runs via RunSandbox
- User: `autopilot-api`
- cgroup net_cls classification (for QoS/firewall)

**Attack Surface:**
- ✅ Strong restriction: only APE IPs can connect
- ⚠️  If APE compromised, can reach this API
- ✅ Sandboxed execution limits blast radius
- 🔴 Factory mode opens 10.0.0.0/8:443 - could be used for data exfil

---

### Port 20564 - updater (hermes-delivery / ape-deliver)

**Purpose:** Firmware update delivery from APE to MCU

**Access Control:**
```
APE_INPUT chain:
  - Source: 192.168.90.103/105
  - Destination: 192.168.90.100
  - Port: 20564
  - Protocol: TCP
```

**Security Implications:**
- 🔴 **CRITICAL**: Firmware update path
- ❓ Authentication/signing verification unknown (need binary analysis)
- ⚠️  APE compromise = ability to push updates to MCU
- Must verify: digital signature checking, rollback protection

---

### Port 53 - DNS Resolution

**Handled by:**
- dnsmasq (for internal resolution)
- Forwarded to external DNS over cellular/WiFi

**Access Control:**
```
INTERNET chain:
  - Allows connections to 127.0.0.1:53 (TCP/UDP)
  - Sandboxed processes can use DNS

connmand:
  - Allows outbound UDP port 53, 67 (DHCP)
```

**Attack Surface:**
- ✅ DNS to localhost only (no external DNS for sandboxed apps)
- ⚠️  dnsmasq vulnerabilities could affect all services
- Cache poisoning risk if dnsmasq not updated

---

## Network Namespace Isolation

### doip-gateway Namespace (192.168.93.82)

**Purpose:** Isolate Diagnostics over IP (DoIP) / UDS traffic

**Network Setup:**
```
Main namespace (192.168.90.100):
  - eth0: APE network
  
doip-gateway namespace (192.168.93.82):
  - veth0: Virtual ethernet to main namespace
  - Isolated from direct APE access
  - NAT rules redirect GTW traffic
```

**NAT Rules:**
```
PREROUTING:
  -A PREROUTING -i eth0 -s gw -p tcp --sport 10001 \
    -d 192.168.90.100 -j DNAT --to-destination 192.168.93.82

POSTROUTING:
  -A POSTROUTING -s 192.168.93.82 -p tcp -o eth0 \
    -d gw --dport 10001 -j SNAT --to-source 192.168.90.100
```

**DoIP Port 13400:**
- Link-local addressing (169.254.0.0/16)
- Forwards TCP/UDP to veth0 namespace
- Used for automotive diagnostics (UDS)

**Attack Surface:**
- ✅ Strong isolation via network namespace
- 🟡 Link-local access means physical proximity required
- ⚠️  If GTW (192.168.90.102) compromised, can reach doip-gateway
- UDS commands could trigger vehicle functions

---

## Multicast Groups - Data Leakage Risk

### 224.0.0.154 - UI Server Messages

**Senders:**
- qtcar (main UI application)
- APE (Autopilot UI updates)

**Receivers:**
- Any service on 192.168.90.0/24 that joins the group
- Dashcam viewer
- Service UIs

**Port:** 5424 (UDP)

**Data Transmitted:**
- UI state updates
- DV (Data Visualization?) traffic to 127.255.255.255

**Security Risk:**
- 🟡 Any compromised service can eavesdrop on UI messages
- Potential information disclosure (speed, GPS, driver actions)

### 224.0.0.155 - Dashcam Streams

**Senders:**
- backup-camera, dashcam services

**Receivers:**
- APE computers (192.168.90.103/105)
- dashcam-viewer service

**Ports:** 9892-9903 (UDP)

**Data Transmitted:**
- Video streams from cameras
- Sentry mode recordings

**Security Risk:**
- 🔴 **HIGH**: Raw camera feeds on multicast
- Any device on 192.168.90.x can join and intercept video
- No apparent encryption (need packet capture to verify)

---

## INTERNET Chain - Sandbox Bypass Analysis

**Purpose:** Prevent sandboxed internet-facing services from accessing internal APIs

**Implementation:**
```iptables
:INTERNET - [0:0]

# Block internal networks
-A INTERNET -d 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.0.0.0/8 \
  -m limit --limit 1/min \
  -j NFLOG --nflog-prefix iptables-sandbox=INTERNET --nflog-group 30

-A INTERNET -d <internal ranges> -j REJECT --reject-with icmp-port-unreachable

# Block loopback and APE network
-A INTERNET -o lo -j REJECT --reject-with icmp-port-unreachable
-A INTERNET -o eth0 -j REJECT --reject-with icmp-port-unreachable
```

**Bypass Opportunities:**

1. **Factory Mode Backdoor:**
```bash
if [ "$FACTORY_DEBUG" ] && ! is-factory-gated && ! is-development-car ; then
    -A INTERNET -p tcp --dport 8080 -d 127.0.0.1/32 -j ACCEPT
    -A INTERNET -p tcp --dport 8080 -d 192.168.90.100/32 -j ACCEPT
fi
```
- If `FACTORY_DEBUG=1` AND car is unfused AND has production certs
- Port 8080 on localhost/MCU IP becomes accessible
- Internet-connected services can reach internal APIs

2. **DNS Exception:**
```iptables
-A INTERNET -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INTERNET -d 127.0.0.1/32 -p udp -m udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
```
- DNS to localhost allowed
- dnsmasq running on 127.0.0.1:53
- DNS rebinding attack potential?

3. **Cellular Interfaces:**
- INTERNET chain blocks `eth0` (APE network) and `lo` (localhost)
- Does NOT explicitly block other interfaces
- `eth0.2` (cellular) and `wlan0` (WiFi) allowed implicitly
- NAT rules forward 192.168.10.0/24 to these interfaces

---

## RunSandbox Mechanism

**Script:** `/etc/sandbox/sandbox.bash`

**Execution Flow:**
```
1. Load profile: /etc/sandbox.d/json/{service}.json
2. Load environment: /etc/sandbox.d/vars/{service}.vars
3. Setup cgroups:
   - CPU limits (cpuset)
   - Memory limits (memory cgroup)
   - Network classification (net_cls cgroup)
   - Freezer (for pause/resume)
4. Setup network namespace (if needed):
   - Create veth pair (veth0 ↔ vpeer0)
   - Assign IP addresses (192.168.93.x subnet)
   - Setup NAT rules
   - Add iptables chain for namespace
5. Setup minijail:
   - chroot (if specified)
   - seccomp policy (via Kafel)
   - AppArmor profile
   - Additional bind mounts (eng mode)
6. Execute: cgexec <cgroup opts> minijail <jail opts> -- /path/to/binary
```

**cgroup Network Classification:**
- Each service assigned unique cgroup ID (NET_CLS_CGROUP_ID)
- iptables can match via `-m cgroup --cgroup <id>`
- Used for service-specific firewall rules

**Example from qtcar.iptables:**
```bash
CGROUP_QTCAR=0x10001

-A OUTPUT -m cgroup --cgroup $CGROUP_QTCAR -j QTCAR
```

**Attack Surface:**
- ✅ Defense-in-depth: cgroups + seccomp + AppArmor + network namespace
- ⚠️  Configuration errors in JSON profiles could weaken isolation
- ⚠️  Eng/dev mode adds additional bind mounts (`sandbox-abm.bash`)
- ❓ Seccomp policies need audit (Kafel files in `/etc/kafel/`)

---

## Subnet Routing & NAT Analysis

### NAT Rules (from /sbin/firewall)

**Masquerading for Internal Subnet:**
```iptables
*nat
-A POSTROUTING -o eth0.2 -s 192.168.10.0/24 -j MASQUERADE
-A POSTROUTING -o wlan0  -s 192.168.10.0/24 -j MASQUERADE
```
- 192.168.10.0/24 is NAT subnet for... what?
- Need to find which services use this subnet
- Likely for guest WiFi hotspot or similar

**DoIP/UDS NAT:**
```iptables
# Redirect UDS traffic between doip-gateway and GTW
-A PREROUTING -i eth0 -s gw -p tcp --sport 10001 -d 192.168.90.100 \
  -j DNAT --to-destination 192.168.93.82

-A POSTROUTING -s 192.168.93.82 -p tcp -o eth0 -d gw --dport 10001 \
  -j SNAT --to-source 192.168.90.100
```

### Interface Overview

| Interface | IP Address | Purpose | Exposed Services |
|-----------|------------|---------|------------------|
| `lo` | 127.0.0.1 | Localhost | Most services (IPC) |
| `eth0` | 192.168.90.100 | APE Network | autopilot-api, updater, service-shell, toolbox-api |
| `eth0.2` | DHCP/Cellular | Cellular Internet | Internet-facing services (via NAT) |
| `wlan0` | DHCP/WiFi | WiFi | Internet-facing services (via NAT) |
| `veth0` | 192.168.93.x | Namespaces | doip-gateway, other isolated services |

**Forwarding Rules:**
```iptables
*filter
:FORWARD DROP [0:0]

# Only specific forwards allowed:
# 1. DoIP link-local traffic
-A FORWARD -i veth0 -p icmp -s 169.254.0.0/16 -o eth0 -d 169.254.0.0/16 -j ACCEPT
-A FORWARD -i eth0  -p icmp -s 169.254.0.0/16 -o veth0 -d 169.254.0.0/16 -j ACCEPT

# 2. DoIP TCP/UDP port 13400
-A FORWARD -i eth0  -p tcp -s 169.254.0.0/16 -o veth0 -d 169.254.0.0/16 --dport 13400 -j ACCEPT

# 3. GTW UDS traffic
-A FORWARD -i veth20 -s 192.168.93.82 -p tcp -o eth0 -d gw --dport 10001 -j ACCEPT
```

**Security Posture:**
```
✅ Default DROP policy on FORWARD chain
✅ Explicit ACCEPT rules only
⚠️  SW-500857: Additional DROP rules for 192.168.90.0/24 (belt-and-suspenders)
```

---

## Complete Port Reference

### Ports 4000-4999 (Internal APIs)

| Port | Service | Protocol | Purpose | Access |
|------|---------|----------|---------|--------|
| 4029 | ? | TCP | Unknown | Localhost |
| 4030 | toolbox-api | TCP | Diagnostics/Toolbox API | APE + Localhost |
| 4031-4034 | ? | TCP | Unknown | Localhost |
| 4035 | toolbox-api | TCP | Toolbox API endpoint | Localhost |
| 4040 | ? | TCP | qtcar access | Localhost |
| 4050 | toolbox-api | TCP | Toolbox API endpoint | Localhost |
| 4051 | ? | TCP | Unknown | Localhost |
| 4060 | toolbox-api | TCP | Toolbox API endpoint | Localhost |
| 4061 | ? | TCP | Unknown | Localhost |
| 4070 | qtcar | TCP | qtcar server | Localhost |
| 4071-4073 | qtcar | UDP | DV traffic (multicast 127.255.255.255) | Localhost |
| 4080 | qtcar | TCP | qtcar server | Localhost |
| 4082 | ? | TCP | Unknown | Localhost |
| 4083 | ? | TCP | Unknown | Localhost |
| 4090 | toolbox-api | TCP | Toolbox API endpoint | Localhost |
| 4091 | ? | TCP | Unknown | Localhost |
| 4093 | ? | TCP | Unknown | Localhost |
| 4094 | toolbox-api | TCP | Toolbox API endpoint | Localhost |
| 4095-4097 | ? | TCP | Unknown | Localhost |
| 4110 | ? | TCP | qtcar access | Localhost |
| 4111 | ? | TCP | Unknown | Localhost |
| 4130 | ? | TCP | qtcar access | Localhost |
| 4131 | ? | TCP | Unknown | Localhost |
| 4146 | ? | UDP | DV traffic | Localhost |
| 4148 | ? | TCP | Unknown | Localhost |
| 4160 | ? | TCP | qtcar access | Localhost |
| 4161 | ? | TCP | Unknown | Localhost |
| 4163 | ? | TCP | Unknown | Localhost |
| 4165 | ? | TCP | Unknown | Localhost |
| 4171 | ? | TCP | Unknown | Localhost |
| 4181 | ? | UDP | DV traffic | Localhost |
| 4201 | ? | TCP | Unknown | Localhost |
| 4210 | ? | TCP | qtcar access | Localhost |
| 4211 | ? | TCP | Unknown | Localhost |
| 4220 | qtcar | TCP | qtcar server | Localhost |
| 4241 | ? | TCP | Unknown | Localhost |
| 4251 | ? | TCP | Unknown | Localhost |
| 4280 | ? | TCP | qtcar access | Localhost |
| 4281 | ? | TCP | Unknown | Localhost |
| 4400 | ? | TCP | qtcar access | Localhost |
| 4401 | ? | TCP | Unknown | Localhost |
| 4500 | ? | TCP | qtcar access | Localhost |
| 4501 | ? | TCP | Unknown | Localhost |
| 4504 | ? | TCP | qtcar access | Localhost |
| 4505 | ? | TCP | Unknown | Localhost |
| 4506 | ? | TCP | qtcar access | Localhost |
| 4508 | ? | TCP | qtcar access | Localhost |
| 4509 | ? | TCP | Unknown | Localhost |
| 4512 | ? | TCP | qtcar access | Localhost |
| 4513 | ? | UDP | DV traffic | Localhost |
| 4520 | ? | TCP | qtcar access | Localhost |
| 4522 | ? | UDP | DV traffic | Localhost |
| 4524 | ? | TCP | qtcar access | Localhost |
| 4525 | ? | UDP | DV traffic | Localhost |
| 4531 | ? | UDP | DV traffic | Localhost |
| 4541 | ? | TCP | Unknown | Localhost |
| 4567 | ? | TCP | qtcar access | Localhost |
| 4570 | qtcar | TCP/UDP | qtcar server + DV | Localhost |
| 4599 | ? | TCP | Unknown | Localhost |
| 4600 | ? | TCP | qtcar access | Localhost |
| 4601 | ? | UDP | DV traffic | Localhost |
| 4998-4999 | ? | UDP | DV traffic | Localhost |

**Pattern Analysis:**
- Most 4xxx ports are localhost-only
- Many used by `qtcar` (main UI application)
- "DV traffic" likely = Data Visualization (multicast to 127.255.255.255)
- Need to analyze qtcar binary to map ports to specific functions

### Ports 8000-9999 (External Services)

| Port | Service | Protocol | Purpose | Access |
|------|---------|----------|---------|--------|
| 8000 | ? | TCP | HTTP? | ? |
| 8002 | autopilot-api | TCP | Autopilot API endpoint | Localhost |
| 8080 | Various | TCP | HTTP, debug proxy | Localhost (FACTORY: All) |
| 8081 | service-shell | TCP | Tesla remote access shell | 192.168.90.0/24 |
| 8082 | ? | TCP | APE service | APE network |
| 8088 | ? | TCP | APE service | APE network |
| 8443 | autopilot-api | TCP | HTTPS Autopilot API | APE only |
| 8444 | autopilot-api | TCP | HTTPS Autopilot API | APE only |
| 8610 | ? | UDP | Augmented vision data | APE → MCU |
| 8611 | ? | UDP | Augmented vision data (APEB?) | APEB → MCU |
| 8885 | autopilot-api | TCP | Autopilot API | APE only |
| 8888 | autopilot-api | TCP | Autopilot API | APE only |
| 8900 | autopilot-api | TCP | Autopilot API | APE only |
| 8901 | hermes-logs | TCP | Log streaming | Owner UID only |
| 8906 | ? | UDP | MCU stats (APE request) | APE → MCU |
| 8950 | ? | TCP | Unknown | ? |
| 9000-9002 | ? | TCP | Unknown | Localhost |
| 9004 | ? | TCP | Unknown | ? |
| 9006 | ? | TCP | Unknown | ? |
| 9080 | ? | TCP | qtcar access | Localhost |
| 9892-9903 | dashcam/backup-camera | UDP | Camera video streams | APE (multicast 224.0.0.155) |

### Other Critical Ports

| Port | Service | Protocol | Purpose | Access |
|------|---------|----------|---------|--------|
| 53 | dnsmasq | TCP/UDP | DNS resolution | Localhost |
| 67 | dhcp | UDP | DHCP client | Outbound |
| 80 | connmand, various | TCP | HTTP, connectivity check | Internet |
| 123 | ntpd | UDP | NTP time sync | Internet + APE |
| 443 | Various | TCP | HTTPS | Internet |
| 1234-1235 | ? | TCP | Unknown | 192.168.90.100 |
| 1666-1667 | ? | TCP | Unknown (Perforce??) | ? |
| 3500 | ? | TCP | Unknown | ? |
| 5353-5354 | ? | UDP | mDNS? Sentry signaling | APE → MCU |
| 5424 | ? | UDP | UI Server multicast | Multicast 224.0.0.154 |
| 5555 | ? | TCP | ADB? (Android Debug Bridge??) | ? |
| 5801 | ? | TCP | VNC? | ? |
| 7654 | toolbox-api | TCP | Toolbox API | Localhost |
| 10001 | GTW | TCP | UDS Gateway (DoIP) | GTW ↔ doip-ns |
| 13400 | doip-gateway | TCP/UDP | DoIP (Diagnostics over IP) | Link-local 169.254.0.0/16 |
| 18466 | ? | TCP | qtcar access | Localhost |
| 19004 | autopilot-api | TCP | Autopilot API | APE only |
| 20100 | ? | TCP | Unknown | ? |
| 20101 | ? | TCP | Unknown | 192.168.90.100 |
| 20564 | updater | TCP | Firmware updates | APE → MCU |
| 20565-20566 | deploy tool (dev) | TCP | SSQ deployment (dev-release only) | APE → MCU |
| 23001 | qtcar | TCP | qtcar server | Localhost |
| 25956 | ? | TCP | qtcar access | Localhost |
| 28496 | ? | TCP | qtcar access | Localhost |
| 30490 | ? | TCP | Unknown | ? |
| 30508-30513 | ? | TCP | Unknown (Android?) | ? |
| 30520 | ? | TCP | Unknown | ? |
| 30530 | ? | TCP | Unknown | ? |
| 31415-31416 | ? | TCP | Unknown (Pi ports?) | ? |
| 38888 | ? | TCP | Unknown | ? |
| 49503 | ? | TCP | Unknown | Localhost |
| 49505 | ? | TCP | Unknown | ? |
| 49507 | ? | TCP | Unknown | ? |
| 49508 | chromium-webapp-http | TCP | Chromium web app backend | Localhost (127.0.0.1) |
| 49509 | hermes-proxy | TCP | Hermes proxy for webapp | Localhost |
| 50666 | ? | TCP | Unknown | ? |
| 50877 | ? | TCP | Unknown | ? |
| 50950 | updater | TCP | Update service | UID updater only |
| 50960 | ? | TCP | Unknown | ? |
| 63277 | gps/aurix | UDP | GPS data | AURIX/APE → MCU |

---

## Attack Scenarios

### Scenario 1: Compromised APE Computer

**Attacker Position:** Code execution on 192.168.90.103 (APE)

**Available Attack Surface:**
1. **autopilot-api (ports 8443, 8444, 8885, 8888, 8900, 19004)**
   - Full access to Autopilot API on MCU
   - Can send commands, receive data
   - RunSandbox limits damage, but API functions unknown

2. **toolbox-api (port 4030)**
   - Diagnostic API access
   - Likely allows status queries, maybe command injection
   - Sandboxed, but could gather intel

3. **service-shell (port 8081)**
   - ❌ Blocked: 192.168.90.103 is ACCEPTED in firewall
   - But requires TLS certificate with correct OID
   - If APE has access to MCU car.crt/car.key → full shell access

4. **updater (port 20564)**
   - Can push firmware updates to MCU
   - **Critical:** If signature verification is weak, full MCU compromise
   - Need to reverse engineer update protocol

5. **Multicast Groups**
   - Join 224.0.0.154 → eavesdrop on UI messages
   - Join 224.0.0.155 → intercept dashcam video

6. **NTP (port 123)**
   - Can respond to NTP queries
   - Time manipulation attacks (certificate expiry, log tampering)

**Lateral Movement:**
- From APE → MCU (limited by firewall)
- From APE → GTW (via UDS/DoIP if vulnerable)
- From APE → AURIX (GPS spoofing on port 63277?)

---

### Scenario 2: Factory Mode Exploit

**Trigger Conditions:**
```bash
FACTORY_DEBUG=1                # Model 3/Y by default
! is-factory-gated             # Car NOT factory-gated
! is-development-car           # Car has PRODUCTION certs
```

**Result:**
```iptables
-A INTERNET -p tcp --dport 8080 -d 127.0.0.1/32 -j ACCEPT
-A INTERNET -p tcp --dport 8080 -d 192.168.90.100/32 -j ACCEPT
```

**Impact:**
- Internet-connected services can reach port 8080
- Port 8080 likely runs debug HTTP server or proxy
- Could access internal APIs via 127.0.0.1:8080
- Bypasses INTERNET chain restrictions

**Attack Chain:**
1. Compromise internet-facing service (e.g., Chromium, connmand)
2. Connect to 127.0.0.1:8080
3. Use debug proxy to reach internal APIs
4. Escalate to full MCU control

---

### Scenario 3: Multicast Video Interception

**Setup:**
- Attacker gains code execution on ANY service on 192.168.90.x
- Could be via APE compromise, or MCU service vuln

**Attack:**
```python
import socket
import struct

# Join dashcam multicast group
MCAST_GRP = '224.0.0.155'
MCAST_PORT = 9892  # Or 9893-9903 for other cameras

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))

# Join multicast group
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# Receive camera frames
while True:
    data, addr = sock.recvfrom(65535)
    # Process video frame
```

**Impact:**
- Real-time camera feed interception
- Sentry mode recording capture
- Backup camera view

**Mitigation Status:**
- ❌ No encryption observed (need packet capture to confirm)
- ❌ No authentication to join multicast group
- ⚠️  Requires network access to 192.168.90.0/24

---

## Recommendations

### Immediate Priorities

1. **Audit Update Mechanism (port 20564)**
   - Reverse engineer `/usr/bin/ape-deliver` and update binaries
   - Verify cryptographic signature checking
   - Test for signature bypass vulnerabilities
   - Check for rollback protection

2. **Analyze service-shell Authentication**
   - Extract certificate validation logic
   - Test OID checking robustness
   - Check self-signed cert fallback conditions
   - Attempt principal bypass

3. **Map qtcar Port Functions**
   - Reverse engineer `/usr/bin/qtcar`
   - Document API endpoints on 4xxx ports
   - Identify unauthenticated endpoints
   - Test for command injection

4. **Factory Mode Audit**
   - Determine exact conditions for `FACTORY_DEBUG` activation
   - Identify what runs on port 8080 in factory mode
   - Test INTERNET chain bypass via 8080

### Long-Term Security Improvements

1. **Encrypt Multicast Traffic**
   - Add encryption to dashcam streams (224.0.0.155)
   - Add encryption/authentication to UI messages (224.0.0.154)

2. **Reduce APE Attack Surface**
   - Minimize ports exposed to 192.168.90.103/105
   - Add authentication to toolbox-api port 4030
   - Consider TLS for autopilot-api connections

3. **Strengthen INTERNET Chain**
   - Remove factory mode 8080 exception
   - Add explicit allow-list for internet-facing services
   - Log all INTERNET chain violations

4. **Network Namespace All Services**
   - Move more services into isolated network namespaces
   - Limit localhost communication to necessary APIs only

5. **Audit Seccomp Policies**
   - Review all Kafel files in `/etc/kafel/`
   - Ensure syscall restrictions are tight
   - Test for seccomp bypass

---

## Files Requiring Further Analysis

### Binaries (Reverse Engineering)
- `/usr/bin/service-shell` (12 MB) - Remote shell, certificate auth
- `/usr/bin/toolbox-api` (6 MB) - Diagnostic API
- `/usr/bin/autopilot-api` - APE↔MCU bridge
- `/usr/bin/ape-deliver` - Update delivery
- `/usr/bin/qtcar` - Main UI, many ports
- `/usr/bin/chromium-*` - Browser variants
- `/sbin/doip-gateway` - DoIP/UDS handler

### Configuration Files
- `/etc/service-shell/principals.d/` - Authorized principals
- `/etc/service-shell/principal-{prd,eng}.pub` - Public keys
- `/etc/sandbox.d/json/*.json` - Sandbox profiles
- `/etc/kafel/*.kafel` - Seccomp policies
- `/etc/apparmor.d/` - AppArmor profiles
- `/sbin/authorized-principals` - Device ID auth

### Scripts
- `/sbin/is-factory-gated` - Factory mode check
- `/sbin/is-development-car` - Dev car check
- `/sbin/is-delivered` - Delivery status
- `/sbin/is-fused` - Fuse status (security)
- `/etc/tesla-certificates.vars` - Certificate paths

---

## Summary

**Total Network Services:** 219 runit services analyzed

**Exposed Ports:** 139 unique ports identified

**Critical Findings:**
1. 🔴 **Service-shell (8081)** accessible from entire 192.168.90.0/24 subnet
2. 🔴 **Firmware update port (20564)** requires signature verification audit
3. 🔴 **Multicast camera streams** appear unencrypted, joinable by any network device
4. 🟡 **Factory mode** opens port 8080, bypassing INTERNET chain
5. 🟡 **toolbox-api port 4030** exposed to APE computers
6. ✅ **Strong sandboxing** via RunSandbox (cgroups + minijail + seccomp + AppArmor)
7. ✅ **INTERNET chain** effectively blocks RFC1918 for internet services
8. ✅ **DoIP isolated** in network namespace

**Overall Security Posture:** 
- Defense-in-depth approach with multiple isolation layers
- Strong firewall rules for most services
- Critical dependencies on certificate security and update signature verification
- APE compromise is highest-impact attack vector

**Next Steps:**
1. Binary analysis of critical services
2. Packet capture of multicast traffic
3. Certificate validation testing
4. Factory mode activation research

---

*Analysis complete. Document generated: 2025-02-03 04:51 UTC*
*Source: Tesla MCU2 firmware extraction from /firmware/mcu2-extracted/*

---

## Network Topology Diagram

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                     TESLA MCU2 NETWORK ARCHITECTURE                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

                                  INTERNET
                                     ▲
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    │                │                │
              ┌─────▼─────┐    ┌────▼────┐     ┌────▼────┐
              │  Cellular │    │  WiFi   │     │ Ethernet│
              │  (LTE/5G) │    │ (wlan0) │     │ (tether)│
              │  (eth0.2) │    └────┬────┘     └────┬────┘
              └─────┬─────┘         │               │
                    │               │               │
                    └───────┬───────┴───────────────┘
                            │ NAT (MASQUERADE)
                            │ 192.168.10.0/24
        ┌───────────────────┴───────────────────────────────────────┐
        │                MCU (192.168.90.100)                       │
        │  ┌─────────────────────────────────────────────────────┐  │
        │  │              MAIN NAMESPACE                         │  │
        │  │                                                     │  │
        │  │  ┌──────────────────────────────────────────────┐  │  │
        │  │  │  Localhost Services (127.0.0.1)              │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ qtcar (ports 4000-4999)               │  │  │  │
        │  │  │  │ - Main UI application                  │  │  │  │
        │  │  │  │ - 4070, 4080, 4220 (servers)          │  │  │  │
        │  │  │  │ - 4xxx (IPC endpoints)                 │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  │                                               │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ toolbox-api (4030,4050,4060,4090,4094) │  │  │  │
        │  │  │  │ - Diagnostic API (sandboxed)           │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  │                                               │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ chromium-webapp-http (49508)           │  │  │  │
        │  │  │  │ autopilot-api (4030,4400,8080,8002)    │  │  │  │
        │  │  │  │ dnsmasq (53)                           │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  └──────────────────────────────────────────────┘  │  │
        │  │                                                     │  │
        │  │  ┌──────────────────────────────────────────────┐  │  │
        │  │  │  APE Network Services (eth0)                 │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ service-shell (8081)                   │  │  │  │
        │  │  │  │ - TLS mutual auth                      │  │  │  │
        │  │  │  │ - Cert + OID required                  │  │  │  │
        │  │  │  │ - LISTENS on 0.0.0.0 ⚠️                │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  │                                               │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ autopilot-api (8443,8444,8885,8888,    │  │  │  │
        │  │  │  │                8900,19004)              │  │  │  │
        │  │  │  │ - APE 103/105 ONLY                     │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  │                                               │  │  │
        │  │  │  ┌────────────────────────────────────────┐  │  │  │
        │  │  │  │ updater (20564)                        │  │  │  │
        │  │  │  │ - Firmware delivery from APE           │  │  │  │
        │  │  │  │ - CRITICAL ⚠️                           │  │  │  │
        │  │  │  └────────────────────────────────────────┘  │  │  │
        │  │  └──────────────────────────────────────────────┘  │  │
        │  └─────────────────────────────────────────────────────┘  │
        │                                                           │
        │  ┌─────────────────────────────────────────────────────┐  │
        │  │         NETWORK NAMESPACES (veth pairs)             │  │
        │  │                                                     │  │
        │  │  ┌──────────────────────────────────────────────┐  │  │
        │  │  │ doip-gateway (192.168.93.82)                 │  │  │
        │  │  │ - veth0 ↔ vpeer0                             │  │  │
        │  │  │ - Port 13400 (DoIP/UDS)                      │  │  │
        │  │  │ - Link-local 169.254.0.0/16                  │  │  │
        │  │  │ - NAT to/from GTW port 10001                 │  │  │
        │  │  └──────────────────────────────────────────────┘  │  │
        │  │                                                     │  │
        │  │  ┌──────────────────────────────────────────────┐  │  │
        │  │  │ Other service namespaces (192.168.93.x)      │  │  │
        │  │  │ - /30 subnets per service                    │  │  │
        │  │  │ - NAT via iptables MASQUERADE                │  │  │
        │  │  └──────────────────────────────────────────────┘  │  │
        │  └─────────────────────────────────────────────────────┘  │
        └───────────────────────────────────────────────────────────┘
                            │
                            │ eth0 (192.168.90.100)
                            │
        ┌───────────────────┴───────────────────────────────────────┐
        │              192.168.90.0/24 Network                      │
        │               (APE / Autopilot Network)                   │
        └───────────────────┬───────────────────────────────────────┘
                            │
           ┌────────────────┼────────────────┬─────────────────┐
           │                │                │                 │
      ┌────▼────┐      ┌────▼────┐     ┌────▼────┐      ┌─────▼─────┐
      │   APE   │      │  APEB   │     │ AURIX   │      │    GTW    │
      │ (AP A)  │      │ (AP B)  │     │(Gateway)│      │ (Gateway) │
      │  .103   │      │  .105   │     │  .104   │      │   .102    │
      └────┬────┘      └────┬────┘     └────┬────┘      └─────┬─────┘
           │                │                │                 │
           │                │                │                 │
      ┌────▼────────────────▼────────────────▼─────────────────▼────┐
      │                                                              │
      │   Sends to MCU:                                             │
      │   - Autopilot API calls (8443,8444,8885,8888,8900,19004)   │
      │   - Firmware updates (20564)                                │
      │   - Camera streams to 224.0.0.155 (multicast)               │
      │   - Augmented vision data (8610,8611 UDP)                   │
      │   - GPS data (63277 UDP) [from AURIX .104]                  │
      │   - NTP requests (123)                                      │
      │   - UI messages to 224.0.0.154 (multicast)                  │
      │                                                              │
      │   Receives from MCU:                                        │
      │   - Sentry mode video (9892-9903 TCP/UDP)                   │
      │   - Dashcam streams (multicast 224.0.0.155)                 │
      │   - UI server updates (multicast 224.0.0.154)               │
      │                                                              │
      └──────────────────────────────────────────────────────────────┘


                        ╔═══════════════════════════╗
                        ║   MULTICAST GROUPS        ║
                        ╚═══════════════════════════╝

      224.0.0.154:5424 ────────► UI Server Messages
          │                      (qtcar, APE, services)
          │
          ├─ qtcar sends UI state
          ├─ APE sends UI updates
          └─ Services subscribe for events

      224.0.0.155:9892-9903 ───► Dashcam Video Streams
          │                      (cameras → APE)
          │
          ├─ Port 9892: Camera 1
          ├─ Port 9893: Camera 2
          ├─ Port 9894: Camera 3
          ├─ Port 9895-9903: Additional cameras/views
          │
          └─ ⚠️  UNENCRYPTED - any device on 192.168.90.x can join

      224.0.1.129:319,320 ─────► Precision Time Protocol (PTP)
                                 (APE .103 → MCU)


                    ╔═══════════════════════════════╗
                    ║   FIREWALL CHAINS             ║
                    ╚═══════════════════════════════╝

      INTERNET ──────────► Sandbox for internet-facing services
          │                Block: 10.0.0.0/8, 172.16.0.0/12,
          │                       192.168.0.0/16, 224.0.0.0/4
          │                Allow: DNS to 127.0.0.1:53
          │                ⚠️  FACTORY: Opens 8080 if unfused + prod certs
          │
          └─ Used by: chromium, connmand, hermes services

      APE_INPUT ─────────► Controls APE → MCU traffic
          │                Sources: 192.168.90.103/105 (+ .104 for GPS)
          │                Allows: autopilot-api, updater, NTP,
          │                        sentry video, dashcam, augmented vision
          │                REJECTS: .30, .60 (specific blocks)
          │
          └─ Default: NFLOG + DROP

      SERVICE-SHELL-INPUT ► service-shell access control
          │                 REJECT: .30, .60, .101-.107
          │                 ACCEPT: Rest of 192.168.90.0/24, localhost
          │
          └─ But still requires TLS cert auth

      TOOLBOX-API-INPUT ─► toolbox-api access control
          │                APE (.103/.105): Port 4030 ONLY
          │                REJECT: .30, .60, .100, .101, .102, .104
          │                ACCEPT: Others
          │
          └─ Additional sandboxing via RunSandbox


                      ╔═══════════════════════════╗
                      ║  ATTACK SURFACE SUMMARY   ║
                      ╚═══════════════════════════╝

      🔴 CRITICAL
         ├─ Port 20564 (updater) - Firmware delivery
         ├─ Port 8081 (service-shell) - Remote access (but cert-protected)
         └─ Multicast 224.0.0.155 - Unencrypted camera streams

      🟡 HIGH
         ├─ Port 4030 (toolbox-api) - Diagnostics from APE
         ├─ Ports 8443-8900 (autopilot-api) - APE communication
         ├─ Port 13400 (doip-gateway) - Automotive diagnostics (link-local)
         └─ Factory mode port 8080 - INTERNET chain bypass

      🟢 MEDIUM
         ├─ Port 123 (NTP) - Time manipulation potential
         ├─ Multicast 224.0.0.154 - UI message eavesdropping
         └─ Port 63277 (GPS) - GPS data injection from AURIX

      ⚪ LOW (Localhost only)
         └─ Ports 4000-4999 (qtcar + internal APIs)


                    ╔════════════════════════════════╗
                    ║  SECURITY CONTROLS SUMMARY     ║
                    ╚════════════════════════════════╝

      ✅ STRONG
         ├─ RunSandbox: cgroups + minijail + seccomp + AppArmor
         ├─ Network namespaces for isolation (doip-gateway)
         ├─ INTERNET chain blocks RFC1918 networks
         ├─ Service-specific firewall rules (82 .iptables files)
         ├─ Default DROP on INPUT/FORWARD chains
         └─ TLS + certificate + OID auth for service-shell

      ⚠️  NEEDS AUDIT
         ├─ Update signature verification (port 20564)
         ├─ toolbox-api authentication (port 4030)
         ├─ autopilot-api API security (multiple ports)
         ├─ Multicast traffic encryption status
         ├─ Factory mode activation conditions
         └─ Seccomp policies (Kafel files)

      ❌ WEAKNESSES
         ├─ service-shell listens on 0.0.0.0 (not limited to eth0)
         ├─ No authentication on multicast groups
         ├─ Factory mode 8080 bypass of INTERNET chain
         └─ Large attack surface from APE (if compromised)

```

---
