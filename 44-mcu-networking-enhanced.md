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

