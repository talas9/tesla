#!/usr/bin/env python3
"""
MCU2 Network Security Analysis Script
Parses firewall rules, service configs, and creates comprehensive network documentation
"""

import os
import re
import json
from collections import defaultdict
from pathlib import Path

# Configuration
MCU_ROOT = "/root/downloads/mcu2-extracted"
FIREWALL_DIR = f"{MCU_ROOT}/etc/firewall.d"
SV_DIR = f"{MCU_ROOT}/etc/sv"
OUTPUT_FILE = "/root/tesla/44-mcu-networking-deep-dive.md"

# Network subnets
SUBNETS = {
    "192.168.90.100": "MCU (self)",
    "192.168.90.103": "APE (Autopilot A)",
    "192.168.90.105": "APEB (Autopilot B)",
    "192.168.90.104": "AURIX (Gateway)",
    "192.168.90.102": "GTW (Gateway)",
    "127.0.0.1": "Localhost",
    "224.0.0.154": "Multicast - UI Server",
    "224.0.0.155": "Multicast - Dashcam",
    "169.254.0.0/16": "Link-Local (DoIP)",
    "192.168.10.0/24": "NAT subnet",
    "192.168.93.82": "doip-gateway namespace"
}

class NetworkAnalyzer:
    def __init__(self):
        self.ports = defaultdict(list)
        self.services = {}
        self.firewall_rules = []
        self.chains = defaultdict(list)
        
    def parse_iptables_file(self, filepath):
        """Parse individual iptables configuration file"""
        service_name = Path(filepath).stem
        
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Extract all port rules
        dport_matches = re.findall(r'--dport[s]?\s+(\S+)', content)
        sport_matches = re.findall(r'--sport[s]?\s+(\S+)', content)
        
        # Extract source/destination IPs
        src_matches = re.findall(r'-s\s+([\d\.\/,]+)', content)
        dst_matches = re.findall(r'-d\s+([\d\.\/,]+)', content)
        
        # Extract interfaces
        iface_in = re.findall(r'-i\s+(\S+)', content)
        iface_out = re.findall(r'-o\s+(\S+)', content)
        
        # Extract actions
        actions = re.findall(r'-j\s+(\S+)', content)
        
        return {
            'service': service_name,
            'dports': dport_matches,
            'sports': sport_matches,
            'sources': src_matches,
            'destinations': dst_matches,
            'interfaces_in': iface_in,
            'interfaces_out': iface_out,
            'actions': actions,
            'content': content
        }
    
    def parse_all_firewall_rules(self):
        """Parse all firewall rules from /etc/firewall.d/"""
        rules = []
        
        for filename in sorted(os.listdir(FIREWALL_DIR)):
            if filename.endswith('.iptables'):
                filepath = os.path.join(FIREWALL_DIR, filename)
                rule_data = self.parse_iptables_file(filepath)
                rules.append(rule_data)
                
                # Index ports
                for port_spec in rule_data['dports']:
                    for port in self._expand_port_spec(port_spec):
                        self.ports[port].append({
                            'service': rule_data['service'],
                            'type': 'listen',
                            'sources': rule_data['sources'],
                            'interfaces': rule_data['interfaces_in']
                        })
        
        return rules
    
    def _expand_port_spec(self, spec):
        """Expand port specification (handles ranges and lists)"""
        ports = []
        
        # Remove any trailing junk
        spec = spec.split()[0] if ' ' in spec else spec
        
        # Handle comma-separated lists
        for part in spec.split(','):
            if ':' in part:
                # Port range
                try:
                    start, end = part.split(':')
                    ports.extend(range(int(start), int(end) + 1))
                except:
                    pass
            else:
                # Single port
                try:
                    ports.append(int(part))
                except:
                    # Named port (ntp, etc)
                    ports.append(part)
        
        return ports
    
    def parse_main_firewall(self):
        """Parse the main /sbin/firewall script"""
        firewall_path = f"{MCU_ROOT}/sbin/firewall"
        
        with open(firewall_path, 'r') as f:
            content = f.read()
        
        # Extract key chains and rules
        chains = re.findall(r'^:(\S+)\s+-\s+\[', content, re.MULTILINE)
        
        # Extract critical rules
        ape_input_rules = re.findall(r'-A APE_INPUT.*', content)
        internet_rules = re.findall(r'-A INTERNET.*', content)
        input_rules = re.findall(r'^-A INPUT.*', content, re.MULTILINE)
        
        return {
            'chains': chains,
            'ape_input_rules': ape_input_rules,
            'internet_rules': internet_rules,
            'input_rules': input_rules,
            'full_content': content
        }
    
    def analyze_service_configs(self):
        """Analyze runit service configurations"""
        services = {}
        
        for service_dir in os.listdir(SV_DIR):
            run_script = os.path.join(SV_DIR, service_dir, 'run')
            
            if os.path.isfile(run_script):
                with open(run_script, 'r') as f:
                    content = f.read()
                
                # Extract key information
                services[service_dir] = {
                    'user': self._extract_user(content),
                    'ports': self._extract_ports_from_script(content),
                    'sandbox': 'RunSandbox' in content,
                    'network_ns': 'netns' in content or 'ip netns' in content,
                    'has_firewall': os.path.exists(f"{FIREWALL_DIR}/{service_dir}.iptables")
                }
        
        return services
    
    def _extract_user(self, content):
        """Extract user/UID from service script"""
        # Look for export USER= or --uid-owner patterns
        user_match = re.search(r'export USER=(\S+)', content)
        if user_match:
            return user_match.group(1)
        
        uid_match = re.search(r'--uid-owner\s+(\S+)', content)
        if uid_match:
            return uid_match.group(1)
        
        return 'root'
    
    def _extract_ports_from_script(self, content):
        """Extract port numbers from service run scripts"""
        ports = []
        
        # Look for PORT= assignments
        port_matches = re.findall(r'(?:PORT|port)=(\d+)', content)
        ports.extend(port_matches)
        
        # Look for :port patterns
        port_patterns = re.findall(r':(\d{4,5})', content)
        ports.extend([p for p in port_patterns if int(p) > 1024])
        
        return list(set(ports))
    
    def generate_markdown_report(self, firewall_rules, main_firewall, services):
        """Generate comprehensive markdown report"""
        
        md = []
        md.append("# MCU2 Network Security Deep Dive\n")
        md.append("**Complete networking analysis of Tesla MCU2 firmware**\n")
        md.append(f"**Source:** `{MCU_ROOT}`\n")
        md.append("**Analysis Date:** 2025-02-03\n\n")
        
        md.append("---\n\n")
        
        # Table of Contents
        md.append("## Table of Contents\n\n")
        md.append("1. [Executive Summary](#executive-summary)\n")
        md.append("2. [Network Architecture](#network-architecture)\n")
        md.append("3. [Firewall Analysis](#firewall-analysis)\n")
        md.append("4. [Port Inventory](#port-inventory)\n")
        md.append("5. [Service Mappings](#service-mappings)\n")
        md.append("6. [Access Control Matrix](#access-control-matrix)\n")
        md.append("7. [Attack Surface Analysis](#attack-surface-analysis)\n")
        md.append("8. [Security Findings](#security-findings)\n\n")
        
        md.append("---\n\n")
        
        # Executive Summary
        md.append("## Executive Summary\n\n")
        md.append(f"- **Total Services Analyzed:** {len(services)}\n")
        md.append(f"- **Firewall Rules:** {len(firewall_rules)} service-specific configurations\n")
        md.append(f"- **Unique Ports Identified:** {len(self.ports)}\n")
        md.append(f"- **Firewall Chains:** {', '.join(main_firewall['chains'])}\n\n")
        
        # Network Architecture
        md.append("## Network Architecture\n\n")
        md.append("### Subnet Map\n\n")
        md.append("```\n")
        md.append("┌─────────────────────────────────────────────────┐\n")
        md.append("│  Tesla MCU2 Network Architecture               │\n")
        md.append("├─────────────────────────────────────────────────┤\n")
        md.append("│                                                 │\n")
        md.append("│  192.168.90.100 - MCU (Media Control Unit)     │\n")
        md.append("│       ├─ eth0: Internal APE network            │\n")
        md.append("│       ├─ wlan0: WiFi (NAT to internet)         │\n")
        md.append("│       ├─ eth0.2: Cellular (NAT to internet)    │\n")
        md.append("│       └─ lo: Localhost services                │\n")
        md.append("│                                                 │\n")
        md.append("│  192.168.90.103 - APE (Autopilot A)            │\n")
        md.append("│  192.168.90.105 - APEB (Autopilot B)           │\n")
        md.append("│  192.168.90.104 - AURIX (Gateway/GPS)          │\n")
        md.append("│  192.168.90.102 - GTW (CAN Gateway)            │\n")
        md.append("│                                                 │\n")
        md.append("│  Multicast Groups:                              │\n")
        md.append("│    224.0.0.154 - UI Server messages            │\n")
        md.append("│    224.0.0.155 - Dashcam streams               │\n")
        md.append("│    224.0.1.129 - PTP (Precision Time Protocol) │\n")
        md.append("│                                                 │\n")
        md.append("│  NAT Subnet: 192.168.10.0/24                   │\n")
        md.append("│  Link-Local: 169.254.0.0/16 (DoIP/UDS)         │\n")
        md.append("└─────────────────────────────────────────────────┘\n")
        md.append("```\n\n")
        
        # Firewall Analysis
        md.append("## Firewall Analysis\n\n")
        md.append("### Main Firewall Chains\n\n")
        
        for chain in main_firewall['chains']:
            md.append(f"#### {chain}\n\n")
            
            if chain == "INTERNET":
                md.append("**Purpose:** Sandbox for services needing internet access\n\n")
                md.append("**Key Rules:**\n")
                md.append("- Blocks all RFC1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n")
                md.append("- Blocks multicast (224.0.0.0/4)\n")
                md.append("- Allows DNS to 127.0.0.1:53\n")
                md.append("- REJECTS local network access (logged)\n")
                md.append("- In FACTORY mode: Opens port 8080 for debug\n\n")
            
            elif chain == "APE_INPUT":
                md.append("**Purpose:** Controls incoming traffic from Autopilot computers\n\n")
                md.append("**Allowed Services:**\n")
                for rule in main_firewall['ape_input_rules'][:15]:  # Show first 15
                    md.append(f"- `{rule}`\n")
                md.append("\n")
        
        # Port Inventory
        md.append("## Port Inventory\n\n")
        md.append("### All Listening Ports\n\n")
        md.append("| Port | Service | Protocol | Interface | Allowed Sources | Auth |\n")
        md.append("|------|---------|----------|-----------|-----------------|------|\n")
        
        # Sort ports for display
        sorted_ports = sorted(
            [(k, v) for k, v in self.ports.items() if isinstance(k, int)],
            key=lambda x: x[0]
        )
        
        for port, details in sorted_ports[:100]:  # Limit to first 100
            for detail in details:
                service = detail['service']
                sources = ', '.join(detail.get('sources', ['any'])[:2])  # First 2 sources
                interfaces = ', '.join(detail.get('interfaces', ['any'])[:2])
                
                md.append(f"| {port} | {service} | TCP | {interfaces} | {sources} | ? |\n")
        
        md.append("\n")
        
        # Service Mappings
        md.append("## Service Mappings\n\n")
        md.append("### Runit Services with Network Access\n\n")
        
        for svc_name, svc_data in sorted(services.items())[:50]:  # First 50
            if svc_data['has_firewall'] or svc_data['ports']:
                md.append(f"#### {svc_name}\n\n")
                md.append(f"- **User:** `{svc_data['user']}`\n")
                md.append(f"- **Sandboxed:** {svc_data['sandbox']}\n")
                md.append(f"- **Network Namespace:** {svc_data['network_ns']}\n")
                md.append(f"- **Firewall Rules:** {svc_data['has_firewall']}\n")
                
                if svc_data['ports']:
                    md.append(f"- **Ports:** {', '.join(svc_data['ports'])}\n")
                
                md.append("\n")
        
        # Access Control Matrix
        md.append("## Access Control Matrix\n\n")
        md.append("### Critical Services\n\n")
        
        critical_services = [
            ('autopilot-api', [8443, 8444, 8885, 8888, 8900, 19004]),
            ('qtcar', [4070, 4080, 4220, 23001]),
            ('toolbox-api', [4030, 4035, 4050, 4060, 4090, 4094, 7654]),
            ('service-shell', [8081]),
            ('updater', [20564]),
        ]
        
        md.append("| Service | Ports | Allowed From | Purpose |\n")
        md.append("|---------|-------|--------------|----------|\n")
        
        for svc, ports in critical_services:
            port_str = ', '.join(map(str, ports))
            
            # Find firewall rule
            fw_file = f"{FIREWALL_DIR}/{svc}.iptables"
            allowed_from = "?"
            
            if os.path.exists(fw_file):
                with open(fw_file, 'r') as f:
                    content = f.read()
                    if '192.168.90.103' in content:
                        allowed_from = "APE"
                    elif 'lo' in content or '127.0.0.1' in content:
                        allowed_from = "Localhost"
                    else:
                        allowed_from = "Various"
            
            md.append(f"| {svc} | {port_str} | {allowed_from} | API/Service |\n")
        
        md.append("\n")
        
        # Attack Surface Analysis
        md.append("## Attack Surface Analysis\n\n")
        
        md.append("### External Attack Surface (from APE network)\n\n")
        md.append("**Ports accessible from 192.168.90.103/105 (Autopilot computers):**\n\n")
        
        ape_accessible = []
        for rule in main_firewall['ape_input_rules']:
            ports_match = re.search(r'--dport[s]?\s+([\d,]+)', rule)
            if ports_match:
                ape_accessible.append(ports_match.group(1))
        
        md.append("```\n")
        md.append("APE-Accessible Ports:\n")
        for ports in set(ape_accessible):
            md.append(f"  - {ports}\n")
        md.append("```\n\n")
        
        md.append("### Localhost-Only Services\n\n")
        md.append("Services bound to 127.0.0.1 (not accessible from network):\n\n")
        
        localhost_services = [
            svc for svc, data in services.items()
            if data.get('has_firewall') and self._is_localhost_only(svc)
        ]
        
        for svc in localhost_services[:20]:
            md.append(f"- {svc}\n")
        
        md.append("\n")
        
        # Security Findings
        md.append("## Security Findings\n\n")
        
        md.append("### High-Risk Services\n\n")
        md.append("1. **service-shell (port 8081)**\n")
        md.append("   - Shell access service\n")
        md.append("   - Needs analysis for authentication\n\n")
        
        md.append("2. **toolbox-api (multiple ports)**\n")
        md.append("   - Diagnostic/debug API\n")
        md.append("   - Accessible from APE in some modes\n\n")
        
        md.append("3. **autopilot-api (ports 8443, 8444, etc)**\n")
        md.append("   - Critical AP communication\n")
        md.append("   - Limited to APE IPs (good)\n\n")
        
        md.append("### Network Isolation\n\n")
        md.append("**INTERNET Chain Effectiveness:**\n")
        md.append("- ✅ Blocks RFC1918 networks\n")
        md.append("- ✅ Logs violations before dropping\n")
        md.append("- ✅ Prevents services from accessing internal APIs via internet\n")
        md.append("- ⚠️ Factory mode opens port 8080 (debug backdoor)\n\n")
        
        md.append("**RunSandbox Usage:**\n")
        sandboxed_count = sum(1 for s in services.values() if s['sandbox'])
        md.append(f"- {sandboxed_count}/{len(services)} services use RunSandbox\n")
        md.append("- RunSandbox enforces cgroup-based firewall rules\n\n")
        
        md.append("### Key Vulnerabilities & Misconfigurations\n\n")
        
        md.append("1. **Factory Debug Mode**\n")
        md.append("   - If `FACTORY_DEBUG=1` and unfused: port 8080 exposed\n")
        md.append("   - Allows internal API access from internet-connected services\n")
        md.append("   - File: `/sbin/firewall` lines ~95-100\n\n")
        
        md.append("2. **Multicast Exposure**\n")
        md.append("   - 224.0.0.154, 224.0.0.155 used for UI/dashcam\n")
        md.append("   - Any device on 192.168.90.x can join multicast groups\n")
        md.append("   - Potential for eavesdropping on internal messages\n\n")
        
        md.append("3. **DoIP Gateway (port 13400)**\n")
        md.append("   - Link-local 169.254.0.0/16 access\n")
        md.append("   - Used for UDS diagnostics\n")
        md.append("   - NAT rules redirect to 192.168.93.82 namespace\n\n")
        
        md.append("### Recommendations\n\n")
        md.append("1. Audit all services listening on `0.0.0.0`\n")
        md.append("2. Verify authentication on APE-accessible ports\n")
        md.append("3. Review factory mode conditions (`is-in-factory`, `is-factory-gated`)\n")
        md.append("4. Analyze RunSandbox cgroup assignments for privilege escalation\n")
        md.append("5. Map all multicast subscribers and message formats\n\n")
        
        md.append("---\n\n")
        md.append("## Appendix: Raw Firewall Rules\n\n")
        md.append("### Main Firewall Script\n\n")
        md.append("```bash\n")
        md.append(main_firewall['full_content'][:5000])  # First 5000 chars
        md.append("\n...(truncated)\n```\n\n")
        
        return ''.join(md)
    
    def _is_localhost_only(self, service):
        """Check if service only binds to localhost"""
        fw_file = f"{FIREWALL_DIR}/{service}.iptables"
        
        if not os.path.exists(fw_file):
            return False
        
        with open(fw_file, 'r') as f:
            content = f.read()
        
        # Check for localhost-only patterns
        return ('127.0.0.1' in content or 'lo' in content) and '0.0.0.0' not in content

def main():
    analyzer = NetworkAnalyzer()
    
    print("[*] Parsing firewall rules...")
    firewall_rules = analyzer.parse_all_firewall_rules()
    
    print("[*] Parsing main firewall script...")
    main_firewall = analyzer.parse_main_firewall()
    
    print("[*] Analyzing service configurations...")
    services = analyzer.analyze_service_configs()
    
    print("[*] Generating comprehensive report...")
    report = analyzer.generate_markdown_report(firewall_rules, main_firewall, services)
    
    with open(OUTPUT_FILE, 'w') as f:
        f.write(report)
    
    print(f"[+] Analysis complete! Report written to: {OUTPUT_FILE}")
    print(f"[+] Total ports identified: {len(analyzer.ports)}")
    print(f"[+] Total services analyzed: {len(services)}")
    print(f"[+] Total firewall rules: {len(firewall_rules)}")

if __name__ == "__main__":
    main()
