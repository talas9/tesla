#!/usr/bin/env python3
"""
Enhanced MCU2 Network Analysis - Service-to-Binary-to-Port Mapping
"""

import os
import re
from pathlib import Path

MCU_ROOT = "/root/downloads/mcu2-extracted"

def extract_service_details():
    """Extract detailed service→binary→port mappings"""
    
    services = {}
    sv_dir = f"{MCU_ROOT}/etc/sv"
    
    for svc_name in os.listdir(sv_dir):
        run_file = f"{sv_dir}/{svc_name}/run"
        
        if not os.path.isfile(run_file):
            continue
        
        with open(run_file, 'r') as f:
            content = f.read()
        
        # Extract binary path
        binary_match = re.search(r'(?:exec|RunSandbox)\s+(/[\w/\-]+)', content)
        binary = binary_match.group(1) if binary_match else None
        
        # Extract user
        user_match = re.search(r'export USER=(\S+)', content)
        user = user_match.group(1) if user_match else 'root'
        
        # Check for RunSandbox
        sandboxed = 'RunSandbox' in content
        
        # Extract bind address if present
        bind_match = re.findall(r'--(?:address|bind)[= ]([0-9\.:]+)', content)
        bind_addr = bind_match[0] if bind_match else None
        
        # Extract port if present
        port_match = re.findall(r'--port[= ](\d+)', content)
        ports = port_match if port_match else []
        
        # Check for network namespace
        netns = 'NET_NS' in content or 'ip netns' in content
        
        services[svc_name] = {
            'binary': binary,
            'user': user,
            'sandboxed': sandboxed,
            'netns': netns,
            'bind_addr': bind_addr,
            'ports_from_script': ports
        }
    
    return services

def parse_firewall_chains():
    """Parse all iptables chains and their purposes"""
    
    firewall_script = f"{MCU_ROOT}/sbin/firewall"
    
    with open(firewall_script, 'r') as f:
        content = f.read()
    
    # Extract all custom chains
    chains = {}
    
    # Find chain definitions
    chain_defs = re.findall(r'^:(\S+)\s+-\s+\[', content, re.MULTILINE)
    
    for chain in chain_defs:
        # Extract rules for this chain
        rules = re.findall(rf'-A {chain}.*', content)
        chains[chain] = rules
    
    return chains

def analyze_port_accessibility():
    """Determine which ports are accessible from where"""
    
    access_matrix = {}
    
    # Parse main firewall
    firewall_script = f"{MCU_ROOT}/sbin/firewall"
    with open(firewall_script, 'r') as f:
        fw_content = f.read()
    
    # Extract APE_INPUT rules
    ape_rules = re.findall(r'-A APE_INPUT.*--dport[s]?\s+([\d,]+).*', fw_content)
    
    for port_spec in ape_rules:
        for port in port_spec.split(','):
            if port not in access_matrix:
                access_matrix[port] = {'accessible_from': []}
            access_matrix[port]['accessible_from'].append('APE (192.168.90.103/105)')
    
    # Check service-specific firewall files
    fw_dir = f"{MCU_ROOT}/etc/firewall.d"
    
    for fw_file in os.listdir(fw_dir):
        if not fw_file.endswith('.iptables'):
            continue
        
        service = fw_file.replace('.iptables', '')
        
        with open(f"{fw_dir}/{fw_file}", 'r') as f:
            content = f.read()
        
        # Find INPUT rules
        input_rules = re.findall(r'-A INPUT.*--dport[s]?\s+([\d,]+).*', content)
        
        # Determine accessibility
        if 'lo' in content or '127.0.0.1' in content:
            accessibility = 'Localhost only'
        elif '192.168.90.103' in content:
            accessibility = 'APE network'
        elif '0.0.0.0' in content:
            accessibility = 'All interfaces'
        else:
            accessibility = 'Unknown'
        
        for port_spec in input_rules:
            for port in port_spec.split(','):
                port = port.strip()
                if port not in access_matrix:
                    access_matrix[port] = {'accessible_from': []}
                access_matrix[port]['service'] = service
                if accessibility not in access_matrix[port]['accessible_from']:
                    access_matrix[port]['accessible_from'].append(accessibility)
    
    return access_matrix

def analyze_authentication():
    """Check for authentication mechanisms"""
    
    auth_info = {}
    
    # Check service-shell (certificate-based auth)
    run_file = f"{MCU_ROOT}/etc/sv/service-shell/run"
    if os.path.exists(run_file):
        with open(run_file, 'r') as f:
            content = f.read()
        
        auth_info['service-shell'] = {
            'port': 8081,
            'auth_type': 'TLS certificate',
            'ca_file': re.search(r'--ca "([^"]+)"', content).group(1) if re.search(r'--ca "([^"]+)"', content) else None,
            'requires_car_cert': 'car.crt' in content,
            'oid_restrictions': re.findall(r'--oid-env ([^\s]+)', content)
        }
    
    return auth_info

def generate_enhanced_report():
    """Generate enhanced markdown report"""
    
    services = extract_service_details()
    chains = parse_firewall_chains()
    access_matrix = analyze_port_accessibility()
    auth_info = analyze_authentication()
    
    report = []
    
    report.append("# MCU2 Network Security - Enhanced Analysis\n\n")
    report.append("## Service → Binary → Port Mapping\n\n")
    report.append("| Service | Binary | User | Ports | Bind Addr | Sandboxed | NetNS |\n")
    report.append("|---------|--------|------|-------|-----------|-----------|-------|\n")
    
    for svc, data in sorted(services.items())[:100]:
        binary = data['binary'] or 'N/A'
        user = data['user']
        ports = ', '.join(data['ports_from_script']) or '-'
        bind_addr = data['bind_addr'] or '-'
        sandboxed = '✓' if data['sandboxed'] else '-'
        netns = '✓' if data['netns'] else '-'
        
        # Truncate binary path
        if binary.startswith('/'):
            binary = binary.split('/')[-1]
        
        report.append(f"| {svc} | `{binary}` | {user} | {ports} | {bind_addr} | {sandboxed} | {netns} |\n")
    
    report.append("\n## Port Accessibility Matrix\n\n")
    report.append("| Port | Service | Accessible From | Risk Level |\n")
    report.append("|------|---------|-----------------|------------|\n")
    
    for port, data in sorted(access_matrix.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)[:100]:
        service = data.get('service', '?')
        accessible_from = ', '.join(data['accessible_from'])
        
        # Assess risk
        if 'All interfaces' in accessible_from or '0.0.0.0' in accessible_from:
            risk = '🔴 HIGH'
        elif 'APE network' in accessible_from:
            risk = '🟡 MEDIUM'
        elif 'Localhost' in accessible_from:
            risk = '🟢 LOW'
        else:
            risk = '⚪ UNKNOWN'
        
        report.append(f"| {port} | {service} | {accessible_from} | {risk} |\n")
    
    report.append("\n## Authentication Analysis\n\n")
    
    for service, auth_data in auth_info.items():
        report.append(f"### {service}\n\n")
        report.append(f"- **Port:** {auth_data['port']}\n")
        report.append(f"- **Auth Type:** {auth_data['auth_type']}\n")
        
        if auth_data.get('ca_file'):
            report.append(f"- **CA Certificate:** `{auth_data['ca_file']}`\n")
        
        if auth_data.get('requires_car_cert'):
            report.append(f"- **Requires Car Certificate:** ✓\n")
        
        if auth_data.get('oid_restrictions'):
            report.append(f"- **OID Restrictions:** {', '.join(auth_data['oid_restrictions'])}\n")
        
        report.append("\n")
    
    report.append("\n## Firewall Chain Analysis\n\n")
    
    for chain, rules in chains.items():
        report.append(f"### {chain}\n\n")
        report.append(f"**Total Rules:** {len(rules)}\n\n")
        
        if len(rules) <= 10:
            report.append("```\n")
            for rule in rules:
                report.append(f"{rule}\n")
            report.append("```\n\n")
        else:
            report.append(f"*(Too many rules to display - {len(rules)} total)*\n\n")
    
    return ''.join(report)

if __name__ == "__main__":
    print("[*] Extracting service details...")
    report = generate_enhanced_report()
    
    output_file = "/root/tesla/44-mcu-networking-enhanced.md"
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"[+] Enhanced report written to: {output_file}")
