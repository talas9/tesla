#!/usr/bin/env python3
"""
Gateway Command & Config Database Query Tool

Based on firmware decompilation results from 52-gateway-firmware-decompile.md

Usage:
    ./gateway_database_query.py --command 0x85
    ./gateway_database_query.py --config 15
    ./gateway_database_query.py --search "factory"
    ./gateway_database_query.py --list-secure
"""

import argparse
import sys

# Command dispatch table (extracted from firmware @ 0x800-0xCAC)
COMMAND_TABLE = {
    0x00: {
        'handler': 0x400014C8,
        'name': 'init_handler',
        'security': 'None',
        'description': 'Boot/initialization command'
    },
    0x67: {
        'handler': 0x40005470,
        'name': 'diag_mode_enter',
        'security': 'Low',
        'description': 'Enter diagnostic mode'
    },
    0x6A: {
        'handler': 0x40005478,
        'name': 'diag_extended',
        'security': 'Low',
        'description': 'Extended diagnostic mode'
    },
    0x75: {
        'handler': 0x400051A4,
        'name': 'uds_session_control',
        'security': 'Medium',
        'description': 'UDS session control'
    },
    0x85: {
        'handler': 0x400053BC,
        'name': 'factory_gate_trigger',
        'security': 'NONE',
        'description': '⚠️  Factory gate initialization (VULNERABLE)',
        'vulnerability': 'No authentication required'
    },
    0x88: {
        'handler': 0x400053C4,
        'name': 'factory_gate_accumulate',
        'security': 'NONE',
        'description': '⚠️  Factory gate data accumulator (VULNERABLE)',
        'vulnerability': 'No bounds checking - buffer overflow possible'
    },
    0x95: {
        'handler': 0x400051A4,
        'name': 'session_ctrl_alt',
        'security': 'Medium',
        'description': 'Alternative session control'
    },
    0xA5: {
        'handler': 0x40005470,
        'name': 'security_access_req',
        'security': 'High',
        'description': 'Security access request (seed)'
    },
    0xA8: {
        'handler': 0x40005478,
        'name': 'security_access_resp',
        'security': 'High',
        'description': 'Security access response (key)'
    },
    0xBA: {
        'handler': 0x40005524,
        'name': 'unlock_ecu',
        'security': 'High',
        'description': 'ECU unlock command (magic: BA BB A0 AD)'
    },
    0xBD: {
        'handler': 0x4000552C,
        'name': 'auth_response',
        'security': 'High',
        'description': 'Authentication response'
    },
    0xCF: {
        'handler': 0x400055D8,
        'name': 'ecu_reset',
        'security': 'Medium',
        'description': 'ECU reset command'
    },
    0xD2: {
        'handler': 0x400055E0,
        'name': 'session_terminate',
        'security': 'Low',
        'description': 'End diagnostic session'
    },
    0xE4: {
        'handler': 0x4000568C,
        'name': 'read_data_by_id',
        'security': 'Low',
        'description': 'UDS Read Data By Identifier (DID)'
    },
    0xE7: {
        'handler': 0x40005694,
        'name': 'write_data_by_id',
        'security': 'Medium',
        'description': 'UDS Write Data By Identifier (DID)'
    },
    0xF9: {
        'handler': 0x40005740,
        'name': 'enter_bootloader',
        'security': 'High',
        'description': 'Enter firmware update mode'
    },
    0xFC: {
        'handler': 0x40005748,
        'name': 'transfer_firmware',
        'security': 'High',
        'description': 'Transfer firmware chunk (8 bytes/frame)'
    },
}

# Configuration database (extracted from /internal.dat + config dumps)
CONFIG_TABLE = {
    0: {
        'name': 'vin',
        'type': 'ASCII',
        'length': 17,
        'secure': True,
        'default': None,
        'description': 'Vehicle Identification Number'
    },
    1: {
        'name': 'carcomputer_pn',
        'type': 'ASCII',
        'length': 12,
        'secure': True,
        'default': None,
        'description': 'MCU part number'
    },
    2: {
        'name': 'carcomputer_sn',
        'type': 'ASCII',
        'length': 14,
        'secure': True,
        'default': None,
        'description': 'MCU serial number'
    },
    5: {
        'name': 'birthday',
        'type': 'uint32',
        'length': 4,
        'secure': True,
        'default': 0,
        'description': 'Unix timestamp (vehicle build date)'
    },
    6: {
        'name': 'country',
        'type': 'ASCII',
        'length': 2,
        'secure': False,
        'default': 'US',
        'description': 'Country code (ISO 3166-1 alpha-2)',
        'values': {
            'US': 'United States',
            'DE': 'Germany',
            'NL': 'Netherlands',
            'UK': 'United Kingdom',
            'CN': 'China',
            'JP': 'Japan'
        }
    },
    7: {
        'name': 'exteriorColor',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Paint color code'
    },
    8: {
        'name': 'drivetrainType',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Drivetrain configuration',
        'values': {
            0: 'RWD (Rear-Wheel Drive)',
            1: 'AWD (All-Wheel Drive)',
            2: 'Performance AWD'
        }
    },
    9: {
        'name': 'airSuspension',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Air suspension type',
        'values': {
            0: 'Coil springs',
            1: 'Standard air suspension',
            2: 'Premium air suspension'
        }
    },
    15: {
        'name': 'devSecurityLevel',
        'type': 'uint8',
        'length': 1,
        'secure': True,
        'default': 3,
        'description': '⚠️  CRITICAL: Security mode (controls signature verification)',
        'values': {
            1: 'Factory mode (NO signature checks, factory gate enabled)',
            2: 'Development mode (relaxed checks)',
            3: 'Production mode (full security enforcement)'
        },
        'warning': 'Changing this to 1 disables all firmware signature verification!'
    },
    28: {
        'name': 'headlamps',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Headlight type',
        'values': {
            0: 'Base halogen',
            1: 'Premium LED',
            2: 'Global adaptive LED'
        }
    },
    29: {
        'name': 'autopilot',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Autopilot hardware version',
        'values': {
            0: 'No Autopilot',
            1: 'AP1 (Mobileye)',
            2: 'AP2.0',
            3: 'AP2.5',
            4: 'AP3.0 (FSD Computer)'
        }
    },
    30: {
        'name': 'superchargingAccess',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Supercharging access level',
        'values': {
            0: 'Not allowed',
            1: 'Free unlimited',
            2: 'Pay-as-you-go'
        }
    },
    37: {
        'name': 'prodCodeKey',
        'type': 'binary',
        'length': 32,
        'secure': True,
        'default': bytes(32),
        'description': '⚠️  Production firmware signature public key (RSA modulus)',
        'warning': 'Critical cryptographic material - read-only in production'
    },
    38: {
        'name': 'prodCmdKey',
        'type': 'binary',
        'length': 32,
        'secure': True,
        'default': bytes(32),
        'description': '⚠️  Production command authentication key (HMAC-SHA256)',
        'warning': 'Critical cryptographic material - read-only in production'
    },
    59: {
        'name': 'dasHw',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 4,
        'description': 'DAS (Driver Assistance System) hardware',
        'values': {
            3: 'PARKER_PASCAL_2_5 (AP2.5)',
            4: 'TESLA_AP3 (FSD Computer)'
        }
    },
    60: {
        'name': 'securityVersion',
        'type': 'uint32',
        'length': 4,
        'secure': True,
        'default': 8,
        'description': 'Security protocol version number'
    },
    61: {
        'name': 'bmpWatchdogDisabled',
        'type': 'uint8',
        'length': 1,
        'secure': True,
        'default': 0,
        'description': '⚠️  DANGEROUS: Disable watchdog timer (0=enabled, 1=disabled)',
        'warning': 'Disabling watchdog can cause system hang without recovery'
    },
    66: {
        'name': 'mapRegion',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 0,
        'description': 'Map data region',
        'values': {
            0: 'US - United States',
            1: 'EU - Europe',
            2: 'NONE - No maps',
            3: 'CN - China',
            4: 'AU - Australia',
            5: 'JP - Japan',
            6: 'TW - Taiwan',
            7: 'KR - South Korea',
            8: 'ME - Middle East',
            9: 'HK - Hong Kong',
            10: 'MO - Macau',
            11: 'SE - Southeast Asia'
        }
    },
    149: {
        'name': 'logLevel',
        'type': 'uint8',
        'length': 1,
        'secure': False,
        'default': 11,
        'description': 'Debug log verbosity (0=silent, 15=maximum)'
    },
}

# UDP protocol commands (port 3500)
UDP_COMMANDS = {
    0x0B: {
        'name': 'ReadConfig',
        'format': '0B 00 <ID>',
        'description': 'Read configuration value',
        'example': '0B 00 3B  # Read dasHw (config ID 59)'
    },
    0x0C: {
        'name': 'WriteConfig',
        'format': '0C 00 <ID> <VALUE>',
        'description': 'Write configuration value (if not secure)',
        'example': '0C 00 42 01  # Set mapRegion to EU (ID 66, value 1)'
    },
    0x14: {
        'name': 'Promote',
        'format': '14 DE AD BE EF',
        'description': 'Elevate privileges / promote mode',
        'example': '14 DE AD BE EF'
    },
    0x18: {
        'name': 'UnlockSwitch',
        'format': '18 BA BB A0 AD',
        'description': 'Unlock secured configurations (requires valid session)',
        'example': '18 BA BB A0 AD'
    },
}


def query_command(can_id):
    """Query command database by CAN ID"""
    if can_id in COMMAND_TABLE:
        cmd = COMMAND_TABLE[can_id]
        print(f"\n{'='*70}")
        print(f"CAN Command: 0x{can_id:02X}")
        print(f"{'='*70}")
        print(f"Handler Address:  0x{cmd['handler']:08X}")
        print(f"Function Name:    {cmd['name']}")
        print(f"Security Level:   {cmd['security']}")
        print(f"Description:      {cmd['description']}")
        if 'vulnerability' in cmd:
            print(f"\n⚠️  VULNERABILITY: {cmd['vulnerability']}")
        print(f"{'='*70}\n")
    else:
        print(f"\n❌ CAN ID 0x{can_id:02X} not found in command table")
        print("   This command uses the default handler (0x40005E34)\n")


def query_config(config_id):
    """Query configuration database by ID"""
    if config_id in CONFIG_TABLE:
        cfg = CONFIG_TABLE[config_id]
        print(f"\n{'='*70}")
        print(f"Config ID: {config_id} (0x{config_id:02X})")
        print(f"{'='*70}")
        print(f"Name:         {cfg['name']}")
        print(f"Type:         {cfg['type']}")
        print(f"Length:       {cfg['length']} bytes")
        print(f"Secure:       {'✅ YES (protected)' if cfg['secure'] else '❌ NO (writable)'}")
        print(f"Default:      {cfg['default']}")
        print(f"Description:  {cfg['description']}")
        
        if 'values' in cfg:
            print(f"\nValid Values:")
            for val, desc in cfg['values'].items():
                print(f"  {val:>3} → {desc}")
        
        if 'warning' in cfg:
            print(f"\n⚠️  WARNING: {cfg['warning']}")
        
        # Show how to read/write
        print(f"\n{'─'*70}")
        print("UDP Commands:")
        print(f"  Read:  0B 00 {config_id:02X}")
        if not cfg['secure']:
            print(f"  Write: 0C 00 {config_id:02X} <VALUE>")
        else:
            print(f"  Write: ⛔ BLOCKED (secure config - requires factory gate)")
        print(f"{'='*70}\n")
    else:
        print(f"\n❌ Config ID {config_id} not documented\n")


def search_database(query):
    """Search command and config databases"""
    query = query.lower()
    results = []
    
    # Search commands
    for can_id, cmd in COMMAND_TABLE.items():
        if (query in cmd['name'].lower() or 
            query in cmd['description'].lower()):
            results.append(('command', can_id, cmd))
    
    # Search configs
    for cfg_id, cfg in CONFIG_TABLE.items():
        if (query in cfg['name'].lower() or 
            query in cfg['description'].lower()):
            results.append(('config', cfg_id, cfg))
    
    if results:
        print(f"\n🔍 Search results for '{query}':\n")
        print(f"{'='*70}")
        
        for result_type, item_id, item in results:
            if result_type == 'command':
                print(f"[CAN 0x{item_id:02X}] {item['name']}")
                print(f"  → {item['description']}")
            else:
                print(f"[CFG {item_id:>3}] {item['name']} ({'SECURE' if item['secure'] else 'writable'})")
                print(f"  → {item['description']}")
            print()
        
        print(f"{'='*70}\n")
    else:
        print(f"\n❌ No results found for '{query}'\n")


def list_secure_configs():
    """List all secure configurations"""
    print(f"\n{'='*70}")
    print("SECURE CONFIGURATIONS (Protected - Require Factory Gate)")
    print(f"{'='*70}\n")
    
    for cfg_id, cfg in sorted(CONFIG_TABLE.items()):
        if cfg['secure']:
            print(f"ID {cfg_id:3} (0x{cfg_id:02X}): {cfg['name']:<25} [{cfg['type']}, {cfg['length']} bytes]")
            print(f"         {cfg['description']}")
            if 'warning' in cfg:
                print(f"         ⚠️  {cfg['warning']}")
            print()
    
    print(f"{'='*70}\n")


def list_all_commands():
    """List all CAN commands"""
    print(f"\n{'='*70}")
    print("GATEWAY CAN COMMAND TABLE")
    print(f"{'='*70}\n")
    
    for can_id, cmd in sorted(COMMAND_TABLE.items()):
        sec_icon = '⚠️ ' if cmd['security'] == 'NONE' else '  '
        print(f"{sec_icon}0x{can_id:02X}  {cmd['name']:<30} [{cmd['security']}]")
        print(f"       {cmd['description']}")
        if 'vulnerability' in cmd:
            print(f"       🔓 {cmd['vulnerability']}")
        print()
    
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Tesla Gateway Command & Config Database Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --command 0x85              # Query factory gate trigger
  %(prog)s --config 15                 # Query devSecurityLevel
  %(prog)s --search "factory"          # Search for "factory"
  %(prog)s --list-secure               # List all secure configs
  %(prog)s --list-commands             # List all CAN commands
        """
    )
    
    parser.add_argument('--command', '-c', type=lambda x: int(x, 0),
                        help='Query CAN command by ID (hex or decimal)')
    parser.add_argument('--config', '-f', type=int,
                        help='Query configuration by ID (decimal)')
    parser.add_argument('--search', '-s', type=str,
                        help='Search database by keyword')
    parser.add_argument('--list-secure', action='store_true',
                        help='List all secure configurations')
    parser.add_argument('--list-commands', action='store_true',
                        help='List all CAN commands')
    
    args = parser.parse_args()
    
    if args.command is not None:
        query_command(args.command)
    elif args.config is not None:
        query_config(args.config)
    elif args.search:
        search_database(args.search)
    elif args.list_secure:
        list_secure_configs()
    elif args.list_commands:
        list_all_commands()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
