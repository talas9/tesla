#!/usr/bin/env python3
"""
Match Odin routines database to Ryzen Gateway config dump.

Maps accessId/codeKey from Odin to actual config IDs (0x0000-0x00A1) 
by matching enum values and descriptions.

Input files:
- file_25---7619e162-1af2-4fc7-b3a7-4892f005ef96.json (Odin database)
- gateway_configs_parsed.txt (Ryzen config dump)

Output:
- odin_config_mapping.txt (accessId → config_id → security_level)
"""

import json
import re
import struct
from pathlib import Path

# File paths
ODIN_FILE = Path("/root/.openclaw/media/inbound/file_25---7619e162-1af2-4fc7-b3a7-4892f005ef96.json")
CONFIGS_FILE = Path("/root/tesla/gateway_configs_parsed.txt")
OUTPUT_FILE = Path("/root/tesla/odin_config_mapping.txt")

def load_odin_database():
    """Load Odin routines database."""
    with open(ODIN_FILE) as f:
        data = json.load(f)
    
    # Combine gen3 and gen2
    all_configs = data.get("gen3", []) + data.get("gen2", [])
    return all_configs

def load_gateway_configs():
    """Parse gateway_configs_parsed.txt to extract config values."""
    configs = {}
    
    with open(CONFIGS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Parse format: ID=0x0007, offset=0x00019158, len=1, data=01
            m = re.match(r"ID=0x([0-9A-Fa-f]{4}), offset=.+, len=(\d+), data=(.+)", line)
            if not m:
                continue
            
            config_id = int(m.group(1), 16)
            length = int(m.group(2))
            data_str = m.group(3)
            
            # Parse data
            if data_str.startswith("'") and data_str.endswith("'"):
                # String data
                data = data_str[1:-1].encode('ascii')
            elif len(data_str) == 2 and all(c in '0123456789ABCDEFabcdef' for c in data_str):
                # Hex byte
                data = bytes.fromhex(data_str)
            elif data_str == "''":
                # Empty
                data = b''
            else:
                # Multi-byte hex or other format
                try:
                    data = bytes.fromhex(data_str)
                except:
                    data = data_str.encode('ascii')
            
            configs[config_id] = {
                "id": config_id,
                "data": data,
                "length": length
            }
    
    return configs

def match_configs(odin_configs, gateway_configs):
    """Match Odin enum values to Gateway config data."""
    matches = []
    
    for odin in odin_configs:
        access_id = odin.get("accessId")
        code_key = odin.get("codeKey")
        access_level = odin.get("accessLevel", "")  # UDP, GTW, or empty
        description = odin.get("description", "")
        
        # Get enum values
        enums = odin.get("content", {}).get("enums", [])
        if not enums:
            continue
        
        # Try to match enum values to config data
        for config_id, config_data in gateway_configs.items():
            if config_data["length"] == 0:
                continue
            
            data = config_data["data"]
            
            # Check if data matches any enum value
            for enum in enums:
                enum_value = enum.get("value")
                
                # Convert enum value to bytes
                if isinstance(enum_value, int):
                    # Try different byte lengths
                    for byte_len in [1, 2, 4]:
                        try:
                            if byte_len == 1:
                                test_bytes = bytes([enum_value])
                            elif byte_len == 2:
                                test_bytes = struct.pack('<H', enum_value)
                            elif byte_len == 4:
                                test_bytes = struct.pack('<I', enum_value)
                            
                            if data == test_bytes or data.startswith(test_bytes):
                                # MATCH!
                                matches.append({
                                    "config_id": config_id,
                                    "access_id": access_id,
                                    "code_key": code_key,
                                    "access_level": access_level,
                                    "description": description,
                                    "enum_matched": enum.get("codeKey"),
                                    "enum_value": enum_value,
                                    "data_hex": data.hex(),
                                    "confidence": "HIGH" if data == test_bytes else "MEDIUM"
                                })
                                break
                        except:
                            pass
                
                elif isinstance(enum_value, str):
                    # Gen2 uses strings
                    try:
                        int_value = int(enum_value)
                        test_bytes = bytes([int_value])
                        
                        if data == test_bytes or data.startswith(test_bytes):
                            matches.append({
                                "config_id": config_id,
                                "access_id": access_id,
                                "code_key": code_key,
                                "access_level": access_level,
                                "description": description,
                                "enum_matched": enum.get("codeKey"),
                                "enum_value": int_value,
                                "data_hex": data.hex(),
                                "confidence": "HIGH" if data == test_bytes else "MEDIUM"
                            })
                            break
                    except:
                        pass
    
    return matches

def write_report(matches):
    """Write mapping report."""
    # Remove duplicates (prefer HIGH confidence)
    unique = {}
    for m in matches:
        config_id = m["config_id"]
        if config_id not in unique or m["confidence"] == "HIGH":
            unique[config_id] = m
    
    matches = list(unique.values())
    matches.sort(key=lambda x: x["config_id"])
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("# Odin Routines → Gateway Config ID Mapping\n")
        f.write("# Generated from Ryzen Gateway flash dump + Odin database\n\n")
        
        f.write(f"Total matches: {len(matches)}\n\n")
        
        # Summary by security level
        udp_configs = [m for m in matches if m["access_level"] == "UDP"]
        gtw_configs = [m for m in matches if m["access_level"] == "GTW"]
        normal_configs = [m for m in matches if not m["access_level"]]
        
        f.write(f"UDP-accessible configs (INSECURE): {len(udp_configs)}\n")
        f.write(f"GTW-only configs (HW-LOCKED): {len(gtw_configs)}\n")
        f.write(f"Normal configs (LIKELY SECURE): {len(normal_configs)}\n\n")
        
        f.write("="*80 + "\n\n")
        
        # Write matches
        for m in matches:
            security = "🔓 INSECURE" if m["access_level"] == "UDP" else \
                      "🚫 HW-LOCKED" if m["access_level"] == "GTW" else \
                      "🔒 LIKELY SECURE"
            
            f.write(f"Config ID: 0x{m['config_id']:04X} | accessId: {m['access_id']} | {security}\n")
            f.write(f"  Code Key: {m['code_key']}\n")
            f.write(f"  Description: {m['description']}\n")
            f.write(f"  Matched Enum: {m['enum_matched']} = {m['enum_value']}\n")
            f.write(f"  Data: {m['data_hex']}\n")
            f.write(f"  Confidence: {m['confidence']}\n")
            f.write("\n")

def main():
    print("Loading Odin database...")
    odin_configs = load_odin_database()
    print(f"  Loaded {len(odin_configs)} configs")
    
    print("\nLoading Gateway config dump...")
    gateway_configs = load_gateway_configs()
    print(f"  Loaded {len(gateway_configs)} configs")
    
    print("\nMatching enum values...")
    matches = match_configs(odin_configs, gateway_configs)
    print(f"  Found {len(matches)} matches")
    
    print("\nWriting report...")
    write_report(matches)
    print(f"  Report written to: {OUTPUT_FILE}")
    
    # Print summary
    udp_matches = [m for m in matches if m["access_level"] == "UDP"]
    gtw_matches = [m for m in matches if m["access_level"] == "GTW"]
    
    print("\n" + "="*80)
    print("CRITICAL FINDINGS:")
    print("="*80)
    
    if udp_matches:
        print(f"\n🔓 INSECURE CONFIGS (UDP-accessible): {len(udp_matches)}")
        for m in udp_matches:
            print(f"  - 0x{m['config_id']:04X}: {m['code_key']} ({m['description']})")
    
    if gtw_matches:
        print(f"\n🚫 HW-LOCKED CONFIGS (GTW-only): {len(gtw_matches)}")
        for m in gtw_matches:
            print(f"  - 0x{m['config_id']:04X}: {m['code_key']} ({m['description']})")
    
    print(f"\n🔒 LIKELY SECURE CONFIGS: {len([m for m in matches if not m['access_level']])}")
    print("\nDone!")

if __name__ == "__main__":
    main()
