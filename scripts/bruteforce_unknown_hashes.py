#!/usr/bin/env python3
"""
Brute-force unknown config value hashes
Tries common enum patterns to decode remaining unknown values
"""

import json
import hashlib

def generate_valuehash(key, value, salt):
    return hashlib.sha256(f"{value}{key}{salt}".encode()).hexdigest()

# Common enum patterns
COMMON_PATTERNS = [
    # Model variants
    "MODEL_Y_CHASSIS", "MODEL_Y", "MY",
    # Colors
    "QUICKSILVER", "MIDNIGHT_CHERRY_RED", "ULTRA_RED", "STEALTH_GREY",
    # ADAS
    "TESLA_AP4_HIGH", "TESLA_AP5", "HW4_HIGH",
    # Camera types
    "RCCB_CAMERAS_V2", "RCCB_CAMERAS_HIGH_RES",
    # Performance
    "PERFORMANCE_PLUS", "TRACK_PACKAGE", 
    # EPAS
    "BOSCH_EPAS", "ZF_EPAS", "EPAS_V2",
    # RGB
    "RGB_ENABLED", "RGB_DISABLED",
    # RDU Cable
    "TYPE_A", "TYPE_B", "TYPE_C", "RDU_CABLE_TYPE_1", "RDU_CABLE_TYPE_2",
    # Radar heater
    "RADAR_HEATER_ENABLED", "RADAR_HEATER_DISABLED", "HEATER_TYPE_1",
]

def load_config():
    with open('/root/tesla/data/configs/config-options-FULL-DECODED.json', 'r') as f:
        return json.load(f)

def main():
    data = load_config()
    salt = data['metadata']['salt']
    
    # Collect unknown hashes
    unknown = {}
    for config_name, config_data in data['configs'].items():
        for val in config_data['values']:
            if not val.get('decoded', False):
                hash_val = val.get('hash')
                if hash_val:
                    if config_name not in unknown:
                        unknown[config_name] = []
                    unknown[config_name].append(hash_val)
    
    print(f"Trying to decode {sum(len(v) for v in unknown.values())} unknown hashes...")
    print(f"Salt: {salt}\n")
    
    found = 0
    
    for config_name, hashes in unknown.items():
        print(f"\n{config_name}:")
        for hash_val in hashes:
            # Try common patterns
            for pattern in COMMON_PATTERNS:
                test_hash = generate_valuehash(config_name, pattern, salt)
                if test_hash == hash_val:
                    print(f"  ✓ FOUND: {pattern} = {hash_val[:16]}...")
                    found += 1
                    break
            else:
                print(f"  ✗ Unknown: {hash_val[:16]}...")
    
    print(f"\n{'='*80}")
    print(f"Results: {found}/{sum(len(v) for v in unknown.values())} decoded")
    
if __name__ == "__main__":
    main()
