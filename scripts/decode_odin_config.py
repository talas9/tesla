#!/usr/bin/env python3
"""
Decode the hashed Odin config-options.json using the unhashed reference.

The encoded file uses SHA-256(salt + codeKey) as keys.
We can reverse this by hashing all known codeKeys from the unhashed file.
"""

import json
import hashlib
from pathlib import Path

# File paths
UNHASHED_FILE = Path("/root/.openclaw/media/inbound/file_25---7619e162-1af2-4fc7-b3a7-4892f005ef96.json")
HASHED_FILE = Path("/root/downloads/model3y-extracted/opt/odin/data/Model3/config-options.json")
OUTPUT_FILE = Path("/root/tesla/odin-config-decoded.json")
MAPPING_FILE = Path("/root/tesla/odin-hash-mapping.txt")

def load_unhashed():
    """Load unhashed reference database."""
    with open(UNHASHED_FILE) as f:
        data = json.load(f)
    
    # Extract all codeKeys
    code_keys = {}
    for config in data.get("gen3", []) + data.get("gen2", []):
        code_key = config.get("codeKey")
        if code_key:
            code_keys[code_key] = config
    
    return code_keys

def load_hashed():
    """Load hashed config file."""
    with open(HASHED_FILE) as f:
        return json.load(f)

def hash_key(salt, code_key):
    """Generate SHA-256 hash of salt + codeKey."""
    combined = salt + code_key
    return hashlib.sha256(combined.encode()).hexdigest()

def decode_config(hashed_data, code_keys):
    """Decode hashed config by matching hashes."""
    salt = hashed_data.get("salt")
    hashed_configs = hashed_data.get("hashed", {})
    
    print(f"Salt: {salt}")
    print(f"Total hashed entries: {len(hashed_configs)}")
    print(f"Total known codeKeys: {len(code_keys)}")
    
    # Build hash → codeKey mapping
    hash_to_key = {}
    for code_key in code_keys.keys():
        h = hash_key(salt, code_key)
        hash_to_key[h] = code_key
    
    print(f"Generated {len(hash_to_key)} hashes")
    
    # Decode
    decoded = {}
    matched = 0
    unmatched = []
    
    for hash_value, config_data in hashed_configs.items():
        if hash_value in hash_to_key:
            code_key = hash_to_key[hash_value]
            decoded[code_key] = config_data
            matched += 1
        else:
            unmatched.append(hash_value)
    
    print(f"\nMatched: {matched}")
    print(f"Unmatched: {len(unmatched)}")
    
    return decoded, hash_to_key, unmatched

def write_output(decoded, hash_to_key, unmatched):
    """Write decoded config and mapping."""
    # Write decoded config
    with open(OUTPUT_FILE, "w") as f:
        json.dump(decoded, f, indent=2)
    
    print(f"\nDecoded config written to: {OUTPUT_FILE}")
    
    # Write mapping
    with open(MAPPING_FILE, "w") as f:
        f.write("# Odin Config Hash Mapping\n")
        f.write(f"# Salt: {hashed_data['salt']}\n\n")
        f.write("# Hash → codeKey\n")
        f.write("="*80 + "\n\n")
        
        for h, key in sorted(hash_to_key.items(), key=lambda x: x[1]):
            f.write(f"{h} → {key}\n")
        
        if unmatched:
            f.write("\n\n# UNMATCHED HASHES (new configs not in unhashed file)\n")
            f.write("="*80 + "\n\n")
            for h in unmatched:
                f.write(f"{h} → UNKNOWN\n")
    
    print(f"Mapping written to: {MAPPING_FILE}")

def analyze_changes(decoded, code_keys):
    """Analyze what changed between versions."""
    print("\n" + "="*80)
    print("ANALYSIS: Changes from unhashed to hashed version")
    print("="*80 + "\n")
    
    # Compare configs
    for code_key, new_data in decoded.items():
        if code_key not in code_keys:
            print(f"NEW CONFIG: {code_key}")
            continue
        
        old_config = code_keys[code_key]
        
        # Check if access level changed
        old_access = old_config.get("accessLevel", "")
        new_access = new_data.get("accessLevel", "")
        
        if old_access != new_access:
            print(f"ACCESS CHANGED: {code_key}")
            print(f"  Old: '{old_access}' → New: '{new_access}'")
        
        # Check if accessId changed
        old_id = old_config.get("accessId")
        new_id = new_data.get("accessId")
        
        if old_id != new_id:
            print(f"ACCESS ID CHANGED: {code_key}")
            print(f"  Old: {old_id} → New: {new_id}")

def main():
    print("Loading unhashed reference...")
    code_keys = load_unhashed()
    
    print("\nLoading hashed config...")
    hashed_data = load_hashed()
    
    print("\nDecoding...")
    decoded, hash_to_key, unmatched = decode_config(hashed_data, code_keys)
    
    print("\nWriting output...")
    write_output(decoded, hash_to_key, unmatched)
    
    print("\nAnalyzing changes...")
    analyze_changes(decoded, code_keys)
    
    print("\nDone!")

if __name__ == "__main__":
    hashed_data = load_hashed()
    main()
