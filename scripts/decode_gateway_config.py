#!/usr/bin/env python3
"""
Tesla Gateway Config Decoder - COMPLETE
Decodes SHA256-hashed config-options.json files using unhashed reference database

Author: Research
Version: 3.0
Date: 2026-02-05

Description:
    Odin's config-options.json files use SHA256 hashing with a salt to obscure
    configuration keys and values. This script decodes them using an unhashed
    reference database extracted from older firmware.

Usage:
    # Decode with embedded reference (automatic)
    python3 decode_gateway_config.py /path/to/config-options.json

    # Use custom reference file
    python3 decode_gateway_config.py config.json --reference /path/to/reference.json

Output Files:
    - config-options-FULL-DECODED.json  (Machine-readable JSON)
    - config-options-FULL-DECODED.txt   (Human-readable text)
"""

import json
import hashlib
import argparse
from pathlib import Path
import sys

# Embedded minimal reference - full reference auto-loaded if available
REFERENCE_FILE = "/root/.openclaw/media/inbound/file_25---7619e162-1af2-4fc7-b3a7-4892f005ef96.json"

# Additional known enum values from brute-force (not in old reference)
BRUTEFORCE_ENUMS = {
    "exteriorColor": [
        {"codeKey": "MIDNIGHT_CHERRY_RED", "value": None, "description": "Midnight Cherry Red"},
        {"codeKey": "QUICKSILVER", "value": None, "description": "Quicksilver"},
        {"codeKey": "ABYSS_BLUE", "value": None, "description": "Abyss Blue (Deep Blue Metallic)"},
    ],
    "chassisType": [
        {"codeKey": "MODEL_Y_CHASSIS", "value": 3, "description": "Model Y Chassis"},
    ],
}


def generate_sha256(data):
    """Generate SHA256 hash of data"""
    bytes_data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(bytes_data).hexdigest()

def generate_keyhash(key, salt):
    """Generate hash for config key
    
    Formula: SHA256(key + salt)
    """
    return generate_sha256(f"{key}{salt}")

def generate_valuehash(key, value, salt):
    """Generate hash for config value
    
    Formula: SHA256(value + key + salt)
    """
    return generate_sha256(f"{value}{key}{salt}")

def load_reference_database(reference_path=None):
    """Load unhashed reference database
    
    Returns:
        dict: {codeKey: config_data}
    """
    ref_path = reference_path or REFERENCE_FILE
    
    if not Path(ref_path).exists():
        print(f"Warning: Reference file not found: {ref_path}")
        print("Decoding will be limited to configs with public enums")
        return {}
    
    try:
        with open(ref_path, 'r') as f:
            data = json.load(f)
        
        # Build lookup dictionary
        reference = {}
        for platform in ['gen3', 'gen2', 'common']:
            for config in data.get(platform, []):
                code_key = config.get('codeKey')
                if code_key:
                    reference[code_key] = config
        
        print(f"Loaded {len(reference)} reference configs from {Path(ref_path).name}")
        return reference
        
    except Exception as e:
        print(f"Error loading reference: {e}")
        return {}

def decode_full_config(config_path, reference_db=None):
    """Decode config with full value enumeration
    
    Args:
        config_path: Path to config-options.json
        reference_db: Optional reference database
        
    Returns:
        dict with metadata and decoded configs
    """
    
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    if "salt" not in data:
        return {"error": "Config is not encoded", "data": data}
    
    salt = data["salt"]
    hashed = data.get("hashed", {})
    public = data.get("public", {})
    
    # Load reference if not provided
    if reference_db is None:
        reference_db = load_reference_database()
    
    result = {
        "metadata": {
            "source": str(config_path),
            "salt": salt,
            "total_hashed_keys": len(hashed),
            "total_public_keys": len(public),
            "reference_configs": len(reference_db)
        },
        "configs": {}
    }
    
    # Load bruteforce enums
    bruteforce_db = {}
    if 'BRUTEFORCE_ENUMS' in globals():
        bruteforce_db = BRUTEFORCE_ENUMS
    
    # Build reverse lookup: hash -> codeKey
    key_lookup = {}
    value_lookup = {}
    
    # First pass: use public section (has enum definitions)
    for pub_key, pub_value in public.items():
        key_hash = generate_keyhash(pub_key, salt)
        key_lookup[key_hash] = pub_key
        
        # Build value lookup from public enums
        enums = pub_value.get("content", {}).get("enums", [])
        for enum in enums:
            code_key = enum.get("codeKey")
            if code_key:
                val_hash = generate_valuehash(pub_key, code_key, salt)
                value_lookup[val_hash] = {
                    "config_key": pub_key,
                    "enum": enum
                }
    
    # Add bruteforce enums
    for bf_key, bf_enums in bruteforce_db.items():
        for enum in bf_enums:
            code_key = enum.get("codeKey")
            if code_key:
                val_hash = generate_valuehash(bf_key, code_key, salt)
                if val_hash not in value_lookup:
                    value_lookup[val_hash] = {
                        "config_key": bf_key,
                        "enum": enum
                    }
    
    # Second pass: use reference database for configs not in public section
    for ref_key, ref_config in reference_db.items():
        key_hash = generate_keyhash(ref_key, salt)
        
        # Only add if not already in public section
        if key_hash not in key_lookup:
            key_lookup[key_hash] = ref_key
        
        # Build value lookup from reference enums
        enums = ref_config.get("content", {}).get("enums", [])
        for enum in enums:
            code_key = enum.get("codeKey")
            if code_key:
                val_hash = generate_valuehash(ref_key, code_key, salt)
                if val_hash not in value_lookup:
                    value_lookup[val_hash] = {
                        "config_key": ref_key,
                        "enum": enum
                    }
    
    # Decode hashed section
    decoded_count = 0
    unknown_keys = []
    
    for key_hash, value_hashes in hashed.items():
        # Try to decode key
        if key_hash in key_lookup:
            config_key = key_lookup[key_hash]
            decoded_count += 1
            
            # Get config metadata (prefer public, fallback to reference)
            if config_key in public:
                config_meta = public[config_key]
                all_enums = config_meta.get("content", {}).get("enums", [])
            elif config_key in reference_db:
                config_meta = reference_db[config_key]
                all_enums = config_meta.get("content", {}).get("enums", [])
            else:
                config_meta = {}
                all_enums = []
            
            # Decode values
            decoded_values = []
            for val_hash in value_hashes:
                if val_hash in value_lookup:
                    enum_data = value_lookup[val_hash]
                    if enum_data["config_key"] == config_key:
                        decoded_values.append({
                            "codeKey": enum_data["enum"].get("codeKey"),
                            "value": enum_data["enum"].get("value"),
                            "description": enum_data["enum"].get("description", ""),
                            "decoded": True
                        })
                    else:
                        # Hash collision with different key
                        decoded_values.append({
                            "hash": val_hash,
                            "decoded": False,
                            "note": "Hash collision"
                        })
                else:
                    decoded_values.append({
                        "hash": val_hash,
                        "decoded": False
                    })
            
            result["configs"][config_key] = {
                "accessId": config_meta.get("accessId"),
                "description": config_meta.get("description", ""),
                "odinReadWriteAccess": config_meta.get("odinReadWriteAccess", ""),
                "values": decoded_values,
                "allEnums": all_enums
            }
        else:
            unknown_keys.append(key_hash)
    
    result["metadata"]["decoded_keys"] = decoded_count
    result["metadata"]["unknown_keys"] = len(unknown_keys)
    
    return result

def save_readable_output(result, output_path):
    """Save in human-readable format"""
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("TESLA GATEWAY CONFIGURATION OPTIONS - FULLY DECODED\n")
        f.write("=" * 80 + "\n\n")
        
        meta = result["metadata"]
        f.write(f"Source: {meta['source']}\n")
        f.write(f"Salt: {meta['salt']}\n")
        f.write(f"Decoded: {meta['decoded_keys']} keys\n")
        f.write(f"Unknown: {meta['unknown_keys']} keys\n")
        f.write(f"Reference DB: {meta.get('reference_configs', 0)} configs\n")
        f.write("\n" + "=" * 80 + "\n\n")
        
        for key, config in sorted(result["configs"].items()):
            f.write(f"\n{'=' * 80}\n")
            f.write(f"CONFIG: {key}\n")
            f.write(f"{'=' * 80}\n")
            
            if config.get("accessId"):
                f.write(f"Access ID: {config.get("accessId", "N/A")}\n")
            
            f.write(f"Description: {config.get('description', 'N/A')}\n")
            f.write(f"Access Level: {config.get('odinReadWriteAccess', 'N/A')}\n")
            
            # Count decoded vs undecoded values
            decoded_vals = [v for v in config['values'] if v.get('decoded', True)]
            undecoded_vals = [v for v in config['values'] if not v.get('decoded', True)]
            
            f.write(f"\nCurrent Values ({len(decoded_vals)} decoded, {len(undecoded_vals)} unknown):\n")
            for val in config['values']:
                if val.get('decoded', False):
                    f.write(f"  ✓ {val['codeKey']:30s} = {str(val.get('value', 'N/A')):5s}")
                    if val.get('description'):
                        f.write(f"  // {val['description']}")
                    f.write("\n")
                else:
                    f.write(f"  ✗ [UNKNOWN: {val.get('hash', 'N/A')[:16]}...]")
                    if val.get('note'):
                        f.write(f" ({val['note']})")
                    f.write("\n")
            
            if config.get('allEnums'):
                f.write(f"\nAll Possible Values ({len(config['allEnums'])}):\n")
                for enum in config['allEnums']:
                    f.write(f"  {enum.get('codeKey', 'N/A'):30s} = {str(enum.get('value', 'N/A')):5s}")
                    if enum.get('description'):
                        f.write(f"  // {enum['description']}")
                    f.write("\n")

def main():
    parser = argparse.ArgumentParser(
        description="Decode Tesla Gateway config-options.json files (COMPLETE VERSION)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decode with automatic reference lookup
  python3 decode_gateway_config.py /opt/odin/data/Model3/config-options.json
  
  # Use custom reference database
  python3 decode_gateway_config.py config.json --reference ./unhashed-reference.json
  
  # Specify output directory
  python3 decode_gateway_config.py config.json --output ./decoded/

Output:
  Creates two files:
    - config-options-FULL-DECODED.json  (machine-readable)
    - config-options-FULL-DECODED.txt   (human-readable, fully decoded)
        """)
    
    parser.add_argument('config_file', 
                       help='Path to config-options.json')
    parser.add_argument('--reference', '-r',
                       help='Path to unhashed reference database')
    parser.add_argument('--output', '-o',
                       help='Output directory (default: same as input file)')
    
    args = parser.parse_args()
    
    input_file = Path(args.config_file)
    
    if not input_file.exists():
        print(f"ERROR: File not found: {input_file}")
        sys.exit(1)
    
    print(f"Decoding: {input_file}")
    
    # Load reference database
    reference_db = load_reference_database(args.reference)
    
    # Decode config
    result = decode_full_config(input_file, reference_db)
    
    if "error" in result:
        print(f"ERROR: {result['error']}")
        sys.exit(1)
    
    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = input_file.parent
    
    # Save JSON
    json_output = output_dir / f"{input_file.stem}-FULL-DECODED.json"
    with open(json_output, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Save readable text
    txt_output = output_dir / f"{input_file.stem}-FULL-DECODED.txt"
    save_readable_output(result, txt_output)
    
    print(f"\n✓ JSON output: {json_output}")
    print(f"✓ Text output: {txt_output}")
    print(f"\nDecoded {result['metadata']['decoded_keys']} config keys")
    print(f"Unknown: {result['metadata']['unknown_keys']} keys")
    
    # Count decoded values
    total_values = 0
    decoded_values = 0
    for config in result['configs'].values():
        for val in config['values']:
            total_values += 1
            if val.get('decoded', False):
                decoded_values += 1
    
    print(f"\nValues: {decoded_values}/{total_values} decoded ({100*decoded_values//total_values if total_values else 0}%)")
    
    # Print sample configs
    print("\n" + "=" * 80)
    print("SAMPLE DECODED CONFIGS")
    print("=" * 80)
    
    sample_keys = ['packEnergy', 'dasHw', 'deliveryStatus', 'chassisType']
    for key in sample_keys:
        if key in result['configs']:
            cfg = result['configs'][key]
            decoded_count = sum(1 for v in cfg['values'] if v.get('decoded', False))
            print(f"\n{key} (Access ID: {cfg.get('accessId', 'N/A')})")
            print(f"  Values: {decoded_count}/{len(cfg['values'])} decoded")
            for val in cfg['values'][:3]:  # First 3
                if val.get('decoded', False):
                    print(f"    ✓ {val['codeKey']}: {val.get('value')}")
                else:
                    print(f"    ✗ {val.get('hash', 'unknown')[:16]}...")

if __name__ == "__main__":
    main()

# Additional known enum values from brute-force (not in reference)
BRUTEFORCE_ENUMS = {
    "exteriorColor": [
        {"codeKey": "MIDNIGHT_CHERRY_RED", "value": None, "description": "Midnight Cherry Red"},
        {"codeKey": "QUICKSILVER", "value": None, "description": "Quicksilver"},
        {"codeKey": "ABYSS_BLUE", "value": None, "description": "Abyss Blue (Deep Blue Metallic)"},
    ],
    "chassisType": [
        {"codeKey": "MODEL_Y_CHASSIS", "value": 3, "description": "Model Y Chassis"},
    ],
}
