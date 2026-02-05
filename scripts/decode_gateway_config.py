#!/usr/bin/env python3
"""
Tesla Gateway Config Decoder
Decodes SHA256-hashed config-options.json files from Odin firmware

Author: Research
Version: 2.0
Date: 2026-02-05

Description:
    Odin's config-options.json files use SHA256 hashing with a salt to obscure
    configuration keys and values. This script decodes them using the public
    enum definitions provided in the same file.

Usage:
    # Decode Model 3 config
    python3 decode_gateway_config.py /path/to/Model3/config-options.json

    # Decode with output directory
    python3 decode_gateway_config.py config-options.json --output ./decoded/

Output Files:
    - config-options-FULL-DECODED.json  (Machine-readable JSON)
    - config-options-FULL-DECODED.txt   (Human-readable text)
"""

import json
import hashlib
import argparse
from pathlib import Path
import sys

def generate_sha256(data):
    """Generate SHA256 hash of data"""
    bytes_data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(bytes_data).hexdigest()

def generate_keyhash(key, salt):
    """Generate hash for config key
    
    Formula: SHA256(key + salt)
    
    Args:
        key: Config key name (e.g., "brakeHWType")
        salt: Salt string from config file
        
    Returns:
        64-character hex string
    """
    return generate_sha256(f"{key}{salt}")

def generate_valuehash(key, value, salt):
    """Generate hash for config value
    
    Formula: SHA256(value + key + salt)
    
    Args:
        key: Config key name
        value: Enum code key (e.g., "BREMBO_P42_MANDO_43MOC")
        salt: Salt string from config file
        
    Returns:
        64-character hex string
    """
    return generate_sha256(f"{value}{key}{salt}")

def decode_full_config(config_path):
    """Decode config with full value enumeration
    
    Args:
        config_path: Path to config-options.json
        
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
    
    result = {
        "metadata": {
            "source": str(config_path),
            "salt": salt,
            "total_hashed_keys": len(hashed),
            "total_public_keys": len(public)
        },
        "configs": {}
    }
    
    # Decode using public keys which have enum definitions
    for pub_key, pub_value in public.items():
        # Generate hash for this key
        key_hash = generate_keyhash(pub_key, salt)
        
        if key_hash in hashed:
            value_hashes = hashed[key_hash]
            
            # Get enum definitions if available
            enums = pub_value.get("content", {}).get("enums", [])
            
            # Try to match value hashes to enums
            decoded_values = []
            for value_hash in value_hashes:
                matched = False
                for enum in enums:
                    code_key = enum.get("codeKey")
                    if code_key:
                        expected_hash = generate_valuehash(pub_key, code_key, salt)
                        if expected_hash == value_hash:
                            decoded_values.append({
                                "codeKey": code_key,
                                "value": enum.get("value"),
                                "description": enum.get("description", "")
                            })
                            matched = True
                            break
                
                if not matched:
                    decoded_values.append({
                        "hash": value_hash,
                        "decoded": False
                    })
            
            result["configs"][pub_key] = {
                "accessId": pub_value.get("accessId"),
                "description": pub_value.get("description", ""),
                "odinReadWriteAccess": pub_value.get("odinReadWriteAccess", ""),
                "values": decoded_values,
                "allEnums": enums
            }
    
    # Count decoded vs unknown
    decoded = len(result["configs"])
    unknown = len(hashed) - decoded
    
    result["metadata"]["decoded_keys"] = decoded
    result["metadata"]["unknown_keys"] = unknown
    
    return result

def save_readable_output(result, output_path):
    """Save in human-readable format
    
    Args:
        result: Decoded config dict
        output_path: Path to output .txt file
    """
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("TESLA GATEWAY CONFIGURATION OPTIONS - FULLY DECODED\n")
        f.write("=" * 80 + "\n\n")
        
        meta = result["metadata"]
        f.write(f"Source: {meta['source']}\n")
        f.write(f"Salt: {meta['salt']}\n")
        f.write(f"Decoded: {meta['decoded_keys']} keys\n")
        f.write(f"Unknown: {meta['unknown_keys']} keys\n")
        f.write("\n" + "=" * 80 + "\n\n")
        
        for key, config in sorted(result["configs"].items()):
            f.write(f"\n{'=' * 80}\n")
            f.write(f"CONFIG: {key}\n")
            f.write(f"{'=' * 80}\n")
            
            if config.get("accessId"):
                f.write(f"Access ID: {config['accessId']} (0x{config['accessId']:02X})\n")
            
            f.write(f"Description: {config.get('description', 'N/A')}\n")
            f.write(f"Access Level: {config.get('odinReadWriteAccess', 'N/A')}\n")
            
            f.write(f"\nCurrent Values ({len(config['values'])}):\n")
            for val in config['values']:
                if val.get('decoded', True):
                    f.write(f"  - {val['codeKey']}: {val.get('value', 'N/A')}")
                    if val.get('description'):
                        f.write(f" // {val['description']}")
                    f.write("\n")
                else:
                    f.write(f"  - [UNKNOWN HASH: {val['hash'][:16]}...]\n")
            
            f.write(f"\nAll Possible Values ({len(config['allEnums'])}):\n")
            for enum in config['allEnums']:
                f.write(f"  {enum['codeKey']:30s} = {str(enum.get('value', 'N/A')):5s}")
                if enum.get('description'):
                    f.write(f"  // {enum['description']}")
                f.write("\n")

def main():
    parser = argparse.ArgumentParser(
        description="Decode Tesla Gateway config-options.json files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decode Model 3 config
  python3 decode_gateway_config.py /opt/odin/data/Model3/config-options.json
  
  # Specify output directory
  python3 decode_gateway_config.py config.json --output ./decoded/
  
  # Process Model Y config
  python3 decode_gateway_config.py /opt/odin/data/ModelY/config-options.json

Output:
  Creates two files in the same directory as input (or --output dir):
    - config-options-FULL-DECODED.json  (machine-readable)
    - config-options-FULL-DECODED.txt   (human-readable)
        """)
    
    parser.add_argument('config_file', 
                       help='Path to config-options.json')
    parser.add_argument('--output', '-o',
                       help='Output directory (default: same as input file)')
    
    args = parser.parse_args()
    
    input_file = Path(args.config_file)
    
    if not input_file.exists():
        print(f"ERROR: File not found: {input_file}")
        sys.exit(1)
    
    print(f"Decoding: {input_file}")
    
    result = decode_full_config(input_file)
    
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
    
    # Print sample configs
    print("\n" + "=" * 80)
    print("SAMPLE DECODED CONFIGS")
    print("=" * 80)
    
    sample_keys = ['packEnergy', 'dasHw', 'brakeHWType', 'mapRegion']
    for key in sample_keys:
        if key in result['configs']:
            cfg = result['configs'][key]
            print(f"\n{key} (Access ID: {cfg.get('accessId', 'N/A')})")
            print(f"  Values: {len(cfg['values'])} options")
            for val in cfg['values'][:3]:  # First 3
                if val.get('decoded', True):
                    print(f"    - {val['codeKey']}: {val.get('value')}")

if __name__ == "__main__":
    main()
