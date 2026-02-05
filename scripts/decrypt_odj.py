#!/usr/bin/env python3
"""
Tesla Odin ODJ File Decryptor
Decrypts Fernet-encrypted ODJ (Odin Diagnostic Job) files

Author: Research
Version: 1.0
Date: 2026-02-05

Description:
    Odin's ODJ files contain diagnostic routines (VIN write, security access, etc.)
    encrypted using Fernet (symmetric encryption with PBKDF2 key derivation).
    
    Encryption Details:
    - Algorithm: Fernet (AES-128-CBC + HMAC-SHA256)
    - Key Derivation: PBKDF2-HMAC-SHA256
    - Iterations: 123456
    - Password: cmftubxi7wlvmh1wmbzz00vf1ziqezf6 (base64 decoded from binary_metadata_utils.py)

Usage:
    # Decrypt single ODJ file
    python3 decrypt_odj.py /path/to/file.odj

    # Decrypt all ODJ files in directory
    python3 decrypt_odj.py /opt/odin/data/Model3/odj/ --recursive

    # Specify output directory
    python3 decrypt_odj.py file.odj --output ./decrypted/

Output:
    Creates decrypted JSON files with same name (without .odj extension)
"""

import json
import base64
import argparse
import sys
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend

# Odin's hardcoded decryption password (from decompiled binary_metadata_utils.py)
ODIN_PASSWORD = "cmftubxi7wlvmh1wmbzz00vf1ziqezf6"

# PBKDF2 parameters (from decompiled code)
PBKDF2_ITERATIONS = 123456
PBKDF2_SALT = b"salt_123"  # Default salt used by Odin

def derive_key(password, salt=PBKDF2_SALT, iterations=PBKDF2_ITERATIONS):
    """Derive Fernet key from password using PBKDF2
    
    Args:
        password: Decryption password
        salt: Salt for PBKDF2 (default: Odin's default)
        iterations: PBKDF2 iterations (default: 123456)
        
    Returns:
        base64-encoded Fernet key
    """
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def decrypt_odj(encrypted_data, password=ODIN_PASSWORD):
    """Decrypt ODJ file content
    
    Args:
        encrypted_data: Encrypted bytes from .odj file
        password: Decryption password
        
    Returns:
        Decrypted dict (parsed JSON)
    """
    try:
        # Derive key
        key = derive_key(password)
        
        # Create Fernet cipher
        cipher = Fernet(key)
        
        # Decrypt
        decrypted_bytes = cipher.decrypt(encrypted_data)
        
        # Parse JSON
        decrypted_json = json.loads(decrypted_bytes.decode('utf-8'))
        
        return decrypted_json
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def decrypt_file(input_path, output_path=None, password=ODIN_PASSWORD):
    """Decrypt single ODJ file
    
    Args:
        input_path: Path to .odj file
        output_path: Output path (default: same name without .odj)
        password: Decryption password
        
    Returns:
        True if successful, False otherwise
    """
    input_file = Path(input_path)
    
    if not input_file.exists():
        print(f"ERROR: File not found: {input_file}")
        return False
    
    # Read encrypted data
    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
    except Exception as e:
        print(f"ERROR reading {input_file}: {e}")
        return False
    
    # Decrypt
    try:
        decrypted = decrypt_odj(encrypted_data, password)
    except Exception as e:
        print(f"ERROR decrypting {input_file}: {e}")
        return False
    
    # Determine output path
    if output_path is None:
        if input_file.suffix == '.odj':
            output_file = input_file.with_suffix('.json')
        else:
            output_file = input_file.parent / f"{input_file.name}.decrypted.json"
    else:
        output_file = Path(output_path)
    
    # Write decrypted JSON
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(decrypted, f, indent=2)
        
        print(f"✓ Decrypted: {input_file.name} → {output_file.name}")
        return True
        
    except Exception as e:
        print(f"ERROR writing {output_file}: {e}")
        return False

def decrypt_directory(input_dir, output_dir=None, recursive=False, password=ODIN_PASSWORD):
    """Decrypt all ODJ files in directory
    
    Args:
        input_dir: Directory containing .odj files
        output_dir: Output directory (default: same as input)
        recursive: Search subdirectories
        password: Decryption password
        
    Returns:
        Tuple of (success_count, failure_count)
    """
    input_path = Path(input_dir)
    
    if not input_path.is_dir():
        print(f"ERROR: Not a directory: {input_path}")
        return (0, 0)
    
    # Find ODJ files
    if recursive:
        odj_files = list(input_path.rglob("*.odj"))
    else:
        odj_files = list(input_path.glob("*.odj"))
    
    if not odj_files:
        print(f"No .odj files found in {input_path}")
        return (0, 0)
    
    print(f"Found {len(odj_files)} ODJ files")
    
    success_count = 0
    failure_count = 0
    
    for odj_file in odj_files:
        # Determine output path
        if output_dir:
            rel_path = odj_file.relative_to(input_path)
            output_file = Path(output_dir) / rel_path.with_suffix('.json')
        else:
            output_file = odj_file.with_suffix('.json')
        
        if decrypt_file(odj_file, output_file, password):
            success_count += 1
        else:
            failure_count += 1
    
    return (success_count, failure_count)

def analyze_odj(decrypted_data, file_name=""):
    """Analyze decrypted ODJ and print summary
    
    Args:
        decrypted_data: Decrypted ODJ dict
        file_name: Original file name for display
    """
    print(f"\n{'=' * 80}")
    print(f"ODJ ANALYSIS: {file_name}")
    print(f"{'=' * 80}")
    
    # Check for routines
    if 'routines' in decrypted_data:
        routines = decrypted_data['routines']
        print(f"\nRoutines: {len(routines)}")
        
        for routine in routines[:5]:  # First 5
            routine_id = routine.get('routine_id', 'N/A')
            name = routine.get('name', 'N/A')
            security = routine.get('security_level', 'N/A')
            print(f"  - {name} (ID: 0x{routine_id:04X}, Security: {security})")
        
        if len(routines) > 5:
            print(f"  ... and {len(routines) - 5} more")
    
    # Check for DIDs (Data Identifiers)
    if 'dids' in decrypted_data:
        dids = decrypted_data['dids']
        print(f"\nData Identifiers: {len(dids)}")
        
        for did in list(dids.items())[:5]:
            print(f"  - 0x{did[0]:04X}: {did[1].get('name', 'N/A')}")
    
    # Check for security algorithms
    if 'security' in decrypted_data:
        security = decrypted_data['security']
        print(f"\nSecurity Config:")
        print(f"  Algorithm: {security.get('algorithm', 'N/A')}")
        print(f"  Buffer Size: {security.get('buffer_size', 'N/A')}")

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Tesla Odin ODJ files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt single file
  python3 decrypt_odj.py /opt/odin/data/Model3/odj/RCM_VIN_LEARN.odj
  
  # Decrypt all ODJ files in directory
  python3 decrypt_odj.py /opt/odin/data/Model3/odj/ --recursive
  
  # Specify output directory
  python3 decrypt_odj.py file.odj --output ./decrypted/
  
  # Use custom password
  python3 decrypt_odj.py file.odj --password "custom_password"

Note:
  Default password is Odin's hardcoded password extracted from firmware.
        """)
    
    parser.add_argument('input',
                       help='Input .odj file or directory')
    parser.add_argument('--output', '-o',
                       help='Output file or directory')
    parser.add_argument('--recursive', '-r',
                       action='store_true',
                       help='Recursively process directories')
    parser.add_argument('--password', '-p',
                       default=ODIN_PASSWORD,
                       help='Decryption password (default: Odin hardcoded)')
    parser.add_argument('--analyze', '-a',
                       action='store_true',
                       help='Print analysis of decrypted content')
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    
    if input_path.is_file():
        # Decrypt single file
        if decrypt_file(input_path, args.output, args.password):
            if args.analyze:
                output_file = Path(args.output) if args.output else input_path.with_suffix('.json')
                with open(output_file, 'r') as f:
                    analyze_odj(json.load(f), input_path.name)
            sys.exit(0)
        else:
            sys.exit(1)
    
    elif input_path.is_dir():
        # Decrypt directory
        success, failure = decrypt_directory(input_path, args.output, args.recursive, args.password)
        
        print(f"\n{'=' * 80}")
        print(f"SUMMARY")
        print(f"{'=' * 80}")
        print(f"Success: {success}")
        print(f"Failure: {failure}")
        print(f"Total:   {success + failure}")
        
        sys.exit(0 if failure == 0 else 1)
    
    else:
        print(f"ERROR: Input not found: {input_path}")
        sys.exit(1)

if __name__ == "__main__":
    main()
