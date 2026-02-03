#!/usr/bin/env python3
"""
Find Gateway SET_CONFIG_DATA validation logic in disassembly
"""

import re
from collections import defaultdict

def analyze_disassembly():
    """Find config validation code in PowerPC disassembly"""
    
    with open('/root/tesla/data/gateway_full_disassembly.txt', 'r') as f:
        lines = f.readlines()
    
    print("="*80)
    print("GATEWAY SET_CONFIG_DATA VALIDATION ANALYSIS")
    print("="*80)
    
    # Strategy 1: Find functions that load from 0x403000 metadata table
    print("\n[1] Searching for metadata table (0x403000) access patterns...")
    metadata_refs = []
    
    for i, line in enumerate(lines):
        # Look for address loads that could point to 0x403000
        # PowerPC pattern: lis r3,0x40  (load immediate shifted)
        if 'lis' in line and ('0x40' in line or '4,' in line):
            # Check following lines for lwz/lbz with offset near 0x3000
            for j in range(1, 15):
                if i+j >= len(lines):
                    break
                next_line = lines[i+j]
                # Look for loads with offset like 0x3000, 0x3004, etc
                if ('lwz' in next_line or 'lbz' in next_line or 'lhz' in next_line):
                    if '0x3' in next_line or '0x4' in next_line:
                        addr = line.split(':')[0].strip()
                        metadata_refs.append((addr, i))
                        print(f"  Found potential metadata access at {addr}")
                        break
    
    print(f"  Total candidates: {len(metadata_refs)}")
    
    # Strategy 2: Find CRC-8 validation function (polynomial 0x2F)
    print("\n[2] Searching for CRC-8 validation (polynomial 0x2F)...")
    crc_functions = []
    
    for i, line in enumerate(lines):
        # Look for loads of 0x2F value
        if ('li ' in line or 'addi' in line) and ',0x2f' in line.lower():
            addr = line.split(':')[0].strip()
            # Check if this is in a loop (look for branch back instructions nearby)
            has_loop = False
            for j in range(max(0, i-20), min(len(lines), i+20)):
                if 'bdnz' in lines[j] or 'bc' in lines[j] or 'blt' in lines[j]:
                    has_loop = True
                    break
            if has_loop:
                crc_functions.append((addr, i))
                print(f"  Found CRC-8 function candidate at {addr}")
    
    print(f"  Total CRC candidates: {len(crc_functions)}")
    
    # Strategy 3: Find config ID range checks
    print("\n[3] Searching for config ID validation (range 0x0000-0x01FF)...")
    range_checks = []
    
    for i, line in enumerate(lines):
        # Look for comparisons with values like 0xFF, 0x1FF, 0x200
        if 'cmpl' in line or 'cmp' in line:
            if any(val in line for val in ['0xff', '0x1ff', '0x200', '255', '511', '512']):
                addr = line.split(':')[0].strip()
                range_checks.append((addr, i))
                if len(range_checks) <= 10:  # Only show first 10
                    print(f"  Found range check at {addr}: {line.strip()}")
    
    print(f"  Total range check candidates: {len(range_checks)}")
    
    # Strategy 4: Find switch/jump tables for command dispatch
    print("\n[4] Searching for command dispatch tables...")
    jump_tables = []
    
    for i, line in enumerate(lines):
        # Look for computed branches (dispatch on opcode)
        if 'lwz' in line and 'r' in line:
            # Check for subsequent branch register instruction
            for j in range(1, 5):
                if i+j >= len(lines):
                    break
                if 'mtctr' in lines[i+j] or 'bctr' in lines[i+j]:
                    addr = line.split(':')[0].strip()
                    jump_tables.append((addr, i))
                    if len(jump_tables) <= 5:
                        print(f"  Found jump table at {addr}")
                    break
    
    print(f"  Total jump table candidates: {len(jump_tables)}")
    
    # Strategy 5: Find security level comparisons
    print("\n[5] Searching for security/access level checks...")
    security_checks = []
    
    for i, line in enumerate(lines):
        # Look for byte comparisons against prefix values: 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x13, 0x15
        if 'cmpl' in line or 'cmp' in line:
            if any(val in line for val in ['0x3,', '0x5,', '0x7,', '0x9,', '0xb,', '0xd,', '0x13,', '0x15,']):
                addr = line.split(':')[0].strip()
                security_checks.append((addr, i))
                if len(security_checks) <= 10:
                    print(f"  Found security check at {addr}: {line.strip()}")
    
    print(f"  Total security check candidates: {len(security_checks)}")
    
    # Now extract code snippets from the most promising candidates
    print("\n" + "="*80)
    print("DETAILED ANALYSIS OF TOP CANDIDATES")
    print("="*80)
    
    # Show metadata table access functions
    if metadata_refs:
        print("\n[METADATA TABLE ACCESS] Top 3 functions:\n")
        for addr, line_num in metadata_refs[:3]:
            print(f"\n--- Function at {addr} ---")
            for k in range(max(0, line_num-5), min(len(lines), line_num+30)):
                print(lines[k].rstrip())
            print()
    
    # Show CRC functions
    if crc_functions:
        print("\n[CRC-8 VALIDATION] Top function:\n")
        addr, line_num = crc_functions[0]
        print(f"\n--- CRC-8 Function at {addr} ---")
        for k in range(max(0, line_num-10), min(len(lines), line_num+40)):
            print(lines[k].rstrip())
        print()
    
    return {
        'metadata_refs': metadata_refs,
        'crc_functions': crc_functions,
        'range_checks': range_checks,
        'jump_tables': jump_tables,
        'security_checks': security_checks
    }

if __name__ == '__main__':
    results = analyze_disassembly()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Metadata table accesses:  {len(results['metadata_refs'])}")
    print(f"CRC-8 functions:          {len(results['crc_functions'])}")
    print(f"Range checks:             {len(results['range_checks'])}")
    print(f"Jump tables:              {len(results['jump_tables'])}")
    print(f"Security checks:          {len(results['security_checks'])}")
