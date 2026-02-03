#!/usr/bin/env python3
"""
Tesla Gateway Config CRC-8 Validator
VERIFIED with Mohammed Talas parameters:
  - width=8
  - polynomial=0x2f
  - init_value=0xff
  - final_xor_value=0x0

Format: [CRC:1][Length:1][Config_ID:2_BE][Data:N]
CRC calculated over: [Length][Config_ID][Data]
"""

import sys
import struct


def crc8_0x2f(data, init=0xFF, xor_out=0x00):
    """
    Calculate CRC-8 with polynomial 0x2F
    
    This is the exact algorithm used by Tesla Gateway
    for config entry validation.
    
    Args:
        data: bytes to calculate CRC over
        init: initial CRC value (0xFF)
        xor_out: final XOR value (0x00)
    
    Returns:
        CRC-8 value (0x00-0xFF)
    """
    crc = init
    
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x2F
            else:
                crc = crc << 1
            crc &= 0xFF
    
    return crc ^ xor_out


def calculate_config_crc(config_id, data):
    """
    Calculate CRC for Gateway config entry
    
    Args:
        config_id: Config ID (0x0000-0xFFFF, 2 bytes)
        data: Config data bytes
    
    Returns:
        CRC-8 value
    """
    length = len(data)
    if length > 255:
        raise ValueError(f"Data too long: {length} bytes (max 255)")
    
    # CRC = crc8_0x2f([Length:1] + [Config_ID:2_BE] + [Data:N])
    crc_data = bytes([length]) + struct.pack('>H', config_id) + data
    return crc8_0x2f(crc_data)


def build_config_entry(config_id, data):
    """
    Build complete config entry with CRC
    
    Args:
        config_id: Config ID (0x0000-0xFFFF)
        data: Config data bytes
    
    Returns:
        Complete entry: [CRC:1][Length:1][ID:2][Data:N]
    """
    crc = calculate_config_crc(config_id, data)
    length = len(data)
    return bytes([crc, length]) + struct.pack('>H', config_id) + data


def verify_config_entry(entry):
    """
    Verify config entry CRC
    
    Args:
        entry: Complete entry bytes [CRC:1][Len:1][ID:2][Data:N]
    
    Returns:
        (config_id, data, stored_crc, calculated_crc, is_valid)
    """
    if len(entry) < 4:
        raise ValueError("Entry too short (minimum 4 bytes)")
    
    stored_crc = entry[0]
    length = entry[1]
    config_id = struct.unpack('>H', entry[2:4])[0]
    
    if len(entry) < 4 + length:
        raise ValueError(f"Entry incomplete: need {4+length} bytes, got {len(entry)}")
    
    data = entry[4:4+length]
    
    # Calculate expected CRC
    calculated_crc = calculate_config_crc(config_id, data)
    is_valid = (stored_crc == calculated_crc)
    
    return config_id, data, stored_crc, calculated_crc, is_valid


def parse_config_flash(flash_data, verbose=False):
    """
    Parse config region from Gateway flash dump
    
    Config entry format:
        [CRC:1][Len:1][ID:2_BE][Data:N]
    
    Args:
        flash_data: Raw flash bytes
        verbose: Print debug info
    
    Returns:
        dict of {config_id: entry_info}
    """
    offset = 0
    configs = {}
    
    while offset < len(flash_data) - 4:
        # Check for erased flash (0xFF)
        if flash_data[offset] == 0xFF:
            offset += 1
            continue
        
        try:
            # Read entry
            stored_crc = flash_data[offset]
            length = flash_data[offset + 1]
            
            # Validate length
            if length == 0 or length > 250:
                if verbose:
                    print(f"Invalid length {length} at offset {offset:#x}, skipping")
                offset += 1
                continue
            
            # Check we have enough data
            if offset + 4 + length > len(flash_data):
                break
            
            # Extract entry
            entry = flash_data[offset:offset+4+length]
            config_id, data, _, calc_crc, valid = verify_config_entry(entry)
            
            configs[config_id] = {
                'offset': offset,
                'length': length,
                'data': data,
                'stored_crc': stored_crc,
                'calculated_crc': calc_crc,
                'valid': valid,
                'entry': entry
            }
            
            if verbose:
                # Try to decode as ASCII
                try:
                    data_str = data.decode('ascii')
                    if all(32 <= ord(c) < 127 for c in data_str):
                        data_repr = f"'{data_str}'"
                    else:
                        data_repr = data.hex().upper()
                except:
                    data_repr = data.hex().upper()
                
                print(f"Config 0x{config_id:04X} at 0x{offset:06X}: "
                      f"len={length:2d}, CRC={'✓' if valid else '✗'} "
                      f"(0x{stored_crc:02X}/0x{calc_crc:02X}), "
                      f"data={data_repr}")
            
            # Move to next entry
            offset += 4 + length
            
        except Exception as e:
            if verbose:
                print(f"Error at offset {offset:#x}: {e}")
            offset += 1
    
    return configs


def test_known_configs():
    """Test with known config values"""
    print("=== Testing Known Configs ===\n")
    
    # Example from Mohammed
    print("Example from Mohammed:")
    print("Hex: E10C0001313737363030302D30322D43")
    config_id = 0x0001
    data = b"1776000-02-C"
    expected_crc = 0xE1
    
    calc_crc = calculate_config_crc(config_id, data)
    entry = build_config_entry(config_id, data)
    
    print(f"  Config ID: 0x{config_id:04X}")
    print(f"  Data: '{data.decode('ascii')}'")
    print(f"  Expected CRC: 0x{expected_crc:02X}")
    print(f"  Calculated:   0x{calc_crc:02X}")
    print(f"  Result: {'✓ PASS' if calc_crc == expected_crc else '✗ FAIL'}")
    print(f"  Full entry: {entry.hex().upper()}")
    print()
    
    # Verify parsing
    print("Parsing entry:")
    parsed_id, parsed_data, stored, calculated, valid = verify_config_entry(entry)
    print(f"  Parsed ID: 0x{parsed_id:04X}")
    print(f"  Parsed data: '{parsed_data.decode('ascii')}'")
    print(f"  CRC valid: {valid}")
    print()


def main():
    if len(sys.argv) < 2:
        print("Tesla Gateway Config CRC-8 Validator")
        print("=" * 60)
        print("\nFormat: [CRC:1][Length:1][Config_ID:2_BE][Data:N]")
        print("CRC calculated over: [Length][Config_ID][Data]")
        print("\nUsage:")
        print("  ./gateway_crc_validator.py test")
        print("    Run tests with known configs")
        print()
        print("  ./gateway_crc_validator.py build <config_id_hex> <data>")
        print("    Build config entry with CRC")
        print()
        print("  ./gateway_crc_validator.py verify <hex_entry>")
        print("    Verify config entry CRC")
        print()
        print("  ./gateway_crc_validator.py parse <flash_dump.bin>")
        print("    Parse config region from flash dump")
        print()
        print("Examples:")
        print("  ./gateway_crc_validator.py test")
        print("  ./gateway_crc_validator.py build 0x0001 '1776000-02-C'")
        print("  ./gateway_crc_validator.py verify E10C0001313737363030302D30322D43")
        print("  ./gateway_crc_validator.py parse config.bin")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "test":
        test_known_configs()
    
    elif command == "build":
        if len(sys.argv) < 4:
            print("Error: Missing arguments")
            print("Usage: ./gateway_crc_validator.py build <config_id_hex> <data>")
            sys.exit(1)
        
        try:
            config_id = int(sys.argv[2], 0)  # Accepts 0x prefix
            data = sys.argv[3].encode('ascii')
            
            entry = build_config_entry(config_id, data)
            crc = entry[0]
            
            print(f"Config ID: 0x{config_id:04X}")
            print(f"Data: '{data.decode('ascii')}'")
            print(f"CRC: 0x{crc:02X}")
            print(f"Full entry: {entry.hex().upper()}")
            
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif command == "verify":
        if len(sys.argv) < 3:
            print("Error: Missing hex entry")
            sys.exit(1)
        
        try:
            entry = bytes.fromhex(sys.argv[2])
            config_id, data, stored_crc, calc_crc, valid = verify_config_entry(entry)
            
            # Try to decode as ASCII
            try:
                data_str = data.decode('ascii')
                if all(32 <= ord(c) < 127 for c in data_str):
                    data_repr = f"'{data_str}'"
                else:
                    data_repr = data.hex().upper()
            except:
                data_repr = data.hex().upper()
            
            print(f"Config ID: 0x{config_id:04X}")
            print(f"Data: {data_repr}")
            print(f"Stored CRC:     0x{stored_crc:02X}")
            print(f"Calculated CRC: 0x{calc_crc:02X}")
            print(f"Result: {'✓ VALID' if valid else '✗ INVALID'}")
            
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif command == "parse":
        if len(sys.argv) < 3:
            print("Error: Missing flash dump file")
            sys.exit(1)
        
        flash_file = sys.argv[2]
        
        try:
            with open(flash_file, 'rb') as f:
                flash_data = f.read()
            
            print(f"Parsing flash dump: {flash_file} ({len(flash_data)} bytes)")
            print()
            
            configs = parse_config_flash(flash_data, verbose=True)
            
            print(f"\n{'='*60}")
            print(f"Total configs found: {len(configs)}")
            valid_count = sum(1 for c in configs.values() if c['valid'])
            print(f"Valid CRCs: {valid_count}/{len(configs)}")
            
            # Show configs with invalid CRCs
            invalid = [f"0x{cid:04X}" for cid, c in configs.items() if not c['valid']]
            if invalid:
                print(f"\nConfigs with invalid CRCs: {', '.join(invalid)}")
        
        except FileNotFoundError:
            print(f"Error: File not found: {flash_file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
