# Search for UDP port 3500 handler and socket bind patterns
# @category: Analysis

from ghidra.program.model.address import AddressSet
from array import array

def main():
    print("=" * 60)
    print("Searching for UDP Port 3500 Handler")
    print("=" * 60)
    
    currentProgram = getCurrentProgram()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    
    # Port 3500 = 0x0DAC in hex (big-endian)
    # We'll search for this value in various byte orders
    port_be = [0x0D, 0xAC]  # Big-endian (network order)
    port_le = [0xAC, 0x0D]  # Little-endian
    
    print("\nSearching for port 3500 (0x0DAC)...")
    print("  Big-endian: 0x0D 0xAC")
    print("  Little-endian: 0xAC 0x0D")
    print("")
    
    # Convert to jarray for Ghidra's findBytes
    from jarray import array as jarray
    
    # Search for big-endian
    print("Searching for big-endian 0x0D 0xAC...")
    # Convert to signed bytes for jarray
    def to_signed_byte(b):
        return b if b < 128 else b - 256
    search_bytes = jarray([to_signed_byte(0x0D), to_signed_byte(0xAC)], 'b')
    found_addresses = []
    
    address = memory.getMinAddress()
    while address is not None:
        found_addr = memory.findBytes(address, search_bytes, None, True, getMonitor())
        if found_addr is None:
            break
        found_addresses.append(found_addr)
        print("  Found at: {}".format(found_addr))
        address = found_addr.add(1)
        
        # Limit results
        if len(found_addresses) >= 50:
            print("  ... (limiting to 50 results)")
            break
    
    print("\n  Total matches (big-endian): {}".format(len(found_addresses)))
    
    # Search for little-endian
    print("\nSearching for little-endian 0xAC 0x0D...")
    search_bytes_le = jarray([to_signed_byte(0xAC), to_signed_byte(0x0D)], 'b')
    found_addresses_le = []
    
    address = memory.getMinAddress()
    while address is not None:
        found_addr = memory.findBytes(address, search_bytes_le, None, True, getMonitor())
        if found_addr is None:
            break
        found_addresses_le.append(found_addr)
        print("  Found at: {}".format(found_addr))
        address = found_addr.add(1)
        
        # Limit results
        if len(found_addresses_le) >= 50:
            print("  ... (limiting to 50 results)")
            break
    
    print("\n  Total matches (little-endian): {}".format(len(found_addresses_le)))
    
    # Search for "soc_udpcmds_task" string
    print("\nSearching for 'soc_udpcmds_task' string...")
    task_name = "soc_udpcmds_task"
    task_bytes = jarray([ord(c) for c in task_name], 'b')
    
    address = memory.getMinAddress()
    string_matches = []
    while address is not None:
        found_addr = memory.findBytes(address, task_bytes, None, True, getMonitor())
        if found_addr is None:
            break
        string_matches.append(found_addr)
        print("  Found 'soc_udpcmds_task' at: {}".format(found_addr))
        
        # Show context
        refs = getReferencesTo(found_addr)
        if refs:
            print("    References:")
            for ref in refs:
                print("      From: {}".format(ref.getFromAddress()))
        
        address = found_addr.add(1)
        
        # Limit results
        if len(string_matches) >= 10:
            print("  ... (limiting to 10 results)")
            break
    
    print("\n  Total matches (string): {}".format(len(string_matches)))
    
    # Analyze found addresses for socket bind patterns
    print("\n" + "=" * 60)
    print("Analyzing found addresses for socket bind patterns...")
    print("=" * 60)
    
    for addr in found_addresses[:10]:  # Analyze first 10
        print("\nContext around {}:".format(addr))
        
        # Show instructions before and after
        context_addr = addr.subtract(20)
        for i in range(10):
            instr = listing.getInstructionAt(context_addr)
            if instr:
                print("  {}: {}".format(context_addr, instr))
            context_addr = context_addr.add(4)  # VLE instructions can be 2 or 4 bytes
    
    print("\n" + "=" * 60)
    print("Search Complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
