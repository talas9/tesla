# Analyze UDP port 3500 handler context with instructions
# @category: Analysis

from ghidra.program.model.address import Address

def analyze_context(listing, memory, addr, label, context_size=50):
    """Analyze context around an address"""
    print("\n" + "=" * 60)
    print("Analysis: {} at {}".format(label, addr))
    print("=" * 60)
    
    # Show bytes at the address
    print("\nBytes at address:")
    bytes_str = ""
    for i in range(16):
        try:
            byte_val = memory.getByte(addr.add(i)) & 0xFF
            bytes_str += "{:02x} ".format(byte_val)
        except:
            break
    print("  {}".format(bytes_str))
    
    # Show instructions before and after
    print("\nInstructions (context):")
    
    # Start from 40 bytes before
    start_addr = addr.subtract(40)
    instruction = listing.getInstructionContaining(start_addr)
    if instruction is None:
        instruction = listing.getInstructionAfter(start_addr)
    
    # Show up to context_size instructions
    count = 0
    while instruction is not None and count < context_size:
        instr_addr = instruction.getAddress()
        mnemonic = instruction.getMnemonicString()
        
        # Build operands string
        num_operands = instruction.getNumOperands()
        operands_list = []
        for op_idx in range(num_operands):
            operands_list.append(str(instruction.getDefaultOperandRepresentation(op_idx)))
        operands = ",".join(operands_list)
        
        # Highlight the target address
        marker = " <<< TARGET" if instr_addr == addr else ""
        
        print("  {}: {:<10} {}{}".format(
            instr_addr,
            mnemonic,
            operands,
            marker
        ))
        
        instruction = listing.getInstructionAfter(instr_addr)
        count += 1
    
    # Show references TO this address
    print("\nReferences TO {}:".format(addr))
    refs_to = getReferencesTo(addr)
    if refs_to:
        for ref in refs_to[:20]:  # Limit to 20
            from_addr = ref.getFromAddress()
            ref_type = ref.getReferenceType()
            print("  {} [{}]".format(from_addr, ref_type))
            
            # Show the instruction that references this
            ref_instr = listing.getInstructionAt(from_addr)
            if ref_instr:
                print("    -> {}".format(ref_instr))
    else:
        print("  (none)")
    
    # Show references FROM this address
    print("\nReferences FROM {}:".format(addr))
    refs_from = getReferencesFrom(addr)
    if refs_from:
        for ref in refs_from[:20]:
            to_addr = ref.getToAddress()
            ref_type = ref.getReferenceType()
            print("  {} [{}]".format(to_addr, ref_type))
    else:
        print("  (none)")

def main():
    print("=" * 60)
    print("UDP Port 3500 Handler Context Analysis")
    print("=" * 60)
    
    currentProgram = getCurrentProgram()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    
    # Addresses found in previous search
    port_be_addresses = [
        "01207ba8",
        "01207c1e",
        "01311261"
    ]
    
    port_le_addresses = [
        "00fe5236",
        "011ab678"
    ]
    
    string_addresses = [
        "012fa3e4",
        "01301b8c"
    ]
    
    # Analyze port references (big-endian)
    print("\n### Big-Endian Port References (0x0D 0xAC) ###")
    for addr_str in port_be_addresses:
        try:
            addr = toAddr(addr_str)
            analyze_context(listing, memory, addr, "Port 3500 (BE)", 30)
        except Exception as e:
            print("Error analyzing {}: {}".format(addr_str, e))
    
    # Analyze port references (little-endian)
    print("\n\n### Little-Endian Port References (0xAC 0x0D) ###")
    for addr_str in port_le_addresses:
        try:
            addr = toAddr(addr_str)
            analyze_context(listing, memory, addr, "Port 3500 (LE)", 30)
        except Exception as e:
            print("Error analyzing {}: {}".format(addr_str, e))
    
    # Analyze string references
    print("\n\n### Task Name String References ('soc_udpcmds_task') ###")
    for addr_str in string_addresses:
        try:
            addr = toAddr(addr_str)
            analyze_context(listing, memory, addr, "soc_udpcmds_task string", 20)
        except Exception as e:
            print("Error analyzing {}: {}".format(addr_str, e))
    
    print("\n" + "=" * 60)
    print("Analysis Complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
