# Export instructions-only disassembly from Ghidra
# @category: Analysis

from ghidra.program.model.address import AddressSet

def main():
    print("=" * 60)
    print("Exporting Instructions-Only Disassembly")
    print("=" * 60)
    
    currentProgram = getCurrentProgram()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    
    # Output file
    output_file = "/root/tesla/data/disassembly/ghidra-vle-instructions.asm"
    
    print("Program: {}".format(currentProgram.getName()))
    print("Output: {}".format(output_file))
    print("")
    
    # Get all instructions (not DATA blocks)
    instruction_count = 0
    
    # Create output directory if needed
    import os
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(output_file, 'w') as f:
        f.write("; Tesla Gateway VLE Disassembly\n")
        f.write("; Exported from Ghidra\n")
        f.write("; Instructions only (no DATA blocks)\n")
        f.write("; Format: address | bytes | mnemonic operands\n")
        f.write(";\n\n")
        
        # Iterate through all instructions in all memory blocks
        for block in memory.getBlocks():
            instruction = listing.getInstructionAt(block.getStart())
            if instruction is None:
                instruction = listing.getInstructionAfter(block.getStart())
            
            while instruction is not None and block.contains(instruction.getAddress()):
                instruction_count += 1
                
                # Get instruction details
                address = instruction.getAddress()
                mnemonic = instruction.getMnemonicString()
                
                # Build operands string
                num_operands = instruction.getNumOperands()
                operands_list = []
                for op_idx in range(num_operands):
                    operands_list.append(str(instruction.getDefaultOperandRepresentation(op_idx)))
                operands = ",".join(operands_list)
                
                # Get bytes
                byte_count = instruction.getLength()
                bytes_str = ""
                for i in range(byte_count):
                    byte_val = memory.getByte(address.add(i)) & 0xFF
                    bytes_str += "{:02x} ".format(byte_val)
                bytes_str = bytes_str.strip()
                
                # Format: address | bytes | mnemonic operands
                line = "{} | {:20s} | {} {}\n".format(
                    address.toString(),
                    bytes_str,
                    mnemonic,
                    operands if operands else ""
                )
                f.write(line)
                
                # Progress indicator
                if instruction_count % 1000 == 0:
                    print("  Exported {} instructions...".format(instruction_count))
                
                # Get next instruction
                instruction = listing.getInstructionAfter(address)
    
    print("")
    print("=" * 60)
    print("Export Complete!")
    print("  Instructions: {}".format(instruction_count))
    print("  Output: {}".format(output_file))
    print("=" * 60)

if __name__ == '__main__':
    main()
