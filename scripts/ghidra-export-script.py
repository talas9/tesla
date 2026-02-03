# Tesla Gateway VLE Disassembly Export (Fixed)
# @category Tesla

from ghidra.program.model.listing import CodeUnit
from java.io import File

# Output file
output_file = File("/root/tesla/data/disassembly/ghidra-vle-full.asm")

# Get current program
program = currentProgram
listing = program.getListing()
memory = program.getMemory()

# Get all instructions
address_set = memory.getAllInitializedAddressSet()

print("Starting VLE disassembly export...")
print("Binary: " + program.getName())
print("Architecture: " + program.getLanguage().getProcessor().toString())
print("Address range: " + str(address_set))

# Write disassembly
with open(output_file.getAbsolutePath(), 'w') as f:
    f.write("# Tesla Gateway PowerPC VLE Disassembly\n")
    f.write("# Binary: ryzenfromtable.bin (6MB MPC5748G firmware)\n")
    f.write("# Processor: PowerPC VLE 32-bit\n")
    f.write("# Analyzed with Ghidra %s\n" % str(program.getCompilerSpec().getCompilerSpecID()))
    f.write("# Address space: %s\n\n" % str(address_set))
    
    # Iterate through all code units (instructions and data)
    codeUnits = listing.getCodeUnits(address_set, True)
    count = 0
    instr_count = 0
    
    while codeUnits.hasNext():
        cu = codeUnits.next()
        addr = cu.getAddress()
        
        # Get bytes
        bytes_str = ""
        for b in cu.getBytes():
            bytes_str += "%02x " % (b & 0xFF)
        
        # Format based on type
        if cu.getClass().getName().endswith("Instruction"):
            # It's an instruction
            mnemonic = cu.getMnemonicString()
            operands = ""
            for i in range(cu.getNumOperands()):
                if i > 0:
                    operands += ", "
                operands += str(cu.getDefaultOperandRepresentation(i))
            
            line = "0x%08x: %-20s %-10s %s" % (
                addr.getOffset(),
                bytes_str.strip(),
                mnemonic,
                operands
            )
            instr_count += 1
        else:
            # It's data
            line = "0x%08x: %-20s [DATA]" % (
                addr.getOffset(),
                bytes_str.strip()
            )
        
        # Add comment if exists
        comment = cu.getComment(CodeUnit.EOL_COMMENT)
        if comment:
            line += "    ; " + comment
        
        f.write(line + "\n")
        
        count += 1
        if count % 50000 == 0:
            print("Exported %d code units (%d instructions)..." % (count, instr_count))
    
    print("Export complete:")
    print("  Total code units: %d" % count)
    print("  Instructions: %d" % instr_count)
    print("  Data units: %d" % (count - instr_count))

print("Output saved to: " + output_file.getAbsolutePath())
