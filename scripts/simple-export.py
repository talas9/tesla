# Simple VLE export - just dump what was disassembled
# @category Tesla

from java.io import File

program = currentProgram
listing = program.getListing()

output_file = File("/root/tesla/data/disassembly/ghidra-vle-simple.txt")

print("Tesla Gateway VLE Simple Export")
print("Counting instructions...")

# Count what we have
instruction_count = 0
instructions = listing.getInstructions(True)
while instructions.hasNext():
    instructions.next()
    instruction_count += 1

print("Found %d instructions" % instruction_count)

# If we have instructions, export them
if instruction_count > 0:
    print("Exporting...")
    with open(output_file.getAbsolutePath(), 'w') as f:
        f.write("# Tesla Gateway VLE Disassembly\n")
        f.write("# Total instructions: %d\n\n" % instruction_count)
        
        instructions = listing.getInstructions(True)
        count = 0
        while instructions.hasNext():
            instr = instructions.next()
            addr = instr.getAddress()
            
            # Simple format
            f.write("%s: %s\n" % (addr, instr))
            
            count += 1
            if count % 10000 == 0:
                print("Exported %d/%d..." % (count, instruction_count))
    
    print("Complete! Saved to: " + output_file.getAbsolutePath())
else:
    print("WARNING: No instructions found! Ghidra did not disassemble anything.")
    print("This means:")
    print("  - No entry point was set")
    print("  - Or the architecture is wrong")
    print("  - Or the binary is encrypted/compressed")
    
    # Write diagnostic info
    with open(output_file.getAbsolutePath(), 'w') as f:
        f.write("ERROR: No instructions disassembled\n")
        f.write("Architecture: %s\n" % program.getLanguage())
        f.write("Binary size: %d bytes\n" % program.getMemory().getSize())
