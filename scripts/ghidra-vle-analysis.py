# Tesla Gateway VLE Analysis with Entry Point
# @category Tesla

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit
from java.io import File

# Get current program
program = currentProgram
listing = program.getListing()
memory = program.getMemory()
addr_factory = program.getAddressFactory()

print("Tesla Gateway PowerPC VLE Analysis")
print("Binary: " + program.getName())
print("Architecture: " + program.getLanguage().getProcessor().toString())

# Define entry point from boot vector analysis
# Boot vector at 0x10-0x13 contains: 00 F9 00 6C
ENTRY_POINT = 0x00F9006C

try:
    entry_addr = addr_factory.getAddress(hex(ENTRY_POINT))
    print("Setting entry point: " + str(entry_addr))
    
    # Add entry point symbol
    symbol_table = program.getSymbolTable()
    symbol_table.createLabel(entry_addr, "entry_point", ghidra.program.model.symbol.SourceType.USER_DEFINED)
    
    # Disassemble from entry point
    print("Disassembling from entry point...")
    disassembler = ghidra.program.model.util.Disassembler.getDisassembler(
        program, monitor, ghidra.program.util.GhidraMessageLogImpl()
    )
    
    # Disassemble forward from entry
    disassembled = disassembler.disassemble(entry_addr, None)
    print("Disassembled address range: " + str(disassembled))
    
    # Create function at entry point
    function_manager = program.getFunctionManager()
    function_manager.createFunction("main_entry", entry_addr, disassembled, ghidra.program.model.symbol.SourceType.USER_DEFINED)
    print("Created function at entry point")
    
except Exception as e:
    print("Error setting entry point: " + str(e))
    import traceback
    traceback.print_exc()

# Now export disassembly
output_file = File("/root/tesla/data/disassembly/ghidra-vle-full.asm")

print("\nExporting disassembly...")

with open(output_file.getAbsolutePath(), 'w') as f:
    f.write("# Tesla Gateway PowerPC VLE Disassembly\n")
    f.write("# Binary: ryzenfromtable.bin (6MB MPC5748G firmware)\n")
    f.write("# Processor: PowerPC VLE 32-bit\n")
    f.write("# Entry Point: 0x%08x\n" % ENTRY_POINT)
    f.write("# Analyzed with Ghidra\n\n")
    
    # Get all memory
    address_set = memory.getAllInitializedAddressSet()
    
    # Iterate through all code units
    codeUnits = listing.getCodeUnits(address_set, True)
    count = 0
    instr_count = 0
    last_was_data = False
    
    while codeUnits.hasNext():
        cu = codeUnits.next()
        addr = cu.getAddress()
        
        # Get bytes
        bytes_str = ""
        for b in cu.getBytes():
            bytes_str += "%02x " % (b & 0xFF)
        
        # Check if it's an instruction
        is_instruction = cu.getClass().getName().endswith("Instruction")
        
        if is_instruction:
            # It's an instruction
            mnemonic = cu.getMnemonicString()
            operands = ""
            for i in range(cu.getNumOperands()):
                if i > 0:
                    operands += ", "
                operands += str(cu.getDefaultOperandRepresentation(i))
            
            # Add section separator if transitioning from data
            if last_was_data:
                f.write("\n# === CODE SECTION ===\n")
                last_was_data = False
            
            line = "0x%08x: %-20s %-10s %s" % (
                addr.getOffset(),
                bytes_str.strip(),
                mnemonic,
                operands
            )
            instr_count += 1
        else:
            # It's data - skip in disassembly export to reduce file size
            # Only export if it's near code or interesting
            if not last_was_data:
                f.write("\n# === DATA SECTION at 0x%08x ===\n" % addr.getOffset())
                last_was_data = True
            
            # Skip individual data bytes in output (would be huge)
            count += 1
            if count % 100000 == 0:
                print("Processed %d units (%d instructions)..." % (count, instr_count))
            continue
        
        # Add function label if exists
        func = listing.getFunctionAt(addr)
        if func:
            f.write("\n# FUNCTION: %s\n" % func.getName())
        
        # Add comment if exists
        comment = cu.getComment(CodeUnit.EOL_COMMENT)
        if comment:
            line += "    ; " + comment
        
        f.write(line + "\n")
        
        count += 1
        if count % 50000 == 0:
            print("Exported %d units (%d instructions)..." % (count, instr_count))
    
    print("\nExport complete:")
    print("  Total units: %d" % count)
    print("  Instructions: %d" % instr_count)

print("Output saved to: " + output_file.getAbsolutePath())
