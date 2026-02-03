# Define code sections for Tesla Gateway VLE firmware
# @category Tesla

from ghidra.program.model.address import AddressSet

program = currentProgram
addr_factory = program.getAddressFactory()
disassembler = ghidra.program.model.util.Disassembler.getDisassembler(
    program, monitor, ghidra.program.util.GhidraMessageLogImpl()
)

print("Defining code sections for Tesla Gateway VLE firmware")

# Define code entry points based on hexdump analysis
# Clear VLE instructions start around 0x100
CODE_ENTRY_POINTS = [
    0x000000F0,  # Boot code
    0x00000100,  # Main initialization
]

for addr_val in CODE_ENTRY_POINTS:
    try:
        addr = addr_factory.getAddress(hex(addr_val))
        print("Disassembling from: " + str(addr))
        
        # Disassemble forward
        disassembled = disassembler.disassemble(addr, None, True)
        print("  Disassembled: " + str(disassembled))
        
    except Exception as e:
        print("  Error at %s: %s" % (hex(addr_val), str(e)))

print("Code definition complete")
print("Ghidra will continue auto-analysis from these entry points")
