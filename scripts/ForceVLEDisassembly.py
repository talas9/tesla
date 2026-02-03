# Force VLE disassembly starting from reset vector
#@category Tesla
#@author OpenClaw

from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand

print("Force VLE Disassembly Script")
print("============================")

# Define key addresses
RESET_VECTOR_ADDR = 0x00F9006C  # From the reset vector table
BASE_ADDR = 0x00F00000

addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

# Create address object for reset vector
resetAddr = defaultSpace.getAddress(RESET_VECTOR_ADDR)
print("Reset vector address: " + resetAddr.toString())

# Set as entry point
symbolTable = currentProgram.getSymbolTable()
entryPointManager = currentProgram.getSymbolTable()

# Add entry point
currentProgram.getSymbolTable().addExternalEntryPoint(resetAddr)
print("Added entry point at: " + resetAddr.toString())

# Create label
currentProgram.getSymbolTable().createLabel(resetAddr, "RESET_HANDLER", SourceType.USER_DEFINED)
print("Created label: RESET_HANDLER")

# Force disassembly starting from reset vector
print("\nForcing disassembly from reset vector...")
cmd = DisassembleCommand(resetAddr, None, True)
cmd.applyTo(currentProgram, monitor)
print("Disassembly command applied")

# Try to create function at entry point
from ghidra.app.cmd.function import CreateFunctionCmd
funcCmd = CreateFunctionCmd(resetAddr)
funcCmd.applyTo(currentProgram, monitor)
print("Created function at reset vector")

# Disassemble from other common boot code locations
bootAddresses = [
    0x00F00000,  # Base address (might have init code)
    0x00F00100,  # Common boot vector offset
    0x00F90000,  # Start of reset vector region
]

for bootAddr in bootAddresses:
    addr = defaultSpace.getAddress(bootAddr)
    print("\nTrying disassembly from: " + addr.toString())
    cmd = DisassembleCommand(addr, None, True)
    result = cmd.applyTo(currentProgram, monitor)
    if result:
        print("  Success!")
    else:
        print("  Failed or no code found")

# Count results
listing = currentProgram.getListing()
instIter = listing.getInstructions(True)
instructionCount = 0
while instIter.hasNext():
    instIter.next()
    instructionCount += 1

print("\n============================")
print("Disassembly Results:")
print("  Total instructions: " + str(instructionCount))
print("============================")

if instructionCount == 0:
    print("\nWARNING: Still no instructions! VLE disassembly may not be working.")
    print("Possible issues:")
    print("  1. VLE language not properly loaded")
    print("  2. Binary doesn't contain valid VLE code at expected addresses")
    print("  3. Code may be compressed/encrypted")
else:
    print("\nSUCCESS! VLE instructions created.")
