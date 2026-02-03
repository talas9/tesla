# Inspect memory layout and try manual VLE disassembly
#@category Tesla

from ghidra.program.model.address import Address
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType

print("Memory Layout Inspection")
print("=" * 60)

memory = currentProgram.getMemory()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

# Show memory blocks
print("\nMemory Blocks:")
for block in memory.getBlocks():
    print("  %s: %s - %s (size: %d bytes, initialized: %s)" % (
        block.getName(),
        block.getStart(),
        block.getEnd(),
        block.getSize(),
        block.isInitialized()
    ))

# Check what's at key addresses
print("\nChecking key addresses:")
checkAddrs = [
    (0x00F00000, "Base address"),
    (0x00F00010, "Reset vector location in table"),
    (0x00F9006C, "Reset vector target"),
    (0x00F90000, "Start of reset region"),
]

for addrVal, desc in checkAddrs:
    addr = defaultSpace.getAddress(addrVal)
    if memory.contains(addr):
        bytes = []
        for i in range(16):
            try:
                b = memory.getByte(addr.add(i))
                bytes.append("%02x" % (b & 0xFF))
            except:
                bytes.append("??")
        print("  0x%08X (%s): %s" % (addrVal, desc, " ".join(bytes)))
        
        # Check if there's code here
        cu = currentProgram.getListing().getCodeUnitAt(addr)
        if cu:
            cuType = cu.getClass().getSimpleName()
            print("              -> %s: %s" % (cuType, cu))
    else:
        print("  0x%08X (%s): NOT IN MEMORY!" % (addrVal, desc))

# Try to force disassembly at many addresses
print("\nAttempting aggressive disassembly...")
listing = currentProgram.getListing()

# Strategy: Try disassembling every 0x1000 bytes
tryCount = 0
successCount = 0
for offset in range(0, 0x600000, 0x1000):  # Try every 4KB
    addr = defaultSpace.getAddress(0x00F00000 + offset)
    if memory.contains(addr) and not monitor.isCancelled():
        # Only try if not already code
        cu = listing.getCodeUnitAt(addr)
        if cu and cu.getClass().getSimpleName() != "DataDB":
            continue  # Already has code
            
        cmd = DisassembleCommand(addr, None, True)
        if cmd.applyTo(currentProgram, monitor):
            tryCount += 1
            successCount += 1
            if successCount <= 10:
                print("  Disassembled at: %s" % addr)
        else:
            tryCount += 1
    
    if tryCount % 100 == 0 and tryCount > 0:
        print("  Tried %d addresses, %d successful..." % (tryCount, successCount))

# Count final results
instIter = listing.getInstructions(True)
instCount = 0
while instIter.hasNext():
    instIter.next()
    instCount += 1

print("\n" + "=" * 60)
print("Results:")
print("  Disassembly attempts: %d" % tryCount)
print("  Successful: %d" % successCount)
print("  Total instructions: %d" % instCount)
print("=" * 60)
