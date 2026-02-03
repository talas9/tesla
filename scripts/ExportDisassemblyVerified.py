# Export full disassembly and verify instructions were created
#@category Tesla
#@author OpenClaw

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet
from java.io import FileWriter, PrintWriter
from java.util import Date

outputPath = "/root/tesla/data/disassembly/ghidra-vle-working.asm"

print("Starting disassembly export...")
print("Output file: " + outputPath)

listing = currentProgram.getListing()
memory = currentProgram.getMemory()

# Count statistics
instructionCount = 0
dataCount = 0

# First pass: count types
instIter = listing.getInstructions(True)
while instIter.hasNext() and not monitor.isCancelled():
    instIter.next()
    instructionCount += 1

dataIter = listing.getDefinedData(True)
while dataIter.hasNext() and not monitor.isCancelled():
    dataIter.next()
    dataCount += 1

print("========================================")
print("VERIFICATION RESULTS:")
print("  Instructions:  " + str(instructionCount))
print("  Defined Data:  " + str(dataCount))
print("  Memory size:   " + str(memory.getSize()) + " bytes")
print("========================================")

if instructionCount == 0:
    print("ERROR: No instructions were created! Analysis failed.")
    exit(1)

print("\nExporting full disassembly...")

# Export disassembly
writer = PrintWriter(FileWriter(outputPath))

writer.println(";; Tesla Gateway Firmware Disassembly")
writer.println(";; Base Address: 0x00F00000")
writer.println(";; Entry Point: 0x00F9006C (from reset vector)")
writer.println(";; Language: PowerPC VLE (VLEALT-32addr)")
writer.println(";; Binary: ryzenfromtable.bin")
writer.println(";; Analysis Date: " + str(Date()))
writer.println(";;")
writer.println(";; Statistics:")
writer.println(";;   Instructions:  " + str(instructionCount))
writer.println(";;   Defined Data:  " + str(dataCount))
writer.println(";;   Memory size:   " + str(memory.getSize()) + " bytes")
writer.println(";;")
writer.println("================================================\n")

# Export all code units
codeUnits = listing.getCodeUnits(True)
exportedCount = 0

while codeUnits.hasNext() and not monitor.isCancelled():
    cu = codeUnits.next()
    addr = cu.getAddress()
    
    # Get any label at this address
    label = ""
    symbols = currentProgram.getSymbolTable().getSymbols(addr)
    for sym in symbols:
        if sym.isPrimary():
            label = sym.getName() + ":"
            break
    
    if label:
        writer.println("\n" + label)
    
    cuType = cu.getClass().getSimpleName()
    
    if cuType == "InstructionDB" or cuType == "Instruction":
        inst = cu
        writer.println("%-12s  %-40s" % (
            addr.toString(), 
            inst.toString()))
        exportedCount += 1
    else:
        data = cu
        writer.println("%-12s  %-40s  ; DATA" % (
            addr.toString(), 
            data.toString()))
    
    if exportedCount % 10000 == 0 and exportedCount > 0:
        print("Exported " + str(exportedCount) + " instructions...")

writer.close()

print("\n========================================")
print("Export complete!")
print("Total code units exported: " + str(exportedCount))
print("Output: " + outputPath)
print("========================================")
