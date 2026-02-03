# Set Entry Point for Tesla Gateway Firmware
# @category Tesla

# Entry point from boot vector at 0x10-0x13: 00 F9 00 6C
ENTRY_POINT = 0x00F9006C

program = currentProgram
addr_factory = program.getAddressFactory()

try:
    entry_addr = addr_factory.getAddress(hex(ENTRY_POINT))
    print("Setting entry point: " + str(entry_addr))
    
    # Add entry point to program
    symbol_table = program.getSymbolTable()
    
    # Remove any existing entry points
    symbol_table.removeSymbolSpecial(symbol_table.getExternalEntryPointIterator().next())
    
    # Add new entry point
    symbol_table.addExternalEntryPoint(entry_addr)
    symbol_table.createLabel(entry_addr, "ENTRY", ghidra.program.model.symbol.SourceType.USER_DEFINED)
    
    print("Entry point set successfully")
    print("Ghidra will now auto-analyze from this address")
    
except Exception as e:
    print("Error: " + str(e))
    import traceback
    traceback.print_exc()
