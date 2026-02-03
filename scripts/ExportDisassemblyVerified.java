// Export full disassembly and verify instructions were created
//@category Tesla
//@author OpenClaw

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDisassemblyVerified extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        String outputPath = "/root/tesla/data/disassembly/ghidra-vle-working.asm";
        
        println("Starting disassembly export...");
        println("Output file: " + outputPath);
        
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        
        // Count statistics
        int instructionCount = 0;
        int dataCount = 0;
        int undefinedCount = 0;
        
        // First pass: count types
        InstructionIterator instIter = listing.getInstructions(true);
        while (instIter.hasNext() && !monitor.isCancelled()) {
            instIter.next();
            instructionCount++;
        }
        
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            dataIter.next();
            dataCount++;
        }
        
        AddressIterator undefinedIter = listing.getUndefinedRanges(memory.getMinAddress(), memory.getMaxAddress(), true);
        while (undefinedIter.hasNext() && !monitor.isCancelled()) {
            Address addr = undefinedIter.next();
            undefinedCount++;
        }
        
        println("========================================");
        println("VERIFICATION RESULTS:");
        println("  Instructions:  " + instructionCount);
        println("  Defined Data:  " + dataCount);
        println("  Undefined:     " + undefinedCount);
        println("========================================");
        
        if (instructionCount == 0) {
            println("ERROR: No instructions were created! Analysis failed.");
            return;
        }
        
        println("\nExporting full disassembly...");
        
        // Export disassembly
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        
        writer.println(";; Tesla Gateway Firmware Disassembly");
        writer.println(";; Base Address: 0x00F00000");
        writer.println(";; Entry Point: 0x00F9006C (from reset vector)");
        writer.println(";; Language: PowerPC VLE (VLEALT-32addr)");
        writer.println(";; Binary: ryzenfromtable.bin");
        writer.println(";; Analysis Date: " + new java.util.Date());
        writer.println(";;");
        writer.println(";; Statistics:");
        writer.println(";;   Instructions:  " + instructionCount);
        writer.println(";;   Defined Data:  " + dataCount);
        writer.println(";;   Undefined:     " + undefinedCount);
        writer.println(";;");
        writer.println("================================================\n");
        
        // Export all instructions
        CodeUnitIterator codeUnits = listing.getCodeUnits(true);
        int exportedCount = 0;
        
        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            Address addr = cu.getAddress();
            
            // Get any label at this address
            String label = "";
            for (ghidra.program.model.symbol.Symbol sym : currentProgram.getSymbolTable().getSymbols(addr)) {
                if (sym.isPrimary()) {
                    label = sym.getName() + ":";
                    break;
                }
            }
            
            if (!label.isEmpty()) {
                writer.println("\n" + label);
            }
            
            if (cu instanceof Instruction) {
                Instruction inst = (Instruction) cu;
                writer.printf("%-12s  %-30s  ; %s\n", 
                    addr.toString(), 
                    inst.toString(),
                    inst.getMnemonicString());
                exportedCount++;
            } else if (cu instanceof Data) {
                Data data = (Data) cu;
                writer.printf("%-12s  %-30s  ; DATA\n", 
                    addr.toString(), 
                    data.toString());
            }
            
            if (exportedCount % 10000 == 0 && exportedCount > 0) {
                println("Exported " + exportedCount + " instructions...");
            }
        }
        
        writer.close();
        
        println("\n========================================");
        println("Export complete!");
        println("Total code units exported: " + exportedCount);
        println("Output: " + outputPath);
        println("========================================");
    }
}
