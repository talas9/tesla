#!/usr/bin/env python3
"""
Analyze Tesla Gateway firmware with Ghidra PowerPC VLE processor
Exports full disassembly to text file
"""

import os
import sys
import subprocess
from pathlib import Path

# Paths
GHIDRA_ROOT = "/opt/ghidra_11.2.1_PUBLIC"
GHIDRA_HEADLESS = os.path.join(GHIDRA_ROOT, "support", "analyzeHeadless")
BINARY_PATH = "/root/tesla/data/binaries/ryzenfromtable.bin"
PROJECT_DIR = "/root/tesla/ghidra-projects"
PROJECT_NAME = "TeslaGateway"
OUTPUT_DIR = "/root/tesla/data/disassembly"

# Ensure directories exist
Path(PROJECT_DIR).mkdir(parents=True, exist_ok=True)
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# Ghidra script to run analysis and export
GHIDRA_SCRIPT = """
// Tesla Gateway VLE Analysis and Export
// @category Tesla

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ExportDisassembly extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        Program program = getCurrentProgram();
        String outputPath = "/root/tesla/data/disassembly/ghidra-vle-full.asm";
        
        println("Starting export to: " + outputPath);
        
        // Get instruction listing
        Listing listing = program.getListing();
        AddressSetView addressSet = program.getMemory().getAllInitializedAddressSet();
        
        // Open output file
        FileWriter fw = new FileWriter(outputPath);
        BufferedWriter writer = new BufferedWriter(fw);
        
        // Write header
        writer.write("# Tesla Gateway PowerPC VLE Disassembly\\n");
        writer.write("# Binary: ryzenfromtable.bin (6MB MPC5748G firmware)\\n");
        writer.write("# Processor: PowerPC VLE 32-bit\\n");
        writer.write("# Analyzed with Ghidra " + getGhidraVersion() + "\\n");
        writer.write("# Total addresses: " + addressSet.getNumAddresses() + "\\n");
        writer.write("\\n");
        
        // Iterate through all instructions
        InstructionIterator instructions = listing.getInstructions(addressSet, true);
        long count = 0;
        Address lastAddr = null;
        
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Address addr = instr.getAddress();
            
            // Check for gaps (data sections)
            if (lastAddr != null && addr.subtract(lastAddr) > instr.getLength()) {
                writer.write("\\n");
            }
            
            // Format: ADDRESS: BYTES    MNEMONIC OPERANDS    ; COMMENT
            String line = String.format("0x%08x: %-16s %-8s %s",
                addr.getOffset(),
                formatBytes(instr.getBytes()),
                instr.getMnemonicString(),
                instr.getDefaultOperandRepresentation(0)
            );
            
            // Add any comments
            String comment = getEOLComment(addr);
            if (comment != null) {
                line += "    ; " + comment;
            }
            
            writer.write(line + "\\n");
            
            lastAddr = addr;
            count++;
            
            // Progress indicator
            if (count % 10000 == 0) {
                println("Exported " + count + " instructions...");
            }
        }
        
        writer.close();
        println("Export complete: " + count + " instructions written to " + outputPath);
    }
    
    private String formatBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xFF));
        }
        return sb.toString().trim();
    }
}
"""

def create_ghidra_script():
    """Create the Ghidra export script"""
    script_path = os.path.join(PROJECT_DIR, "ExportDisassembly.java")
    with open(script_path, 'w') as f:
        f.write(GHIDRA_SCRIPT)
    return script_path

def run_ghidra_analysis():
    """Run Ghidra headless analysis"""
    
    print("[*] Analyzing Tesla Gateway firmware with Ghidra PowerPC VLE")
    print(f"[*] Binary: {BINARY_PATH}")
    print(f"[*] Project: {PROJECT_DIR}/{PROJECT_NAME}")
    print(f"[*] Output: {OUTPUT_DIR}/ghidra-vle-full.asm")
    print()
    
    # Create Ghidra script
    script_path = create_ghidra_script()
    print(f"[+] Created export script: {script_path}")
    
    # Build Ghidra command
    # analyzeHeadless <project_location> <project_name> [[-import [<file>|<folder>]] | [-process [<project_file>]]]
    #                 [-postScript <ScriptName>]
    #                 [-processor <languageID>]
    #                 [-cspec <compilerSpecID>]
    #                 [-deleteProject]
    cmd = [
        GHIDRA_HEADLESS,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", BINARY_PATH,
        "-processor", "PowerPC:VLE:32:default",
        "-postScript", script_path,
        "-deleteProject",  # Clean up after
        "-max-cpu", "4",   # Use multiple cores
        "-overwrite"       # Overwrite existing project
    ]
    
    print(f"[*] Running: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            print()
            print("[+] Analysis complete!")
            
            # Check output file
            output_file = os.path.join(OUTPUT_DIR, "ghidra-vle-full.asm")
            if os.path.exists(output_file):
                size = os.path.getsize(output_file)
                lines = sum(1 for _ in open(output_file))
                print(f"[+] Disassembly exported: {output_file}")
                print(f"[+] Size: {size:,} bytes ({lines:,} lines)")
                return True
            else:
                print("[!] Warning: Output file not found")
                return False
        else:
            print(f"[!] Ghidra analysis failed with code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("[!] Analysis timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def search_disassembly():
    """Search exported disassembly for key items"""
    output_file = os.path.join(OUTPUT_DIR, "ghidra-vle-full.asm")
    
    if not os.path.exists(output_file):
        print("[!] Disassembly file not found, skipping search")
        return
    
    print()
    print("[*] Searching for key patterns...")
    
    patterns = {
        "UDP Port 3500 (0x0DAC)": ["0x0dac", "0x00000dac", "3500"],
        "String references": ["soc_udpcmds_task", "udpApiTask"],
        "Authentication": ["Hermes", "access_id", "permission"],
        "Config handlers": ["GET_CONFIG", "SET_CONFIG"]
    }
    
    for pattern_name, keywords in patterns.items():
        print(f"\n[*] Searching for: {pattern_name}")
        matches = []
        with open(output_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                for keyword in keywords:
                    if keyword.lower() in line.lower():
                        matches.append((line_num, line.strip()))
                        break
        
        if matches:
            print(f"[+] Found {len(matches)} matches:")
            for line_num, line in matches[:5]:  # Show first 5
                print(f"    Line {line_num}: {line[:80]}")
            if len(matches) > 5:
                print(f"    ... and {len(matches) - 5} more")
        else:
            print(f"[-] No matches found")

if __name__ == "__main__":
    print("=" * 70)
    print("Tesla Gateway Firmware - Ghidra PowerPC VLE Analysis")
    print("=" * 70)
    print()
    
    # Check prerequisites
    if not os.path.exists(GHIDRA_HEADLESS):
        print(f"[!] Error: Ghidra not found at {GHIDRA_HEADLESS}")
        print("[!] Please install Ghidra or update GHIDRA_ROOT path")
        sys.exit(1)
    
    if not os.path.exists(BINARY_PATH):
        print(f"[!] Error: Binary not found at {BINARY_PATH}")
        sys.exit(1)
    
    # Run analysis
    success = run_ghidra_analysis()
    
    if success:
        # Search for key patterns
        search_disassembly()
        
        print()
        print("=" * 70)
        print("[+] Analysis complete!")
        print(f"[+] Full disassembly: {OUTPUT_DIR}/ghidra-vle-full.asm")
        print("=" * 70)
        sys.exit(0)
    else:
        print()
        print("=" * 70)
        print("[!] Analysis failed")
        print("=" * 70)
        sys.exit(1)
