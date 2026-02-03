#!/bin/bash
# Organize Tesla research into structured folders

mkdir -p docs/{core,gateway,mcu,ape,network,tools,evidence,firmware}
mkdir -p data/{configs,strings,disassembly,binaries}
mkdir -p scripts

# Core research documents (00-20)
mv 00-master-cross-reference.md docs/core/ 2>/dev/null
mv 01-*.md 02-*.md 03-*.md 04-*.md 05-*.md docs/core/ 2>/dev/null
mv 06-*.md 07-*.md 08-*.md 09-*.md 10-*.md docs/core/ 2>/dev/null
mv 11-*.md 12-*.md 13-*.md 14-*.md 15-*.md docs/core/ 2>/dev/null
mv 16-*.md 17-*.md 18-*.md 19-*.md 20-*.md docs/core/ 2>/dev/null

# Gateway research (21-55, 76-99)
mv 21-*.md 22-*.md 23-*.md 36-*.md 37-*.md 38-*.md docs/gateway/ 2>/dev/null
mv 47-*.md 50-*.md 51-*.md 52-*.md 53-*.md 54-*.md 55-*.md docs/gateway/ 2>/dev/null
mv 76-*.md 77-*.md 78-*.md 79-*.md 80-*.md 81-*.md 82-*.md docs/gateway/ 2>/dev/null
mv 83-*.md 84-*.md 88-*.md 89-*.md 90-*.md 91-*.md 92-*.md docs/gateway/ 2>/dev/null
mv 93-*.md 94-*.md 95-*.md 96-*.md 97-*.md 98-*.md 99-*.md docs/gateway/ 2>/dev/null

# MCU research (24-35)
mv 24-*.md 25-*.md 26-*.md 27-*.md 28-*.md 29-*.md 30-*.md docs/mcu/ 2>/dev/null
mv 31-*.md 32-*.md 33-*.md 34-*.md 35-*.md docs/mcu/ 2>/dev/null

# APE research (40-46)
mv 40-*.md 41-*.md 42-*.md 43-*.md 44-*.md 45-*.md 46-*.md docs/ape/ 2>/dev/null

# Network research (48-49)
mv 48-*.md 49-*.md docs/network/ 2>/dev/null

# Tools (56-58)
mv 56-*.md 57-*.md 58-*.md docs/tools/ 2>/dev/null

# Evidence & audit (59-75)
mv 59-*.md 60-*.md 61-*.md 62-*.md 63-*.md 64-*.md 65-*.md docs/evidence/ 2>/dev/null
mv 66-*.md 67-*.md 68-*.md 69-*.md 70-*.md 71-*.md 72-*.md docs/evidence/ 2>/dev/null
mv 73-*.md 74-*.md 75-*.md docs/evidence/ 2>/dev/null

# Firmware binaries
mv 85-*.md 86-*.md 87-*.md docs/firmware/ 2>/dev/null

# Special files
mv README.md VERIFICATION-STATUS.md EVIDENCE-AUDIT-SUMMARY.md docs/ 2>/dev/null

# Data files
mv *.csv *.txt *.json data/ 2>/dev/null || true
mv gateway_*.txt data/disassembly/ 2>/dev/null || true
mv *.bin data/binaries/ 2>/dev/null || true

# Scripts
mv *.py scripts/ 2>/dev/null || true
mv organize.sh scripts/

echo "Organization complete!"
ls -R docs/ data/ scripts/ | head -100
