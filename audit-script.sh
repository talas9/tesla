#!/bin/bash
# Comprehensive evidence quality audit script

# Uncertain language markers
UNCERTAIN_WORDS=(
  "hypothesized"
  "estimated"
  "likely"
  "probably"
  "assumed"
  "theoretical"
  "appears to"
  "seems to"
  "might be"
  "could be"
  "possibly"
  "presumably"
  "speculation"
  "unclear"
  "uncertain"
  "suggested"
  "inferred"
)

# Evidence markers (positive)
EVIDENCE_MARKERS=(
  "0x[0-9a-fA-F]+"
  "/[a-z/]+\.(so|conf|xml|json)"
  "strings output"
  "binwalk"
  "ghidra"
  "disassembly"
  "objdump"
  "readelf"
)

OUTPUT="/root/tesla/audit-results.txt"
> "$OUTPUT"

echo "=== EVIDENCE QUALITY AUDIT ===" >> "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

total_files=0
files_with_uncertain=0
files_with_evidence=0

for file in /root/tesla/*.md; do
  if [[ "$(basename "$file")" == "59-EVIDENCE-AUDIT.md" ]]; then
    continue
  fi
  
  total_files=$((total_files + 1))
  basename_file=$(basename "$file")
  
  # Count uncertain language
  uncertain_count=0
  uncertain_lines=""
  for word in "${UNCERTAIN_WORDS[@]}"; do
    matches=$(grep -in "\b$word\b" "$file" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
      uncertain_count=$((uncertain_count + $(echo "$matches" | wc -l)))
      uncertain_lines+="$matches"$'\n'
    fi
  done
  
  # Count evidence markers
  evidence_count=0
  for marker in "${EVIDENCE_MARKERS[@]}"; do
    count=$(grep -iEc "$marker" "$file" 2>/dev/null || echo 0)
    evidence_count=$((evidence_count + count))
  done
  
  # Check for source citations
  citation_count=$(grep -Ec '(Source:|Reference:|binwalk|strings|ghidra|IDA|objdump)' "$file" 2>/dev/null || echo 0)
  
  if [[ $uncertain_count -gt 0 ]]; then
    files_with_uncertain=$((files_with_uncertain + 1))
  fi
  
  if [[ $evidence_count -gt 0 ]]; then
    files_with_evidence=$((files_with_evidence + 1))
  fi
  
  # Calculate quality score
  if [[ $evidence_count -gt 0 ]]; then
    if [[ $uncertain_count -eq 0 ]]; then
      quality="✅ HIGH"
    elif [[ $evidence_count -gt $uncertain_count ]]; then
      quality="⚠️ MEDIUM"
    else
      quality="❌ LOW"
    fi
  else
    if [[ $uncertain_count -gt 5 ]]; then
      quality="❌ VERY LOW"
    else
      quality="🔍 NEEDS REVIEW"
    fi
  fi
  
  echo "FILE: $basename_file" >> "$OUTPUT"
  echo "  Quality: $quality" >> "$OUTPUT"
  echo "  Uncertain phrases: $uncertain_count" >> "$OUTPUT"
  echo "  Evidence markers: $evidence_count" >> "$OUTPUT"
  echo "  Citations: $citation_count" >> "$OUTPUT"
  
  if [[ $uncertain_count -gt 0 ]]; then
    echo "  Top uncertain lines:" >> "$OUTPUT"
    echo "$uncertain_lines" | head -5 >> "$OUTPUT"
  fi
  
  echo "" >> "$OUTPUT"
done

echo "=== SUMMARY ===" >> "$OUTPUT"
echo "Total files scanned: $total_files" >> "$OUTPUT"
echo "Files with uncertain language: $files_with_uncertain" >> "$OUTPUT"
echo "Files with evidence markers: $files_with_evidence" >> "$OUTPUT"
echo "Confidence rate: $(( (files_with_evidence * 100) / total_files ))%" >> "$OUTPUT"

cat "$OUTPUT"
