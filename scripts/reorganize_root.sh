#!/bin/bash
# Clean up root directory - move everything to proper locations

# Move all numbered docs to docs/ if not already there
for file in [0-9]*.md; do
  if [ -f "$file" ]; then
    category=$(echo "$file" | cut -d'-' -f1)
    # Determine category based on number
    if [ $category -le 20 ]; then
      mv "$file" docs/core/ 2>/dev/null
    elif [ $category -ge 76 ]; then
      mv "$file" docs/gateway/ 2>/dev/null
    fi
  fi
done

# Move data files to data/ subdirectories
mv *.csv data/ 2>/dev/null
mv *.txt data/ 2>/dev/null
mv *.json data/ 2>/dev/null
mv *.bin data/binaries/ 2>/dev/null

# Move Python scripts
mv *.py scripts/ 2>/dev/null

# Move organization/temp files to docs/meta/
mkdir -p docs/meta
mv ORGANIZATION-SUMMARY.md docs/meta/ 2>/dev/null
mv EVIDENCE-AUDIT-SUMMARY.md docs/meta/ 2>/dev/null

# Keep only these in root:
# - README.md
# - .gitignore
# - .git/
# - docs/
# - data/
# - scripts/

echo "Root cleanup complete!"
ls -la | head -20
