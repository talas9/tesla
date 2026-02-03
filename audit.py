#!/usr/bin/env python3
"""Comprehensive evidence quality audit for Tesla research documents"""

import re
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Uncertain language markers
UNCERTAIN_PATTERNS = [
    r'\b(hypothesized|hypothesize)\b',
    r'\b(estimated|estimate)\b',
    r'\b(likely|probably|possibly|presumably)\b',
    r'\b(assumed|assumption)\b',
    r'\b(theoretical|theory)\b',
    r'\b(appears to|seems to)\b',
    r'\b(might be|could be|may be)\b',
    r'\b(speculation|speculative)\b',
    r'\b(unclear|uncertain)\b',
    r'\b(suggested|suggests)\b',
    r'\b(inferred|inference)\b',
    r'\b(untested|unverified)\b',
]

# Strong evidence markers
EVIDENCE_PATTERNS = [
    r'0x[0-9a-fA-F]{4,}',  # Memory addresses
    r'/[a-z/]+\.(so|conf|xml|json|bin)',  # File paths
    r'\b(binwalk|strings|ghidra|IDA|objdump|readelf)\b',  # Tools
    r'(Source:|Reference:|Extracted from:)',  # Citations
    r'```\s*(assembly|c|cpp)',  # Code blocks
    r'Disassembly of',
]

def analyze_file(filepath):
    """Analyze a single markdown file for evidence quality"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return None
    
    results = {
        'filepath': filepath,
        'filename': os.path.basename(filepath),
        'line_count': len(lines),
        'uncertain_matches': [],
        'evidence_matches': [],
        'citations': 0,
        'code_blocks': 0,
        'addresses': 0,
    }
    
    # Find uncertain language
    for i, line in enumerate(lines, 1):
        for pattern in UNCERTAIN_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                results['uncertain_matches'].append({
                    'line': i,
                    'text': line.strip()[:100],
                    'pattern': pattern
                })
    
    # Find evidence markers
    for i, line in enumerate(lines, 1):
        for pattern in EVIDENCE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                results['evidence_matches'].append({
                    'line': i,
                    'text': line.strip()[:100],
                    'pattern': pattern
                })
    
    # Count specific evidence types
    results['citations'] = len(re.findall(r'(Source:|Reference:|Extracted from:)', content, re.IGNORECASE))
    results['code_blocks'] = len(re.findall(r'```', content))
    results['addresses'] = len(re.findall(r'0x[0-9a-fA-F]{4,}', content))
    
    return results

def calculate_quality_score(results):
    """Calculate evidence quality score"""
    uncertain_count = len(results['uncertain_matches'])
    evidence_count = len(results['evidence_matches'])
    
    # Quality scoring
    if evidence_count >= 10 and uncertain_count < 5:
        return '✅ VERIFIED', 90
    elif evidence_count >= 5 and uncertain_count < evidence_count:
        return '⚠️ INFERRED', 60
    elif uncertain_count > 10 or evidence_count == 0:
        return '❌ UNTESTED', 20
    else:
        return '🔍 NEEDS RE-ANALYSIS', 40

def main():
    tesla_dir = Path('/root/tesla')
    output_file = tesla_dir / '59-EVIDENCE-AUDIT.md'
    
    # Find all markdown files
    md_files = sorted(tesla_dir.glob('*.md'))
    md_files = [f for f in md_files if f.name != '59-EVIDENCE-AUDIT.md']
    
    all_results = []
    
    print(f"Scanning {len(md_files)} markdown files...")
    
    for filepath in md_files:
        results = analyze_file(filepath)
        if results:
            all_results.append(results)
    
    # Generate audit report
    report = []
    report.append("# EVIDENCE AUDIT REPORT")
    report.append(f"\nGenerated: {datetime.now().isoformat()}")
    report.append(f"\nTotal documents analyzed: {len(all_results)}\n")
    report.append("---\n")
    
    # Summary statistics
    quality_counts = defaultdict(int)
    total_uncertain = 0
    total_evidence = 0
    
    # Sort by quality (worst first)
    scored_results = []
    for r in all_results:
        quality, score = calculate_quality_score(r)
        scored_results.append((score, quality, r))
        quality_counts[quality] += 1
        total_uncertain += len(r['uncertain_matches'])
        total_evidence += len(r['evidence_matches'])
    
    scored_results.sort(key=lambda x: x[0])  # Lower score = worse quality
    
    report.append("## SUMMARY STATISTICS\n")
    for quality, count in sorted(quality_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count * 100) // len(all_results)
        report.append(f"- {quality}: {count} documents ({percentage}%)")
    report.append(f"\n- Total uncertain phrases found: {total_uncertain}")
    report.append(f"- Total evidence markers found: {total_evidence}")
    report.append(f"- Average evidence per document: {total_evidence // len(all_results)}\n")
    
    report.append("---\n")
    report.append("## DETAILED FINDINGS\n")
    
    # Detailed per-file analysis
    for score, quality, r in scored_results:
        report.append(f"\n### {r['filename']}")
        report.append(f"\n**Quality:** {quality} (Score: {score}/100)")
        report.append(f"\n**Statistics:**")
        report.append(f"- Lines: {r['line_count']}")
        report.append(f"- Uncertain phrases: {len(r['uncertain_matches'])}")
        report.append(f"- Evidence markers: {len(r['evidence_matches'])}")
        report.append(f"- Memory addresses: {r['addresses']}")
        report.append(f"- Citations: {r['citations']}")
        report.append(f"- Code blocks: {r['code_blocks'] // 2}")  # Divide by 2 (open + close)
        
        # Show top uncertain phrases
        if r['uncertain_matches']:
            report.append(f"\n**Top Uncertain Phrases:**")
            for match in r['uncertain_matches'][:5]:
                report.append(f"- Line {match['line']}: {match['text']}")
        
        # Show sample evidence
        if r['evidence_matches']:
            report.append(f"\n**Sample Evidence:**")
            for match in r['evidence_matches'][:3]:
                report.append(f"- Line {match['line']}: {match['text']}")
        
        report.append("")
    
    # Priority re-analysis list
    report.append("---\n")
    report.append("## PRIORITY RE-ANALYSIS LIST\n")
    report.append("\n### CRITICAL (❌ UNTESTED)\n")
    
    critical = [r for s, q, r in scored_results if '❌' in q]
    for r in critical:
        report.append(f"- **{r['filename']}** - {len(r['uncertain_matches'])} uncertain, {len(r['evidence_matches'])} evidence")
    
    report.append("\n### MEDIUM (🔍 NEEDS RE-ANALYSIS)\n")
    needs_review = [r for s, q, r in scored_results if '🔍' in q]
    for r in needs_review:
        report.append(f"- **{r['filename']}** - {len(r['uncertain_matches'])} uncertain, {len(r['evidence_matches'])} evidence")
    
    report.append("\n### LOW (⚠️ INFERRED)\n")
    inferred = [r for s, q, r in scored_results if '⚠️' in q]
    for r in inferred:
        report.append(f"- **{r['filename']}** - Needs source citations")
    
    # Correction tasks
    report.append("\n---\n")
    report.append("## CORRECTION TASKS\n")
    report.append("\n### Documents Needing Complete Re-Analysis\n")
    for r in critical[:10]:
        report.append(f"- [ ] {r['filename']} - Re-analyze with firmware binaries")
    
    report.append("\n### Documents Needing Source Citations\n")
    for r in inferred[:10]:
        if r['citations'] < 3:
            report.append(f"- [ ] {r['filename']} - Add specific binary/file sources")
    
    report.append("\n### Hypotheses Ready for Verification\n")
    report.append("- [ ] Cross-reference with available firmware dumps")
    report.append("- [ ] Verify CAN message IDs with actual captures")
    report.append("- [ ] Test exploit code in safe environment")
    report.append("- [ ] Validate memory addresses with disassembly")
    
    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"\n✅ Audit complete! Report written to {output_file}")
    print(f"\nQuality breakdown:")
    for quality, count in sorted(quality_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {quality}: {count} documents")

if __name__ == '__main__':
    main()
