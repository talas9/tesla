#!/usr/bin/env python3
"""Build an index for /root/tesla markdown research.

Outputs:
- /root/tesla/kb/index/INDEX.md  (human)
- /root/tesla/kb/index/INDEX.json (machine)

Design goals:
- No external deps (stdlib only)
- Best-effort frontmatter parsing
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path('/root/tesla')
KB = ROOT / 'kb'
OUT_MD = KB / 'index' / 'INDEX.md'
OUT_JSON = KB / 'index' / 'INDEX.json'

FRONTMATTER_RE = re.compile(r'^---\s*\n(.*?)\n---\s*\n', re.DOTALL)
H1_RE = re.compile(r'^#\s+(.+?)\s*$')
H2_RE = re.compile(r'^##\s+(.+?)\s*$')

# extremely tiny YAML-ish parser for simple frontmatter (key: value, lists in [a,b])
# if it fails, we just ignore it.

def _parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    body = m.group(1)
    rest = text[m.end():]
    data: Dict[str, Any] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        # naive list support
        if v.startswith('[') and v.endswith(']'):
            inner = v[1:-1].strip()
            data[k] = [x.strip().strip('"').strip("'") for x in inner.split(',') if x.strip()]
        else:
            data[k] = v
    return data, rest

@dataclass
class DocEntry:
    path: str
    title: str
    h2: List[str]
    meta: Dict[str, Any]


def _extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        m = H1_RE.match(line)
        if m:
            return m.group(1).strip()
    return fallback


def _extract_h2(text: str) -> List[str]:
    out: List[str] = []
    for line in text.splitlines():
        m = H2_RE.match(line)
        if m:
            out.append(m.group(1).strip())
    return out


def main() -> None:
    md_files: List[Path] = []
    for p in ROOT.rglob('*.md'):
        # skip generated index outputs and KB meta docs themselves
        if str(p).startswith(str(KB / 'index')):
            continue
        if str(p).startswith(str(KB / 'meta')):
            continue
        if str(p).startswith(str(KB / 'scripts')):
            continue
        md_files.append(p)

    entries: List[DocEntry] = []
    for p in sorted(md_files):
        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        meta, rest = _parse_frontmatter(text)
        title = meta.get('title') or _extract_title(rest, p.name)
        h2 = _extract_h2(rest)
        rel = str(p)
        entries.append(DocEntry(path=rel, title=title, h2=h2, meta=meta))

    # Build markdown index
    lines: List[str] = []
    lines.append('# Tesla Research Index\n')
    lines.append(f'Generated from `{ROOT}`.\n')
    lines.append(f'Total docs: **{len(entries)}**\n')

    for e in entries:
        lines.append(f"## {e.title}")
        lines.append(f"- Path: `{e.path}`")
        if e.meta:
            # show common fields if present
            for k in ['date', 'vehicle', 'components', 'tags', 'confidence']:
                if k in e.meta:
                    lines.append(f"- {k}: `{e.meta[k]}`")
        if e.h2:
            lines.append('- Sections:')
            for h in e.h2[:30]:
                lines.append(f"  - {h}")
        lines.append('')

    OUT_MD.write_text('\n'.join(lines).strip() + '\n', encoding='utf-8')

    OUT_JSON.write_text(
        json.dumps([asdict(e) for e in entries], indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8'
    )

    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_JSON}")


if __name__ == '__main__':
    main()
