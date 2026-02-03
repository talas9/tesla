# Tesla Knowledge Base (KB)

This folder is the **single source of truth** for all Tesla firmware/UI/gateway/Hermes research we’ve extracted.

## Goals
- **One knowledge base**: everything referenced from a single index.
- **Incremental updates**: add new findings without breaking structure.
- **Indexable**: generate machine-readable + human-readable indexes.

## Structure
- `../` (parent): research docs (e.g. `00-master-cross-reference.md`, `02-gateway-can-flood-exploit.md`)
- `kb/meta/` : schemas + conventions
- `kb/scripts/` : index/build utilities
- `kb/index/` : generated outputs (`INDEX.md`, `INDEX.json`)

## Update workflow
1. Add/modify a doc in `/root/tesla/*.md` (or subfolders).
2. Prefer adding a small **Frontmatter block** (see `kb/meta/frontmatter.md`).
3. Rebuild indexes:
   ```bash
   python3 /root/tesla/kb/scripts/build_kb_index.py
   ```
4. Review `kb/index/INDEX.md` and `kb/index/INDEX.json`.

## Notes
- Keep raw artifacts (scripts, payloads, screenshots) in `/root/tesla/artifacts/` and reference them from docs.
