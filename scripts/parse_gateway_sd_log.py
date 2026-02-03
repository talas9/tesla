#!/usr/bin/env python3
"""Parse Tesla gateway SD-card log and regenerate analysis artifacts."""
from __future__ import annotations

import csv
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LOG_PATH = Path("/root/tesla/_docx_1711.txt")
CSV_PATH = Path("/root/tesla/09a-gateway-config-ids.csv")
MD_PATH = Path("/root/tesla/09-gateway-sdcard-log-analysis.md")

LINE_RE = re.compile(r"^\s*\d+:\"(?P<body>.*)\"\s*$")
TS_RE = re.compile(r"^(?P<tag>\S+)\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})::(?P<msg>.*)$")
CONFIG_RE = re.compile(r"Config\s+(?P<name>\S+)\s+id=(?P<id>\d+),\s+value=(?P<value>.*?)\s+len=(?P<len>\d+)")
TFTP_RE = re.compile(r"tftp\s+src:(?P<src>[^\s]+)\s+dest:(?P<dest>[^,]+),\s+attempt\s+#(?P<attempt>\d+)", re.IGNORECASE)
TRANSFER_DONE_RE = re.compile(r"(?P<target>[^\s].*?)\s+transfer completed", re.IGNORECASE)
MAP_MATCH_RE = re.compile(r"Matching\s+(?P<count>\d+)\s+line\s+with\s+(?P<key>.+?)\s+in\s+map\s+file", re.IGNORECASE)

HIGHLIGHT_IDS = [15, 29, 37, 38, 39, 40, 57, 59, 66]
TIMELINE_KEY_PHRASES = [
    "Spawn Update Task",
    "Two-pass update",
    "Begin hwidacq",
    "Queuing",
    "Entered OTA state",
    "tftp src",
    "Update",
    "Update completed",
    "Rebooting",
]
ERROR_KEYWORDS = ["err", "error", "refused", "mismatch", "failed"]

@dataclass
class ConfigMeta:
    id: int
    name: str
    first_ts: str
    last_ts: str
    value: str
    length: str


def parse_log() -> Tuple[List[Tuple[str, str, str]], Dict[int, ConfigMeta], List[Tuple[str, str, str, str]],
                        List[Tuple[str, str]], List[Tuple[str, str, str]]]:
    entries: List[Tuple[str, str, str]] = []  # (tag_time, tag, msg)
    configs: Dict[int, ConfigMeta] = {}
    tftp_starts: List[Tuple[str, str, str, str]] = []  # (ts, src, dest, attempt)
    transfers_done: List[Tuple[str, str]] = []  # (ts, target)
    map_matches: List[Tuple[str, str, str]] = []  # (ts, count, key)

    with LOG_PATH.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n\r")
            m = LINE_RE.match(line)
            if not m:
                continue
            body = m.group("body")
            entries.append(split_entry(body))
            ts, tag, msg = entries[-1]

            # configs
            cm = CONFIG_RE.search(msg if msg else body)
            if cm:
                cid = int(cm.group("id"))
                val = cm.group("value")
                length = cm.group("len")
                name = cm.group("name")
                meta = configs.get(cid)
                if not meta:
                    configs[cid] = ConfigMeta(cid, name, ts or "(no-ts)", ts or "(no-ts)", val, length)
                else:
                    meta.name = name
                    meta.last_ts = ts or meta.last_ts
                    meta.value = val
                    meta.length = length

            tftp = TFTP_RE.search(msg if msg else body)
            if tftp:
                tftp_starts.append((ts or "(no-ts)", tftp.group("src"), tftp.group("dest"), tftp.group("attempt")))
            td = TRANSFER_DONE_RE.search(msg if msg else body)
            if td and "tftp" not in (msg or body).lower():
                transfers_done.append((ts or "(no-ts)", td.group("target")))
            mm = MAP_MATCH_RE.search(msg if msg else body)
            if mm:
                map_matches.append((ts or "(no-ts)", mm.group("count"), mm.group("key")))
    return entries, configs, tftp_starts, transfers_done, map_matches


def split_entry(body: str) -> Tuple[str, str, str]:
    m = TS_RE.match(body)
    if not m:
        return "", "", body
    return f"{m.group('tag')} {m.group('time')}", m.group("tag"), m.group("msg")


def gather_timeline(entries: List[Tuple[str, str, str]]) -> List[Tuple[str, str]]:
    seen = set()
    timeline = []
    for ts, tag, msg in entries:
        combined = f"{tag} {msg}".strip()
        for phrase in TIMELINE_KEY_PHRASES:
            if phrase in combined and phrase not in seen:
                seen.add(phrase)
                timeline.append((ts or "(no-ts)", combined))
    return timeline


def collect_errors(entries: List[Tuple[str, str, str]]) -> Counter:
    cnt = Counter()
    for ts, tag, msg in entries:
        text = " ".join(filter(None, [tag, msg])).lower()
        for keyword in ERROR_KEYWORDS:
            if keyword in text:
                cnt[keyword] += 1
    return cnt


def write_csv(configs: Dict[int, ConfigMeta]) -> int:
    os.makedirs(CSV_PATH.parent, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "value (raw)", "len", "first_timestamp", "last_timestamp"])
        for cid in sorted(configs):
            meta = configs[cid]
            writer.writerow([meta.id, meta.name, meta.value, meta.length, meta.first_ts, meta.last_ts])
    return len(configs)


def write_md(entries: List[Tuple[str, str, str]], configs: Dict[int, ConfigMeta], tftp: List[Tuple[str, str, str, str]],
             transfers: List[Tuple[str, str]], map_matches: List[Tuple[str, str, str]], timeline: List[Tuple[str, str]],
             errors: Counter) -> None:
    os.makedirs(MD_PATH.parent, exist_ok=True)
    lines: List[str] = []
    lines.append("# Gateway SD-card log analysis")
    lines.append("")
    lines.append(f"Source log: `{LOG_PATH}`")
    lines.append(f"Total parsed lines: {len(entries)}")
    lines.append(f"Config rows written: {len(configs)}")
    lines.append(f"TFTP starts: {len(tftp)}")
    lines.append(f"Transfer completions: {len(transfers)}")
    lines.append(f"Map match entries: {len(map_matches)}")
    lines.append("")
    lines.append("## Highlighted Config IDs")
    for cid in HIGHLIGHT_IDS:
        meta = configs.get(cid)
        if meta:
            lines.append(f"- id={cid} name={meta.name} len={meta.length} last_value={meta.value} first={meta.first_ts} last={meta.last_ts}")
        else:
            lines.append(f"- id={cid} not present in log")
    lines.append("")
    lines.append("## Timeline anchors")
    for ts, item in timeline:
        lines.append(f"- {ts}: {item}")
    lines.append("")
    lines.append("## Error keyword counts")
    if not errors:
        lines.append("- (none)")
    else:
        for keyword, count in errors.most_common():
            lines.append(f"- {keyword}: {count}")
    lines.append("")
    lines.append("## TFTP transfers")
    lines.append("| timestamp | src → dest | attempt |")
    lines.append("|---|---|---|")
    for ts, src, dest, attempt in tftp:
        lines.append(f"| {ts} | {src} → {dest} | {attempt} |")
    lines.append("")
    lines.append("## Transfer completions (sample)")
    for ts, target in transfers[:10]:
        lines.append(f"- {ts}: {target}")
    lines.append("")
    lines.append("## Map matches (sample)")
    for ts, count, key in map_matches[:10]:
        lines.append(f"- {ts}: {count} line(s) with {key} in map file")

    MD_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    entries, configs, tftp_starts, transfers_done, map_matches = parse_log()
    timeline = gather_timeline(entries)
    errors = collect_errors(entries)
    rows = write_csv(configs)
    write_md(entries, configs, tftp_starts, transfers_done, map_matches, timeline, errors)
    print(f"Written {rows} config rows; highlights include {[cid for cid in HIGHLIGHT_IDS if cid in configs]}")


if __name__ == "__main__":
    main()
