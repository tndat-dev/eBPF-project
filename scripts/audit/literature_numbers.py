#!/usr/bin/env python3
"""Literature numbers of references/KNOWLEDGE_SYNTHESIS.md checked against the text of the cited PDFs.

For every line of the synthesis that names exactly one paper of the key table (lines marked [ĐA], the project's own
analysis, and the quick-map table are skipped), each number of the line is searched in the text of that paper's PDF
(pdftotext; decimal comma -> point, thousands dot removed). Section numbers of the project's reports (5.17, 4.3...),
years and one-digit counts are not checked. A number that is not found is listed for reading by hand: it may be the
project's own number on that line, a rounding, or an error.

Needs the PDFs (outside git: references/pdf/, copy on NFS) and pdftotext (poppler-utils).

    python3 scripts/audit/literature_numbers.py [--text-dir DIR]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYNTHESIS = ROOT/'references'/'KNOWLEDGE_SYNTHESIS.md'
PDF_DIR = ROOT/'references'/'pdf'


def key_table(text):
    keys = {}
    for line in text[text.index('## Bảng tra khóa → file'):].splitlines():
        m = re.match(r'\| ([^|]+?) (\*\(dựng lại\)\* )?\| .* \| `([^`]+\.pdf)` \|', line)
        if m:
            keys[m.group(1).strip()] = (m.group(3), bool(m.group(2)))
    return keys


def forms(token):
    t = token.replace('.', '').replace(',', '.') if re.match(r'^\d{1,3}(\.\d{3})+$', token) else token.replace(',', '.')
    out = {t}
    if re.match(r'^\d{4,}$', t):
        out.add(f'{int(t):,}')
    if t.startswith('0.'):
        out.add(t[1:])
    if t.endswith('.0'):
        out.add(t[:-2])
    return out


def check(text_dir):
    text = SYNTHESIS.read_text()
    keys = key_table(text)
    body = text[text.index('## 1. Phát hiện'):text.index('## Bảng tra khóa → file')]
    checked, unmatched = 0, []
    for line in body.splitlines():
        if line.startswith('| 1.') or '[ĐA]' in line:
            continue
        hit = [k for k in keys if k.split(' (')[0] in line]
        if len(hit) != 1:
            continue
        seg = re.sub(r'\((?:Pulse|syscall|RCA|RESEARCH_IDEAS|mục|R)\s?[^)]*\)', '', line)
        nums = [n for n in re.findall(r'(?<![\w.,])(\d+(?:[.,]\d+)?)(?![\w])', seg)
                if not re.match(r'^(19|20)\d\d$', n) and not re.match(r'^\d\.\d{1,2}$', n) and n not in tuple('0123456789') + ('10',)]
        pdf, reconstructed = keys[hit[0]]
        txt = text_dir/(pdf[:-4] + '.txt')
        if not txt.exists():
            src = PDF_DIR/pdf
            if not src.exists():
                continue
            subprocess.run(['pdftotext', str(src), str(txt)], check=False, capture_output=True)
        if not nums or not txt.exists():
            continue
        paper = txt.read_text(errors='ignore')
        for n in nums:
            checked += 1
            if not any(f in paper for f in forms(n)):
                unmatched.append((hit[0] + (' (reconstructed)' if reconstructed else ''), n, line.strip()[:160]))
    return checked, unmatched


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--text-dir', type=Path, help='cache for pdftotext output (default: a temporary directory)')
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        text_dir = a.text_dir or Path(tmp)
        text_dir.mkdir(parents=True, exist_ok=True)
        checked, unmatched = check(text_dir)
    print(f'{checked} literature numbers checked, {len(unmatched)} not found in the cited PDF')
    for key, n, line in unmatched:
        print(f'  {key} | {n} | {line}')


if __name__ == '__main__':
    main()
