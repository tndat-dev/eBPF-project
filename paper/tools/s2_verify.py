#!/usr/bin/env python3
"""Literature step of the paper pipeline: verify references on Semantic Scholar (free API, no key) and build the
citation map that the section-writing step may cite (PaperOrchestra `citation_map.json`).

Input: a JSON list of {key, title, year?, kind?} (kind 'software' or 'web' entries are kept as given, not looked up).
Per paper: /graph/v1/paper/search/match on the title; accepted when the normalised titles match (token Jaccard >= 0.85)
and, if a year is given, |year difference| <= 1. Output per key: verified flag, S2 paper id, title, year, venue,
authors, DOI/arXiv id, abstract. Only titles of published papers are sent.

    python3 s2_verify.py --refs refs.json --out citation_map.json [--sleep 3]
"""
# Bước tìm tài liệu của paper: kiểm từng tài liệu trên Semantic Scholar (Crossref theo DOI khi S2 không có) → citation_map.json.
import argparse
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API = 'https://api.semanticscholar.org/graph/v1/paper/search/match'
FIELDS = 'title,year,venue,authors,externalIds,abstract,publicationVenue'


def norm(t):
    t = t.lower().replace('{', '').replace('}', '').replace("'", '').replace('\u2019', '')
    return set(re.sub(r'[^a-z0-9 ]', ' ', t).split())


def similar(a, b):
    x, y = norm(a), norm(b)
    return len(x & y) / max(1, len(x | y))


def match(title, sleep, tries=6):
    url = API + '?' + urllib.parse.urlencode(dict(query=title, fields=FIELDS))
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'paper-reference-check/1.0'})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r).get('data') or []
            return data[0] if data else None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                time.sleep(sleep * (2 ** i))
                continue
            raise
    return 'rate-limited'


def crossref(ref):
    """Verification of a DOI on Crossref (used when Semantic Scholar has no record): title similarity and year."""
    req = urllib.request.Request('https://api.crossref.org/works/' + urllib.parse.quote(ref['doi']),
                                 headers={'User-Agent': 'paper-reference-check/1.0'})
    with urllib.request.urlopen(req, timeout=30) as r:
        m = json.load(r)['message']
    title = (m.get('title') or [''])[0]
    year = ((m.get('published') or m.get('issued') or {}).get('date-parts') or [[None]])[0][0]
    sim = similar(ref['title'], title)
    year_ok = ref.get('year') is None or year is None or abs(int(ref['year']) - int(year)) <= 1
    return dict(verified=bool(sim >= 0.85 and year_ok), similarity=round(sim, 3), source='crossref', s2_title=title,
                s2_year=year, venue='; '.join(m.get('container-title') or []), pages=m.get('page'),
                authors=[(x.get('given', '') + ' ' + x.get('family', '')).strip() for x in m.get('author') or []],
                external_ids=dict(DOI=m.get('DOI')), abstract=None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--refs', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--sleep', type=float, default=3.0)
    a = ap.parse_args()
    out = json.loads(a.out.read_text()) if a.out.exists() else {}
    for ref in json.loads(a.refs.read_text()):
        key = ref['key']
        if key in out and out[key].get('verified') is True or out.get(key, {}).get('verified') == 'not-a-paper':
            continue
        if ref.get('kind') in ('software', 'web'):
            out[key] = dict(ref, verified='not-a-paper')
            a.out.write_text(json.dumps(out, indent=1, ensure_ascii=False) + '\n')
            continue
        if ref.get('doi'):                                  # no Semantic Scholar record: Crossref by DOI
            out[key] = dict(ref, **crossref(ref))
            a.out.write_text(json.dumps(out, indent=1, ensure_ascii=False) + '\n')
            print(f"{key:22s} {out[key]['verified']!s:12s} crossref {out[key].get('s2_title', '')[:60]}", flush=True)
            continue
        p = match(ref['title'], a.sleep)
        time.sleep(a.sleep)
        if p == 'rate-limited':
            print(f'{key:22s} rate limited, left for the next pass', flush=True)
            continue
        if p is None:
            out[key] = dict(ref, verified=False, reason='no match')
        else:
            sim = similar(ref['title'], p['title'])
            year_ok = ref.get('year') is None or p.get('year') is None or abs(int(ref['year']) - int(p['year'])) <= 1
            out[key] = dict(ref, verified=bool(sim >= 0.85 and (year_ok or sim == 1.0)), similarity=round(sim, 3),
                            year_note=None if year_ok else 'S2 year differs (preprint or reprint): check the venue year',
                            s2_id=p.get('paperId'),
                            s2_title=p.get('title'), s2_year=p.get('year'), venue=p.get('venue'),
                            authors=[x['name'] for x in p.get('authors') or []], external_ids=p.get('externalIds'),
                            abstract=p.get('abstract'))
        a.out.write_text(json.dumps(out, indent=1, ensure_ascii=False) + '\n')
        print(f"{key:22s} {out[key]['verified']!s:12s} {out[key].get('s2_title', '')[:70] if out[key].get('s2_title') else ''}",
              flush=True)


if __name__ == '__main__':
    main()
