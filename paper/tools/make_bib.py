#!/usr/bin/env python3
"""Build the paper's references.bib from verified metadata only (paper/literature/citation_map.json), never by hand.

Title, authors, DOI/arXiv id: from the verified record (Semantic Scholar, or Crossref by DOI). Entry type, publication
year and venue name: from the thesis bibliography when the key is there (the venue year, e.g. USENIX Security 2022 for
a 2020 preprint), else from the record, with a small map of abbreviated venue names. Only keys cited in the paper's
sections are written; a cited key that is not verified (or not a known software/web entry) stops the build.

    python3 make_bib.py --map citation_map.json --thesis-bib thesis/references.bib --software software.bib \
        --sections paper/latex/sections --output paper/latex/references.bib
"""
import argparse
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

VENUE = {'TSEC': 'ACM Transactions on Information and System Security',
         'arXiv.org': 'arXiv'}
CONFERENCE = re.compile(r'Symposium|Conference|Proceedings|Workshop|Anais|Escola|Simp|Congress|Meeting|S&P|Engineering Conference', re.I)


def thesis_entries(path):
    out = {}
    for m in re.finditer(r'@(\w+)\{([^,]+),(.*?)\n\}', Path(path).read_text(), re.S):
        fields = {k.lower(): v.strip() for k, v in re.findall(r'(\w+)\s*=\s*\{(.*?)\},?\s*\n', m.group(3) + '\n', re.S)}
        out[m.group(2)] = dict(type=m.group(1).lower(), **fields)
    return out


def cited(sections):
    keys = set()
    for f in Path(sections).glob('*.tex'):
        for group in re.findall(r'\\cite\{([^}]*)\}', f.read_text()):
            keys.update(k.strip() for k in group.split(','))
    return keys


def tex_escape(s):
    return s.replace('&', r'\&').replace('%', r'\%').replace('_', r'\_').replace('#', r'\#')


def crossref_meta(doi, cache):
    """Year, venue and pages of a DOI from Crossref (cached): the publisher's record of where and when it appeared."""
    if doi not in cache:
        req = urllib.request.Request('https://api.crossref.org/works/' + urllib.parse.quote(doi),
                                     headers={'User-Agent': 'paper-reference-check/1.0'})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                m = json.load(r)['message']
            cache[doi] = dict(year=((m.get('published') or m.get('issued') or {}).get('date-parts') or [[None]])[0][0],
                              venue=(m.get('container-title') or [None])[-1], series=(m.get('container-title') or [None])[0]
                              if len(m.get('container-title') or []) > 1 else None, pages=m.get('page'), type=m.get('type'))
        except Exception as e:                             # no Crossref record: keep the other sources
            cache[doi] = dict(error=str(e))
        time.sleep(1)
    return cache[doi]


def entry(key, rec, th, cache=None):
    if th and th.get('type') == 'book':                 # a book: its DOI match is often a review of it; keep the
        rec = dict(rec, external_ids={})                # publisher and year of the thesis entry
    doi = (rec.get('external_ids') or {}).get('DOI')
    cr = crossref_meta(doi, cache) if (doi and cache is not None) else {}
    if cr.get('year') and cr.get('venue'):              # the publisher's record decides year, venue, pages
        rec = dict(rec, source='crossref', s2_year=cr['year'], pages=cr.get('pages') or rec.get('pages'),
                   venue='; '.join(x for x in (cr.get('series'), cr['venue']) if x))
        if cr.get('type') == 'journal-article':
            rec['venue_kind'] = 'article'
    if rec.get('source') == 'crossref':                 # a DOI record: its own year and venue are authoritative
        th = None
        venue = (rec.get('venue') or '').split('; ')[-1]
        series = (rec.get('venue') or '').split('; ')[0] if '; ' in (rec.get('venue') or '') else None
        year = rec.get('s2_year')
        kind = rec.get('venue_kind') or ('inproceedings' if series or CONFERENCE.search(venue) else 'article')
    else:
        series = None
        year = (th or {}).get('year') or rec.get('year') or rec.get('s2_year')
        venue = (th or {}).get('booktitle') or (th or {}).get('journal') or VENUE.get(rec.get('venue'), rec.get('venue')) or ''
        kind = (th or {}).get('type') or ('inproceedings' if CONFERENCE.search(venue) else 'article' if venue else 'misc')
        if kind == 'misc' and CONFERENCE.search(venue) and venue != 'arXiv':
            kind = 'inproceedings'
    venue = venue.strip('{}')
    authors = ' and '.join(rec.get('authors') or []) or (th or {}).get('author', '')
    if not authors:
        raise SystemExit(f'{key}: no author in the verified record nor in the thesis entry')
    f = [f"  author = {{{authors}}}", f"  title = {{{{{tex_escape(rec['s2_title'])}}}}}",
         f"  year = {{{year}}}"]
    if kind == 'inproceedings' and venue:
        f.append(f"  booktitle = {{{tex_escape(venue)}}}")
    elif kind == 'article' and venue:
        f.append(f"  journal = {{{tex_escape(venue)}}}")
    elif kind == 'book' and th and th.get('publisher'):
        f.append(f"  publisher = {{{th['publisher']}}}")
    elif kind == 'misc' and venue:
        f.append(f"  howpublished = {{{tex_escape(venue)}}}")
    if series:
        f.append(f"  series = {{{series}}}")
    if rec.get('pages'):
        f.append(f"  pages = {{{rec['pages'].replace('-', '--')}}}")
    ids = rec.get('external_ids') or {}
    if ids.get('DOI'):
        f.append(f"  doi = {{{ids['DOI']}}}")
    elif ids.get('ArXiv'):
        f.append(f"  note = {{arXiv:{ids['ArXiv']}}}")
    return f"@{kind}{{{key},\n" + ',\n'.join(f) + '\n}\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--map', type=Path, required=True)
    ap.add_argument('--thesis-bib', type=Path, required=True)
    ap.add_argument('--software', type=Path, required=True, help='hand-kept @misc entries for tools and web pages')
    ap.add_argument('--sections', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--crossref-cache', type=Path, help='JSON cache of Crossref records by DOI')
    a = ap.parse_args()
    cmap, th = json.loads(a.map.read_text()), thesis_entries(a.thesis_bib)
    software = a.software.read_text()
    soft_keys = set(re.findall(r'@\w+\{([^,]+),', software))
    keys = cited(a.sections)
    bad = sorted(k for k in keys if k not in soft_keys and (cmap.get(k, {}).get('verified') is not True))
    if bad:
        raise SystemExit(f'cited but not verified: {bad}')
    cache = json.loads(a.crossref_cache.read_text()) if a.crossref_cache and a.crossref_cache.exists() else {}
    out = [software.strip() + '\n'] + [entry(k, cmap[k], th.get(k), cache if a.crossref_cache else None)
                                       for k in sorted(keys - soft_keys)]
    if a.crossref_cache:
        a.crossref_cache.write_text(json.dumps(cache, indent=1, ensure_ascii=False) + '\n')
    a.output.write_text('% generated by paper/tools/make_bib.py from verified metadata; do not edit by hand\n\n' + '\n'.join(out))
    print(f'{len(keys)} cited, {len(keys - soft_keys)} papers, {len(keys & soft_keys)} software/web')


if __name__ == '__main__':
    main()
