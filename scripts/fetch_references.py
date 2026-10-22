#!/usr/bin/env python3
"""Catalog the papers and sources cited by the reports and keep a local PDF copy of each paper that is reachable.

Sources: every markdown link in the four status reports and RESEARCH_IDEAS.md, plus ``references/extra.json``
(classics cited by author and year only). Each entry gets a type (paper / dataset / tool / web), the reports citing
it, a resolved PDF link where one is public (arXiv, USENIX, NDSS, PMLR, MDPI, ACM, direct .pdf) and, after download,
the SHA-256 and size of the file. PDFs go to ``references/pdf/`` which is git-ignored: the repository is public and
most papers may not be redistributed; the catalog (``references/catalog.json``) is what is versioned, so any copy
can be checked against it. Downloads are data only: nothing fetched is executed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

REPORTS = ('RESEARCH_IDEAS.md', 'SENTINEL_PULSE_STATUS.md', 'SYSCALL_FEATURE_EXPERIMENT_STATUS.md',
           'RCA_RUNTIME_STATUS.md', 'RULE_INTEGRATION_STATUS.md')
LINK = re.compile(r'\[([^\]]{3,200})\]\((https?://[^)\s]+)\)')
UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
      'Accept': 'text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
DATASET = ('zenodo.org', 'ieee-dataport.org', 'github.com/LID-DS')
TOOL = ('github.com', 'raw.githubusercontent.com', 'mapie.readthedocs.io', 'attack.mitre.org')
WEB = ('sysdig.com', 'scmagazine.com', 'utwente.nl/en/eemcs/events')


def kind(url):
    if any(d in url for d in DATASET):
        return 'dataset'
    if any(d in url for d in TOOL):
        return 'tool'
    if any(d in url for d in WEB):
        return 'web'
    return 'paper'


def get(url, limit=200_000_000):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=40) as response:
        chunks, size = [], 0
        while size < limit and (chunk := response.read(1 << 20)):  # read(n) may return early on chunked replies
            chunks.append(chunk); size += len(chunk)
        return b''.join(chunks), response.geturl()


def arxiv_id(url):
    m = re.search(r'(?:arxiv\.org/(?:abs|pdf|html)/|ar5iv\.labs\.arxiv\.org/html/)(\d{4}\.\d{4,5})', url)
    return m.group(1) if m else None


def pdf_candidates(url):
    """PDF links to try for a cited URL, cheapest first; the landing page is parsed only when needed."""
    if (aid := arxiv_id(url)):
        return [f'https://arxiv.org/pdf/{aid}']
    if url.lower().split('?')[0].endswith('.pdf') or '/download/' in url:
        return [url]
    if 'proceedings.mlr.press' in url and url.endswith('.html'):
        stem = url[:-5]
        return [f'{stem}/{stem.rsplit("/", 1)[1]}.pdf', 'landing:' + url]
    if 'dl.acm.org/doi/' in url:
        return [re.sub(r'/doi/(fullHtml|abs|full)?/?', '/doi/pdf/', url)]
    if 'api.crossref.org/works/' in url:
        doi = urllib.parse.unquote(url.split('/works/', 1)[1])
        return [f'https://dl.acm.org/doi/pdf/{doi}'] if doi.startswith('10.1145/') else []
    if 'projecteuclid.org/' in url and url.endswith('.full'):
        return [url[:-5] + '.pdf']
    if 'scitepress.org/PublishedPapers/' in url:
        year, number = url.rstrip('/').split('/')[-2:]
        return [f'https://www.scitepress.org/Papers/{year}/{number}/{number}.pdf']
    return ['landing:' + url]


def from_landing(url):
    html, final = get(url, 5_000_000)
    text = html.decode('utf-8', 'replace')
    if 'mdpi.com' in final:
        return [final.rstrip('/') + '/pdf']
    found = re.findall(r'href="([^"]+\.pdf)"', text) + re.findall(r'content="([^"]+\.pdf)"', text)
    found += re.findall(r'href="([^"]*/article/download/[^"]+)"', text)
    found += ['https://openreview.net/pdf?id=' + i for i in re.findall(r'openreview\.net/(?:forum|pdf)\?id=([A-Za-z0-9_-]+)', text)]
    found = [f for f in found if 'slides' not in f.lower()]
    base = re.match(r'https?://[^/]+', final).group(0)  # type: ignore[union-attr]
    return [f if f.startswith('http') else base + f for f in dict.fromkeys(found)]


def slug(entry):
    return re.sub(r'[^a-z0-9]+', '-', entry['title'].lower())[:70].strip('-')


def register(entry, path: Path, how):
    data = path.read_bytes()
    return dict(status='downloaded', how=how, file=f'pdf/{path.name}', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def fetch(entry, pdf_dir: Path):
    # a copy placed by hand under the expected name (publisher pages that need a browser) is registered as is
    if (manual := pdf_dir / f'{slug(entry)}.pdf').exists():
        return register(entry, manual, 'placed_by_hand')
    tried = []
    if entry.get('pdf_url') == 'none':                  # checked by hand: no public PDF of this paper
        return dict(status='not_downloaded', expected_file=f'pdf/{slug(entry)}.pdf', tried=[entry.get('note', '')])
    candidates = [entry['pdf_url']] if entry.get('pdf_url') else pdf_candidates(entry['url'])
    for candidate in candidates:
        try:
            options = from_landing(candidate[8:]) if candidate.startswith('landing:') else [candidate]
        except (urllib.error.URLError, OSError, ValueError) as error:
            tried.append(f'{candidate}: {str(error)[:80]}'); continue
        for option in options[:3]:
            try:
                data, final = get(option)
            except (urllib.error.URLError, OSError, ValueError) as error:
                tried.append(f'{option}: {str(error)[:80]}'); continue
            if not data.startswith(b'%PDF'):
                tried.append(f'{option}: not a PDF (paywall or login page)'); continue
            if b'%%EOF' not in data[-2048:]:
                tried.append(f'{option}: truncated PDF ({len(data)} bytes)'); continue
            path = pdf_dir / f'{slug(entry)}.pdf'
            path.write_bytes(data)
            return dict(register(entry, path, 'script'), pdf_url=final)
    return dict(status='not_downloaded', expected_file=f'pdf/{slug(entry)}.pdf', tried=tried or ['no public PDF link known'])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--no-download', action='store_true')
    a = p.parse_args()
    ref = a.repo / 'references'; pdf_dir = ref / 'pdf'; pdf_dir.mkdir(parents=True, exist_ok=True)
    entries = {}
    for report in REPORTS:
        for title, url in LINK.findall((a.repo / report).read_text()):
            e = entries.setdefault(url, dict(title=title, url=url, cited_in=[]))
            if report not in e['cited_in']:
                e['cited_in'].append(report)
    for extra in json.loads((ref / 'extra.json').read_text()):
        entries.setdefault(extra['url'], dict(cited_in=[])).update(extra)
    old = {e['url']: e for e in json.loads((ref / 'catalog.json').read_text())} if (ref / 'catalog.json').exists() else {}
    catalog = []
    for url, e in sorted(entries.items(), key=lambda kv: kv[1]['title'].lower()):
        e['type'] = kind(url)
        previous = old.get(url, {})
        if previous.get('status') == 'downloaded' and (ref / previous['file']).exists():
            e.update({k: previous[k] for k in ('status', 'how', 'pdf_url', 'file', 'bytes', 'sha256', 'fetched_at') if k in previous})
        elif e['type'] == 'paper' and not a.no_download:
            e.update(fetch(e, pdf_dir), fetched_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
        else:
            e.setdefault('status', 'link_only' if e['type'] != 'paper' else 'not_downloaded')
        catalog.append(e)
        print(f"{e['status']:15s} {e['type']:8s} {e['title'][:70]}")
    (ref / 'catalog.json').write_text(json.dumps(catalog, ensure_ascii=False, indent=1) + '\n')
    counts = {}
    for e in catalog:
        counts[(e['type'], e['status'])] = counts.get((e['type'], e['status']), 0) + 1
    print(counts)


if __name__ == '__main__':
    main()
