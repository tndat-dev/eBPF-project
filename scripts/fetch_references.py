#!/usr/bin/env python3
"""Catalog the papers and sources cited by the reports and keep one local PDF per paper.

Sources: every markdown link in the four status reports and RESEARCH_IDEAS.md, plus ``references/extra.json``
(classics cited by author and year, core methods, tools; an entry may set ``pdf_url``, ``html_url``, ``type`` or a
``bib`` override). For each paper:

1. bibliography from the arXiv API, Crossref (DOI) or the publisher page's ``citation_*`` tags (override first);
2. a PDF, in this order: the copy already kept, an explicit ``pdf_url``, the page's ``citation_pdf_url``, known URL
   patterns, open-access locations from OpenAlex. A PDF counts only if it is complete (``%PDF`` ... ``%%EOF``) and
   its first pages carry the paper's title (a repository brochure once came back instead of a paper);
3. else the publisher's full-text HTML printed to PDF with headless Chrome (``html_url`` or a known pattern),
   accepted only if the print carries the title (a bot-check page is rejected);
4. else a reconstruction: ``references/reconstructions.json`` holds what is publicly known (abstract with its
   source) and the compiler's reading of the paper; the PDF says on every page that it is not the original.

Files are named ``<year>-<first author>-<title>.pdf`` (``--web.pdf`` for a printed page, ``--reconstructed.pdf``
for a reconstruction) in ``references/pdf/``, which is git-ignored: the repository is public and most papers may
not be redistributed. ``references/catalog.json`` (versioned) records bibliography, origin, size and SHA-256 of
every file. Downloads are data only: nothing fetched is executed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

REPORTS = ('RESEARCH_IDEAS.md', 'SENTINEL_PULSE_STATUS.md', 'SYSCALL_FEATURE_EXPERIMENT_STATUS.md',
           'RCA_RUNTIME_STATUS.md', 'RULE_INTEGRATION_STATUS.md')
LINK = re.compile(r'\[([^\]]{3,200})\]\((https?://[^)\s]+)\)')
UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
      'Accept': 'text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
DATASET = ('zenodo.org', 'ieee-dataport.org', 'github.com/LID-DS')
TOOL = ('github.com', 'raw.githubusercontent.com', 'mapie.readthedocs.io', 'attack.mitre.org', 'istio.io/latest/docs',
        'falco.org', 'tetragon.io', 'prometheus.io/docs')
WEB = ('sysdig.com', 'scmagazine.com', 'utwente.nl/en/eemcs/events')
CHROME = shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')


def kind(url):
    for name, domains in (('dataset', DATASET), ('tool', TOOL), ('web', WEB)):
        if any(d in url for d in domains):
            return name
    return 'paper'


def get(url, limit=200_000_000, headers=None):
    request = urllib.request.Request(url, headers=headers or UA)
    with urllib.request.urlopen(request, timeout=40) as response:
        chunks, size = [], 0
        while size < limit and (chunk := response.read(1 << 20)):  # read(n) may return early on chunked replies
            chunks.append(chunk); size += len(chunk)
        return b''.join(chunks), response.geturl()


def get_json(url):
    return json.loads(get(url, headers={'User-Agent': 'sentinel-pulse-thesis-references (no email)'})[0])


# ------------------------------------------------------------------ bibliography

def ascii_slug(text, limit=60):
    text = unicodedata.normalize('NFKD', text.replace('đ', 'd').replace('Đ', 'D')).encode('ascii', 'ignore').decode()
    words = re.sub(r'[^a-z0-9]+', ' ', text.lower()).split()
    out = ''
    for w in words:
        if len(out) + len(w) + 1 > limit:
            break
        out = f'{out}-{w}' if out else w
    return out or 'untitled'


def surname(author):
    author = author.strip()
    if ',' in author:
        return author.split(',')[0].strip()
    return author.split()[-1] if author else 'unknown'


def arxiv_id(entry):
    text = ' '.join(filter(None, (entry['url'], entry.get('pdf_url'))))
    m = re.search(r'(?:arxiv\.org/(?:abs|pdf|html)/|ar5iv\.labs\.arxiv\.org/html/)(\d{4}\.\d{4,5})', text)
    return m.group(1) if m else None


def doi_of(entry, landing=None):
    if (entry.get('bib') or {}).get('doi'):
        return entry['bib']['doi']
    text = urllib.parse.unquote(' '.join(filter(None, (entry['url'], entry.get('pdf_url')))))
    m = re.search(r'(10\.\d{4,9}/[^\s?#]+)', text)
    if m and 'arxiv' not in m.group(1).lower():
        return re.sub(r'\.(full|pdf)$', '', m.group(1).rstrip('.'))
    return (landing or {}).get('doi') or None


def datacite_arxiv(aid):
    """arXiv metadata through its DataCite DOI 10.48550/arXiv.<id> (the arXiv API rate-limits bulk lookups)."""
    a = get_json(f'https://api.datacite.org/dois/10.48550/arxiv.{aid}')['data']['attributes']
    abstract = next((d['description'] for d in a.get('descriptions', []) if d.get('descriptionType') == 'Abstract'), None)
    return dict(title=' '.join(a['titles'][0]['title'].split()), authors=[c.get('name', '') for c in a.get('creators', [])],
                year=a.get('publicationYear'), venue='arXiv', arxiv=aid, abstract=' '.join(abstract.split()) if abstract else None,
                abstract_source=f'arXiv {aid} (DataCite)' if abstract else None)


def arxiv_meta(aid):
    try:
        return datacite_arxiv(aid)
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError):
        pass
    time.sleep(3)                                    # arXiv API etiquette: one request per 3 s
    xml = get(f'http://export.arxiv.org/api/query?id_list={aid}')[0].decode()
    entry = xml.split('<entry>', 1)[1] if '<entry>' in xml else ''
    title = re.search(r'<title>(.*?)</title>', entry, re.S)
    authors = re.findall(r'<name>(.*?)</name>', entry)
    year = re.search(r'<published>(\d{4})', entry)
    abstract = re.search(r'<summary>(.*?)</summary>', entry, re.S)
    if not title:
        return {}
    return dict(title=' '.join(title.group(1).split()), authors=authors, year=int(year.group(1)) if year else None,
                venue='arXiv', arxiv=aid, abstract=' '.join(abstract.group(1).split()) if abstract else None,
                abstract_source=f'arXiv {aid}')


def crossref_meta(doi):
    m = get_json(f'https://api.crossref.org/works/{urllib.parse.quote(doi)}')['message']
    parts = (m.get('issued') or m.get('published') or {}).get('date-parts') or [[None]]
    authors = [f"{a.get('given', '')} {a.get('family', '')}".strip() for a in m.get('author', [])] or \
              [e.get('name', '') for e in m.get('editor', [])]
    abstract = re.sub(r'<[^>]+>', ' ', m.get('abstract') or '')
    title = re.sub(r'<[^>]+>', '', (m.get('title') or [''])[0])
    return dict(title=' '.join(title.split()), authors=authors, year=parts[0][0],
                venue=(m.get('container-title') or [None])[0] or m.get('publisher'), doi=doi,
                abstract=' '.join(abstract.split()) or None, abstract_source=f'Crossref {doi}' if abstract.strip() else None)


def landing_meta(url):
    text = get(url, 5_000_000)[0].decode('utf-8', 'replace')
    tag = lambda n: [html.unescape(v).strip() for v in re.findall(
        r'<meta[^>]+(?:name|property)="' + n + r'"[^>]+content="([^"]*)"', text, re.I)]
    date = (tag('citation_publication_date') or tag('citation_date') or tag('citation_online_date') or [''])[0]
    abstract = (tag('citation_abstract') or tag('dc.description') or tag('og:description') or tag('description') or [None])[0]
    return dict(title=(tag('citation_title') or [''])[0], authors=tag('citation_author'),
                year=int(date[:4]) if date[:4].isdigit() else None,
                venue=(tag('citation_conference_title') or tag('citation_journal_title') or tag('citation_publisher') or [None])[0],
                doi=(tag('citation_doi') or [None])[0], pdf_url=(tag('citation_pdf_url') or [None])[0],
                abstract=abstract if abstract and len(abstract) > 120 else None,
                abstract_source=url if abstract and len(abstract) > 120 else None)


def openalex(doi):
    w = get_json(f'https://api.openalex.org/works/https://doi.org/{urllib.parse.quote(doi)}')
    pdfs = [loc.get('pdf_url') for loc in [w.get('best_oa_location') or {}] + (w.get('locations') or []) if loc and loc.get('pdf_url')]
    inv = w.get('abstract_inverted_index') or {}
    words = sorted((pos, word) for word, positions in inv.items() for pos in positions)
    return dict(pdfs=list(dict.fromkeys(pdfs)), abstract=' '.join(w for _, w in words) or None)


def bibliography(entry, log):
    bib, landing = {}, {}
    if 'doi.org' not in entry['url'] and '/pdf/' not in entry['url'] and not entry['url'].lower().endswith('.pdf'):
        try:
            landing = landing_meta(entry['url'])
        except (urllib.error.URLError, OSError, ValueError) as error:
            log.append(f"landing page: {str(error)[:80]}")
    aid, doi = arxiv_id(entry), None
    for source in ('arxiv', 'crossref'):
        try:
            if source == 'arxiv' and aid:
                bib = {**arxiv_meta(aid), **{k: v for k, v in bib.items() if v}}
            if source == 'crossref' and (doi := doi_of(entry, landing)):
                bib = {**crossref_meta(doi), **{k: v for k, v in bib.items() if v}}
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            log.append(f"{source}: {str(error)[:80]}")
    for k, v in landing.items():
        if v and not bib.get(k):
            bib[k] = v
    bib.update({k: v for k, v in (entry.get('bib') or {}).items() if v})
    if doi:
        bib['doi'] = doi
    return bib, landing


# ------------------------------------------------------------------ files

def page_text(pdf: Path, pages=2):
    if not shutil.which('pdftotext'):
        return None
    run = subprocess.run(['pdftotext', '-l', str(pages), str(pdf), '-'], capture_output=True, text=True)
    return run.stdout if run.returncode == 0 else ''


def title_score(text, title):
    """1.0 when the title's characters (letters and digits only) run contiguously near the start of the text, which
    survives small caps split by pdftotext ("N OD L INK"); else the share of title words found in order there."""
    if not title or not text:
        return 0.0
    flat = lambda s: re.sub(r'[^a-z0-9]', '', ascii_slug(s, 100000))
    head = ascii_slug(text, 100000)[:4000]
    if flat(title)[:40] and flat(title)[:40] in flat(head):
        return 1.0
    words, pos, found = [w for w in ascii_slug(title, 400).split('-') if len(w) >= 3], 0, 0
    page = head.split('-')
    for w in words:
        if w in page[pos:]:
            pos = page.index(w, pos) + 1; found += 1
    return found / len(words) if words else 0.0


def title_position(text, title):
    """Where the title starts in the text (letters and digits only); the paper's own title comes first on its first
    page, a title quoted in the abstract comes later."""
    flat = lambda s: re.sub(r'[^a-z0-9]', '', ascii_slug(s, 100000))
    pos = flat(ascii_slug(text, 100000)[:4000]).find(flat(title or '')[:40])
    return pos if pos >= 0 else 10 ** 6


def first_text(pdf: Path):
    text = page_text(pdf, 1) or ''
    return text if len(text) >= 400 else (page_text(pdf, 2) or '')       # cover sheets: read the next page too


def carries_title(pdf: Path, title):
    if not shutil.which('pdftotext') or not title:
        return True                                      # nothing to check against: accept
    return title_score(first_text(pdf), title) >= 0.9


def complete_pdf(data):
    return data.startswith(b'%PDF') and b'%%EOF' in data[-2048:]


def pdf_candidates(entry, landing, bib, log):
    out = []
    if entry.get('pdf_url') and entry['pdf_url'] != 'none':
        out.append(entry['pdf_url'])
    if landing.get('pdf_url'):
        out.append(urllib.parse.urljoin(entry['url'], landing['pdf_url']))
    url = entry['url']
    if (aid := bib.get('arxiv') or arxiv_id(entry)):
        out.append(f'https://arxiv.org/pdf/{aid}')
    if url.lower().split('?')[0].endswith('.pdf') or '/download/' in url:
        out.append(url)
    if 'proceedings.mlr.press' in url and url.endswith('.html'):
        stem = url[:-5]; out.append(f'{stem}/{stem.rsplit("/", 1)[1]}.pdf')
    if 'projecteuclid.org/' in url and url.endswith('.full'):
        out.append(url[:-5] + '.pdf')
    if 'scitepress.org/PublishedPapers/' in url:
        year, number = url.rstrip('/').split('/')[-2:]; out.append(f'https://www.scitepress.org/Papers/{year}/{number}/{number}.pdf')
    if bib.get('doi'):
        try:
            out += openalex(bib['doi'])['pdfs']
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            log.append(f"openalex: {str(error)[:80]}")
    return list(dict.fromkeys(out))


def html_candidates(entry, bib):
    out = [entry['html_url']] if entry.get('html_url') else []
    if 'mdpi.com/' in entry['url']:
        out.append(entry['url'].rstrip('/') + '/htm')
    if (bib.get('doi') or '').startswith('10.1145/'):
        out.append(f"https://dl.acm.org/doi/fullHtml/{bib['doi']}")
    if 'dl.acm.org/doi/fullHtml/' in entry['url']:
        out.append(entry['url'])
    if (aid := bib.get('arxiv')):
        out.append(f'https://arxiv.org/html/{aid}')
    return list(dict.fromkeys(out))


def chrome_print(url_or_file, out: Path, wait_ms=20000):
    if not CHROME:
        return False
    with tempfile.TemporaryDirectory() as profile:
        run = subprocess.run([CHROME, '--headless=new', '--disable-gpu', '--no-first-run', f'--user-data-dir={profile}',
                              '--no-pdf-header-footer', f'--virtual-time-budget={wait_ms}', f'--user-agent={UA["User-Agent"]}',
                              f'--print-to-pdf={out}', url_or_file], capture_output=True, timeout=180)
    return run.returncode == 0 and out.exists() and out.stat().st_size > 5000


def file_name(bib, entry, suffix=''):
    year = bib.get('year') or 'nd'
    first = ascii_slug(surname((bib.get('authors') or ['unknown'])[0]), 30)
    return f"{year}-{first}-{ascii_slug(bib.get('title') or entry['label'])}{suffix}.pdf"


def reconstruct(entry, bib, recon, contexts, out: Path):
    esc = html.escape
    rows = ''.join(f'<tr><th>{esc(k)}</th><td>{v}</td></tr>' for k, v in (
        ('Tiêu đề', esc(bib.get('title') or entry['label'])), ('Tác giả', esc(', '.join(bib.get('authors') or []) or 'không rõ')),
        ('Nơi công bố', esc(str(bib.get('venue') or 'không rõ'))), ('Năm', esc(str(bib.get('year') or 'không rõ'))),
        ('DOI', esc(bib.get('doi') or '—')), ('Trang gốc', f'<a href="{esc(entry["url"])}">{esc(entry["url"])}</a>')))
    abstract = recon.get('abstract') or bib.get('abstract')
    source = recon.get('abstract_source') or bib.get('abstract_source')
    points = ''.join(f'<li>{esc(p)}</li>' for p in recon.get('reading', []))
    ctx = ''.join(f'<li><b>{esc(f)}</b>: {esc(t)}</li>' for f, t in contexts[:8])
    page = f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 18mm 16mm; }}
body {{ font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #111; }}
.banner {{ border: 2px solid #b00; color: #b00; padding: 8px 10px; font-weight: bold; margin-bottom: 14px; }}
h1 {{ font-size: 15pt; margin: 6px 0 10px; }} h2 {{ font-size: 12pt; margin: 16px 0 6px; border-bottom: 1px solid #999; }}
table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #bbb; padding: 4px 6px; text-align: left; vertical-align: top; }}
th {{ background: #f2f2f2; width: 22%; }} .src {{ color: #555; font-size: 9pt; }}
footer {{ position: fixed; bottom: -10mm; left: 0; right: 0; font-size: 8pt; color: #b00; text-align: center; }}
</style></head><body>
<footer>BẢN DỰNG LẠI từ thông tin công khai trên web — không phải bản gốc của bài báo; không trích dẫn nội dung từ bản này như lời của tác giả.</footer>
<div class="banner">BẢN DỰNG LẠI — KHÔNG PHẢI BẢN GỐC. Không tìm được bản PDF hay toàn văn công khai của bài này.
Tài liệu này gom thông tin thư mục, tóm tắt công khai (nguyên văn, có nguồn) và phần đọc hiểu của người dựng ({esc(recon.get('compiled_by', 'Claude, cho đồ án Sentinel Pulse'))}, {esc(recon.get('compiled_at', ''))}).
Khi trích dẫn, dùng thông tin thư mục và đối chiếu với bản gốc.</div>
<h1>{esc(bib.get('title') or entry['label'])}</h1>
<h2>Thông tin thư mục</h2><table>{rows}</table>
<h2>Tóm tắt công khai của tác giả</h2>
{f'<p>{esc(abstract)}</p><p class="src">Nguồn: {esc(source or "")}</p>' if abstract else '<p>Không có tóm tắt công khai.</p>'}
<h2>Nội dung chính theo hiểu biết của người dựng</h2>
<p class="src">Diễn giải, không phải nguyên văn; dựa trên tóm tắt và trang công bố{', ' + esc(recon['basis']) if recon.get('basis') else ''}.</p>
<ul>{points or '<li>Chưa có.</li>'}</ul>
<h2>Đồ án Sentinel Pulse dùng bài này ở đâu</h2><ul>{ctx or '<li>(không tìm thấy câu trích trong báo cáo)</li>'}</ul>
<h2>Cách lấy bản gốc</h2><p>{esc(recon.get('how_to_get', 'Qua trang gốc ở trên (thư viện trường hoặc liên hệ tác giả).'))}</p>
</body></html>"""
    with tempfile.TemporaryDirectory() as tmp:
        page_file = Path(tmp) / 'page.html'
        page_file.write_text(page)
        return chrome_print(page_file.as_uri(), out, wait_ms=2000)


def contexts_for(entry, repo: Path, terms=()):
    out = []
    keys = [entry['url']] + [w for w in [entry['label'][:40]] if len(w) > 8] + list(terms)
    for report in REPORTS:
        for line in (repo / report).read_text().splitlines():
            if any(k in line for k in keys):
                plain = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', line).strip(' |-*')
                out.append((report, plain[:400]))
    return out


def register(path: Path, how, **extra):
    data = path.read_bytes()
    return dict(status='downloaded' if how in ('script', 'kept', 'placed_by_hand') else how, how=how,
                file=f'pdf/{path.name}', bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **extra)


def obtain(entry, bib, landing, pdf_dir: Path, recon, repo, log):
    target = pdf_dir / file_name(bib, entry)
    if target.exists() and not entry.get('old_file'):        # placed by hand under the expected name
        return register(target, 'placed_by_hand')
    if entry.get('old_file') and (pdf_dir.parent / entry['old_file']).exists():
        path = pdf_dir.parent / entry['old_file']
        suffix = '--web' if path.name.endswith('--web.pdf') else '--reconstructed' if path.name.endswith('--reconstructed.pdf') else ''
        dest = pdf_dir / file_name(bib, entry, suffix)
        if path != dest:
            path.rename(dest)
        status = {'--web': 'printed_from_web', '--reconstructed': 'reconstructed'}.get(suffix, 'downloaded')
        return dict(register(dest, 'kept'), status=status)
    if entry.get('pdf_url') != 'none':
        for url in pdf_candidates(entry, landing, bib, log):
            try:
                data, final = get(url)
            except (urllib.error.URLError, OSError, ValueError) as error:
                log.append(f'{url}: {str(error)[:80]}'); continue
            if not complete_pdf(data):
                log.append(f'{url}: not a complete PDF (paywall, login or bot check)'); continue
            if target.exists():
                raise RuntimeError(f'refusing to overwrite {target.name}')
            target.write_bytes(data)
            if not carries_title(target, bib.get('title')):
                target.unlink(); log.append(f'{url}: PDF does not carry the title'); continue
            return register(target, 'script', pdf_url=final)
    web = pdf_dir / file_name(bib, entry, '--web')
    for url in html_candidates(entry, bib):
        if chrome_print(url, web) and carries_title(web, bib.get('title')) and len(page_text(web, 50) or '') > 8000:
            return register(web, 'printed_from_web', html_url=url)
        log.append(f'{url}: web print missing, blocked or without the full text')
        web.unlink(missing_ok=True)
    if recon:
        out = pdf_dir / file_name(bib, entry, '--reconstructed')
        if reconstruct(entry, bib, recon, contexts_for(entry, repo, recon.get('context_terms', ())), out):
            return register(out, 'reconstructed')
    return dict(status='not_downloaded', tried=log[-6:] or ['no public PDF or full text found'])


def adopt(papers, pdf_dir: Path, manual):
    """Match every PDF in the folder (ours, renamed or not, and copies placed by hand under any name) to a paper by
    its title near the start of the text; one file per paper, best match first. ``manual`` (references/
    manual_matches.json) pairs files that carry no text layer (old scans) with their paper by hand. Byte-identical
    extra copies are removed."""
    files = {f: first_text(f) for f in sorted(pdf_dir.glob('*.pdf'))}
    chosen, used = {}, set()
    for name, url in manual.items():
        if (pdf_dir / name).exists() and url in papers:
            chosen[url] = pdf_dir / name; used.add(pdf_dir / name)
    pairs = sorted(((-title_score(t, e['bib'].get('title')), title_position(t, e['bib'].get('title')), f.name, f, url)
                    for f, t in files.items() for url, e in papers.items() if e['bib'].get('title')))
    for neg, _, _, f, url in pairs:
        score = -neg
        if score < 0.9 or url in chosen or f in used:
            continue
        chosen[url] = f; used.add(f)
    keep = {hashlib.sha256(f.read_bytes()).hexdigest() for f in chosen.values()}
    removed = []
    for f in files:
        if f not in used and hashlib.sha256(f.read_bytes()).hexdigest() in keep:
            f.unlink(); removed.append(f.name)
    return chosen, removed


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--refresh-bib', action='store_true', help='query bibliographic sources again')
    a = p.parse_args()
    ref = a.repo / 'references'; pdf_dir = ref / 'pdf'; pdf_dir.mkdir(parents=True, exist_ok=True)
    recons = json.loads((ref / 'reconstructions.json').read_text()) if (ref / 'reconstructions.json').exists() else {}
    entries = {}
    for report in REPORTS:
        for label, url in LINK.findall((a.repo / report).read_text()):
            e = entries.setdefault(url, dict(label=label, url=url, cited_in=[]))
            if report not in e['cited_in']:
                e['cited_in'].append(report)
    for extra in json.loads((ref / 'extra.json').read_text()):
        e = entries.setdefault(extra['url'], dict(label=extra['title'], url=extra['url'], cited_in=[]))
        e.update({k: v for k, v in extra.items() if k not in ('title', 'cited_in')})
        e['cited_in'] = sorted(set(e['cited_in']) | set(extra.get('cited_in', [])))
    for url, e in list(entries.items()):                 # two links to one paper: keep the target, merge citations
        if e.get('alias_of') and e['alias_of'] in entries:
            target = entries[e['alias_of']]
            target['cited_in'] = sorted(set(target['cited_in']) | set(e['cited_in']))
            target.setdefault('also_cited_as', []).append(url)
            del entries[url]
    old = {e['url']: e for e in json.loads((ref / 'catalog.json').read_text())} if (ref / 'catalog.json').exists() else {}
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    papers, landings, logs = {}, {}, {}
    for url, e in sorted(entries.items(), key=lambda kv: kv[1]['label'].lower()):   # 1. bibliography
        e.setdefault('type', kind(url))
        if e['type'] != 'paper':
            e['status'] = 'link_only'; continue
        prev, log = old.get(url, {}), logs.setdefault(url, [])
        override = dict(e.get('bib') or {})                # hand-checked fields always win
        bib = prev.get('bib') if not a.refresh_bib else None
        if not bib or not bib.get('title') or not bib.get('year') or not bib.get('authors'):
            bib, landings[url] = bibliography(e, log)
        bib = {**bib, **{k: v for k, v in override.items() if v}}
        e['bib'] = {k: v for k, v in bib.items() if k != 'pdf_url'}
        papers[url] = e
        print(f"bib  {e['bib'].get('year')} {(e['bib'].get('authors') or ['?'])[0][:20]:20s} {e['bib'].get('title', '')[:70]}", flush=True)
    manual = json.loads((ref / 'manual_matches.json').read_text()) if (ref / 'manual_matches.json').exists() else {}
    chosen, removed = adopt(papers, pdf_dir, {k: v for k, v in manual.items() if not k.startswith('_')})   # 2. files in the folder
    for url, f in list(chosen.items()):              # park chosen files under unique names: no rename overwrites another
        parked = f.with_name(f'.parked-{hashlib.sha256(url.encode()).hexdigest()[:12]}-{f.name}')
        f.rename(parked); chosen[url] = parked
    for url, e in papers.items():                                                  # 3. rename, or fetch / print / rebuild
        prev, log = old.get(url, {}), logs[url]
        f = chosen.get(url)
        suffix = '--web' if f and f.name.endswith('--web.pdf') else '--reconstructed' if f and f.name.endswith('--reconstructed.pdf') else ''
        if f and suffix == '--reconstructed' and url in recons and recons[url].get('compiled_at') != prev.get('reconstructed_from'):
            f.unlink(); f = None                                                       # reconstruction text changed: rebuild
        if f:
            dest = pdf_dir / file_name(e['bib'], e, suffix)
            if dest.exists() and dest != f:
                raise RuntimeError(f'refusing to overwrite {dest.name} with {f.name}')
            f.rename(dest)
            status = {'--web': 'printed_from_web', '--reconstructed': 'reconstructed'}.get(suffix, 'downloaded')
            how = prev['how'] if prev.get('how') not in (None, 'kept') else 'placed_by_hand'   # origin survives later runs
            e.update(register(dest, how), status=status, fetched_at=prev.get('fetched_at') or now)
            for k in ('pdf_url', 'html_url', 'reconstructed_from'):
                if prev.get(k):
                    e.setdefault(k, prev[k])
        else:
            e.update(obtain(e, e['bib'], landings.get(url, {}), pdf_dir, recons.get(url), a.repo, log), fetched_at=now)
            if e.get('status') == 'reconstructed':
                e['reconstructed_from'] = recons[url].get('compiled_at')
        print(f"{e['status']:17s} {e.get('how', ''):14s} {e.get('file', e['label'])[:90]}", flush=True)
    catalog = sorted(entries.values(), key=lambda e: e['label'].lower())
    for e in catalog:
        e.pop('old_file', None)
    print('removed identical extra copies:', removed)
    owned = {e.get('file') for e in catalog}
    print('PDF files matching no paper (left in place):', sorted(f'pdf/{f.name}' for f in pdf_dir.glob('*.pdf') if f'pdf/{f.name}' not in owned))
    (ref / 'catalog.json').write_text(json.dumps(catalog, ensure_ascii=False, indent=1) + '\n')
    counts = {}
    for e in catalog:
        counts[(e['type'], e['status'])] = counts.get((e['type'], e['status']), 0) + 1
    print(counts)


if __name__ == '__main__':
    main()
