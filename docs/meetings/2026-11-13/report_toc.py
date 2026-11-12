"""Fill the static TOC page numbers of x/word/document.xml from a PDF render (pages of the body headings)."""
import os, re, subprocess, sys, tempfile
SOFFICE = sys.argv[1]
def build():
    if os.path.exists('out.docx'): os.remove('out.docx')
    subprocess.run('cd x && zip -q -X -D -r ../out.docx .', shell=True, check=True)
def pages():
    with tempfile.TemporaryDirectory() as t:
        subprocess.run([sys.executable, SOFFICE, '--headless', '--convert-to', 'pdf', '--outdir', t, 'out.docx'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pdf = os.path.join(t, 'out.pdf')
        n = int(re.search(r'Pages:\s+(\d+)', subprocess.run(['pdfinfo', pdf], capture_output=True, text=True).stdout).group(1))
        return [subprocess.run(['pdftotext', '-f', str(i), '-l', str(i), '-layout', pdf, '-'], capture_output=True, text=True).stdout for i in range(1, n + 1)]
norm = lambda s: re.sub(r'\s+', ' ', s).strip()
for rnd in range(3):
    build(); texts = pages()
    d = open('x/word/document.xml', encoding='utf-8').read()
    changed, missing = 0, []
    def fix(m):
        global changed
        p = m.group(0)
        if 'w:leader="dot"' not in p: return p
        title = re.findall(r'<w:t[^>]*>([^<]*)</w:t>', p)[0]
        page = next((i + 1 for i, t in enumerate(texts) if '.......' not in t and norm(title) in norm(t)), None)
        if page is None: missing.append(title); return p
        new = re.sub(r'(<w:tab/><w:t>)\d+(</w:t>)', rf'\g<1>{page}\g<2>', p)
        if new != p: changed += 1
        return new
    d = re.sub(r'<w:p>(?:(?!</w:p>).)*?w:leader="dot".*?</w:p>', fix, d, flags=re.S)
    open('x/word/document.xml', 'w', encoding='utf-8').write(d)
    print('round', rnd, 'changed', changed, 'missing', missing, 'pages', len(texts))
    if not changed: break
build()
