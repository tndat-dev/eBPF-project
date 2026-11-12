"""Deck of the 13/11/2026 meeting, built on the owner's 06/11 deck (theme, layout TIEU_DE, table and bullet styles)."""
import copy
import math
import sys
from xml.sax.saxutils import escape

from lxml import etree
from pptx import Presentation
from pptx.util import Emu

SRC, OUT = sys.argv[1], sys.argv[2]
A = 'http://schemas.openxmlformats.org/drawingml/2006/main'
P = 'http://schemas.openxmlformats.org/presentationml/2006/main'
NS = f'xmlns:a="{A}" xmlns:p="{P}"'
LEFT, WIDTH, TOP = 813960, 10880280, 1097280
EMU_IN = 914400


def rpr(size, bold):
    return (f'<a:rPr lang="vi-VN" sz="{int(size * 100)}" b="{1 if bold else 0}" u="none" strike="noStrike">'
            f'<a:solidFill><a:srgbClr val="000000"/></a:solidFill><a:effectLst/><a:uFillTx/>'
            f'<a:latin typeface="Arial"/><a:ea typeface="Arial"/></a:rPr>')


def cell(text, size, header):
    line = lambda c: f'<a:ln{c} w="9360"><a:solidFill><a:srgbClr val="BFBFBF"/></a:solidFill><a:prstDash val="solid"/></a:ln{c}>'
    fill = '<a:solidFill><a:srgbClr val="F2F2F2"/></a:solidFill>' if header else '<a:noFill/>'
    runs = ''.join(f'<a:r>{rpr(size, header or b)}<a:t>{escape(t)}</a:t></a:r>' for t, b in split_bold(text))
    return (f'<a:tc><a:txBody><a:bodyPr lIns="54720" tIns="36360" rIns="54720" bIns="36360" anchor="ctr"><a:noAutofit/></a:bodyPr>'
            f'<a:p><a:pPr defTabSz="914400"><a:lnSpc><a:spcPct val="100000"/></a:lnSpc></a:pPr>{runs}'
            f'<a:endParaRPr lang="vi-VN" sz="{int(size * 100)}"/></a:p></a:txBody>'
            f'<a:tcPr anchor="ctr" marL="54720" marR="54720" marT="36360" marB="36360">{line("L")}{line("R")}{line("T")}{line("B")}{fill}</a:tcPr></a:tc>')


def split_bold(text):
    """'**x** y' -> [('x', True), (' y', False)]."""
    parts, out = text.split('**'), []
    for i, t in enumerate(parts):
        if t:
            out.append((t, i % 2 == 1))
    return out or [('', False)]


def lines_of(text, width_emu, size):
    per_line = max(4, int(width_emu / EMU_IN * 7.6 * 16 / size))
    return sum(max(1, math.ceil(len(chunk) / per_line)) for chunk in text.replace('**', '').split('\n'))


def table(rows, widths, size, top):
    total = sum(widths)
    cols = [int(WIDTH * w / total) for w in widths]
    heights = []
    for r in rows:
        n = max(lines_of(t, c - 109440, size) for t, c in zip(r, cols))
        heights.append(int(n * size * 1.22 * 12700 + 72720 + 20000))
    grid = ''.join(f'<a:gridCol w="{c}"/>' for c in cols)
    trs = ''.join(f'<a:tr h="{h}">' + ''.join(cell(t, size, i == 0) for t in r) + '</a:tr>' for i, (r, h) in enumerate(zip(rows, heights)))
    xml = (f'<p:graphicFrame {NS}><p:nvGraphicFramePr><p:cNvPr id="100" name="Table"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>'
           f'<p:xfrm><a:off x="{LEFT}" y="{top}"/><a:ext cx="{WIDTH}" cy="{sum(heights)}"/></p:xfrm>'
           f'<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table"><a:tbl><a:tblPr/>'
           f'<a:tblGrid>{grid}</a:tblGrid>{trs}</a:tbl></a:graphicData></a:graphic></p:graphicFrame>')
    return etree.fromstring(xml), sum(heights)


def bullets(items, size, top, height):
    paras = ''
    for it in items:
        runs = ''.join(f'<a:r>{rpr(size, b)}<a:t>{escape(t)}</a:t></a:r>' for t, b in split_bold(it))
        paras += (f'<a:p><a:pPr marL="228600" indent="-228600" defTabSz="914400"><a:lnSpc><a:spcPct val="100000"/></a:lnSpc>'
                  f'<a:spcAft><a:spcPts val="{int(size * 40)}"/></a:spcAft><a:buClr><a:srgbClr val="000000"/></a:buClr>'
                  f'<a:buFont typeface="Symbol" charset="2"/><a:buChar char="&#61623;"/></a:pPr>{runs}</a:p>')
    xml = (f'<p:sp {NS}><p:nvSpPr><p:cNvPr id="101" name="Text"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
           f'<p:spPr><a:xfrm><a:off x="{LEFT}" y="{top}"/><a:ext cx="{WIDTH}" cy="{height}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
           f'<a:noFill/></p:spPr><p:txBody><a:bodyPr wrap="square" lIns="0" tIns="0" rIns="0" bIns="0" anchor="t"><a:noAutofit/></a:bodyPr>'
           f'{paras}</p:txBody></p:sp>')
    return etree.fromstring(xml)


def bullets_height(items, size):
    return sum(lines_of(t, WIDTH - 228600, size) * size * 1.2 * 12700 + size * 40 * 127 for t in items)


prs = Presentation(SRC)
template = prs.slides[1]
number = next(sh for sh in template.shapes if sh.is_placeholder and sh.placeholder_format.idx == 6)
number_xml = copy.deepcopy(number._element)
layout = prs.slide_layouts.get_by_name('TIEU_DE')
sldIdLst = prs.slides._sldIdLst
for sldId in list(sldIdLst):
    prs.part.drop_rel(sldId.rId)
    sldIdLst.remove(sldId)

FIT = 6858000 - 420000


def slide(title, tbl=None, widths=None, notes=(), size=15, note_size=15, img=None):
    s = prs.slides.add_slide(layout)
    for ph in list(s.placeholders):
        if ph.placeholder_format.idx != 0:
            ph._element.getparent().remove(ph._element)
    t = s.shapes.title
    t.text = title
    for r in t.text_frame.paragraphs[0].runs:
        r.font.name, r.font.size, r.font.bold = 'Arial', Emu(22 * 12700), True
    top = TOP
    tree = s.shapes._spTree
    if tbl:
        el, h = table(tbl, widths, size, top)
        tree.append(el)
        top += h + 180000
    if img:
        from PIL import Image as _I
        w0, h0 = _I.open(img).size
        room = FIT - top - (bullets_height(notes, note_size) + 120000 if notes else 0)
        w = min(WIDTH, int(room * w0 / h0))
        h = int(w * h0 / w0)
        s.shapes.add_picture(img, LEFT + (WIDTH - w) // 2, top, Emu(w), Emu(h))
        top += h + 120000
    if notes:
        while top + bullets_height(notes, note_size) > FIT and note_size > 11:
            note_size -= 1
        tree.append(bullets(list(notes), note_size, top, max(300000, FIT - top)))
    tree.append(copy.deepcopy(number_xml))
    if tbl and top > FIT + 200000:
        print('WARNING overflow:', title, top)
    return s


exec(open(sys.argv[3]).read())
prs.save(OUT)
print('slides', len(prs.slides))
