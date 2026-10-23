import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('fetch_references', Path(__file__).parents[1]/'scripts/fetch_references.py')
fr = importlib.util.module_from_spec(spec); spec.loader.exec_module(fr)

EGAI = ('e-GAI: e-value-based Generalized α-Investing for Online False Discovery Rate Control\nYifan Zhang ...\n'
        'Abstract. Building on FDR control for online anomaly detection (Kronert et al.), we ...')
KRONERT = 'FDR control for Online Anomaly Detection\nEtienne Krönert, Alain Celisse ...\nAbstract ...'


def test_title_matching_survives_small_caps_and_rejects_generic_words():
    assert fr.title_score('N OD L INK: An Online System for Fine-Grained APT Attack Detection and Investigation',
                          'NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation') == 1.0
    benchmarking = 'Benchmarking Anomaly Detection Algorithms: Deep Learning and Beyond ... real-world ... random'
    assert fr.title_score(benchmarking, 'Algorithmic Learning in a Random World') < 0.9


def test_a_title_quoted_in_an_abstract_does_not_win_the_file(tmp_path, monkeypatch):
    (tmp_path/'a.pdf').write_bytes(b'egai'); (tmp_path/'b.pdf').write_bytes(b'kronert')
    monkeypatch.setattr(fr, 'first_text', lambda f: {'a.pdf': EGAI, 'b.pdf': KRONERT}[f.name])
    papers = {'egai': dict(bib=dict(title='e-GAI: e-value-based Generalized α-Investing for Online False Discovery Rate Control')),
              'kronert': dict(bib=dict(title='FDR control for Online Anomaly Detection'))}
    assert fr.title_position(EGAI, papers['kronert']['bib']['title']) > fr.title_position(KRONERT, papers['kronert']['bib']['title'])
    chosen, removed = fr.adopt(papers, tmp_path, {})
    assert {u: f.name for u, f in chosen.items()} == {'egai': 'a.pdf', 'kronert': 'b.pdf'} and removed == []


def test_identical_extra_copy_is_removed_and_manual_matches_win(tmp_path, monkeypatch):
    for name, body in (('scan.pdf', b'scan'), ('k1.pdf', b'k'), ('k2.pdf', b'k')):
        (tmp_path/name).write_bytes(body)
    monkeypatch.setattr(fr, 'first_text', lambda f: {'scan.pdf': 'JSTOR cover', 'k1.pdf': KRONERT, 'k2.pdf': KRONERT}[f.name])
    papers = {'lorden': dict(bib=dict(title='Procedures for Reacting to a Change in Distribution')),
              'kronert': dict(bib=dict(title='FDR control for Online Anomaly Detection'))}
    chosen, removed = fr.adopt(papers, tmp_path, {'scan.pdf': 'lorden'})
    assert chosen['lorden'].name == 'scan.pdf' and chosen['kronert'].name in ('k1.pdf', 'k2.pdf')
    assert len(removed) == 1 and sorted(p.name for p in tmp_path.iterdir()) in (['k1.pdf', 'scan.pdf'], ['k2.pdf', 'scan.pdf'])
