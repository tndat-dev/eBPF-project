import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('headline_numbers', ROOT/'scripts'/'audit'/'headline_numbers.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_every_headline_number_matches_its_receipt():
    rows, failures = audit.run()
    assert failures == 0, [r['id'] for r in rows if not r['ok']]
    assert len(rows) >= 30


def test_a_number_edited_in_a_report_fails_the_audit():
    def read(doc):
        text = (ROOT/doc).read_text()
        return text.replace('**98,7%** (306/310)', '**98,8%** (306/310)') if doc == 'SENTINEL_PULSE_STATUS.md' else text
    rows, failures = audit.run(read)
    assert {r['id'] for r in rows if not r['ok']} == {'final-recall', 'final-precision'}      # both rows print 98,7% (306/310)
