"""rich_token_cache.py: two-level paths, connect detail, process context."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
import rich_token_cache as rc  # noqa: E402


def test_port_class():
    assert [rc.port_class(p) for p in (80, 3306, 50000)] == ['wk', 'reg', 'eph']


def test_connect_detail_from_lidds_args():
    f = rc.fact('path2', 'connect', 'res=0 fd=3(<4t>172.17.0.2:40000->172.17.0.3:3306)')
    assert f == ('connect', 'o', '4t:reg')


def test_exec_resets_history_and_pushes_the_program():
    lines = ['1000 0 1 sh 7 read < res=5 data=',
             '1001 0 1 cat 7 execve < res=0 exe=/bin/cat',   # sysdig names the new program at the execve exit
             '1002 0 1 cat 7 read < res=5 data=']
    vocab = {}
    rows = rc.recording_rows('exec', lines, vocab, 4)
    names = {i: f for f, i in vocab.items()}
    last = [k for k in rows if names.get(k[-1], ('',))[0] == 'read' and k[-2] != -1]
    assert last and names[last[0][-2]] == ('comm', 'o', 'cat')
