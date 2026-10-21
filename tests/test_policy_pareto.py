import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('policy_pareto', Path(__file__).parents[1]/'scripts'/'analysis'/'policy_pareto.py')
pp = importlib.util.module_from_spec(spec); spec.loader.exec_module(pp)


def row(burden, recall, control, p95):
    return dict(burden=burden, recall=recall, control=control, p95=p95)


def test_frontier_and_dominance():
    rows = {'a': row(6, .99, .04, 1.9), 'b': row(4, .99, .03, 2.6), 'c': row(7, .99, .05, 2.0), 'd': row(4, .99, .03, 2.6)}
    assert pp.dominated(rows['c'], rows['a']) and not pp.dominated(rows['a'], rows['b'])
    assert pp.frontier(rows) == ['a', 'b', 'd']          # ties do not dominate each other


def test_wilson_and_clustered_bootstrap():
    lo, hi = pp.wilson(311, 313)
    assert lo < 311 / 313 < hi <= 1
    hours = {'w1': 10.0, 'w2': 10.0}
    episodes = {'x': {'w1': 10, 'w2': 30}, 'y': {'w1': 10, 'w2': 30}}
    ci, diff = pp.burden_bootstrap(episodes, hours, ['x', 'y'], reps=200)
    assert ci['x'][0] >= 1.0 and ci['x'][1] <= 3.0 and diff['y'] == [0.0, 0.0]
