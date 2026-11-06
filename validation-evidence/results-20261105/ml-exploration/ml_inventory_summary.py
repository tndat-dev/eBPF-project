"""DEVELOPMENT only: for each (syscall, kind), in how many attack and normal recordings it appears in something the
training never had (unseen token, or last token of an unseen 4-gram); kind err/open/size/name. Input: the outputs of
lidds_ml_token_inventory.py. Also the attack recordings each exit kind is needed for: those whose novel items are
all of that kind (removing it leaves nothing new)."""
import glob, json, sys
from collections import Counter, defaultdict
A = sys.argv[1]
att, nor, only = Counter(), Counter(), Counter(); NA = NN = 0; per_scn = defaultdict(Counter)
for f in sorted(glob.glob(A + '/*.json')):
    d = json.load(open(f)); s = d['scenario']
    for name, r in d['recordings'].items():
        keys = set(r['novel'])
        if r['split'] == 'test-normal':
            NN += 1; nor.update(keys)
        else:
            NA += 1; att.update(keys)
            kinds = {k.split('|')[1] for k in keys}
            if len(kinds) == 1: only[next(iter(kinds))] += 1
            for k in keys:
                if k.split('|')[1] != 'name': per_scn[s][k] += 1
print(f'{NA} attack, {NN} normal development recordings')
print('attack recordings whose novel items are of one kind only:', dict(only))
print('\n(syscall|kind): attack recordings, normal recordings (top 40 by attack count, excluding name)')
for k, n in sorted(att.items(), key=lambda kv: -kv[1]):
    if k.endswith('|name'): continue
    print(f'  {k:28s} {n:4d} ({100*n/NA:5.1f}%)  normal {nor[k]:4d} ({100*nor[k]/NN:5.1f}%)')
    if n < 15: break
by_sys = Counter()
for k, n in att.items():
    sc, kind = k.split('|')
    if kind in ('err', 'size'): by_sys[sc] += n
print('\nsyscalls whose exit (err or size) appears most in attack novelty:', by_sys.most_common(20))
print('\nper scenario, top exit items:')
for s, c in sorted(per_scn.items()):
    print(f'  {s:22s}', ', '.join(f'{k} {n}' for k, n in c.most_common(5)))
