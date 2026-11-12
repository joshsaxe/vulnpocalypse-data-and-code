"""Which vendor attributes go with mass exploitation? The tests behind the sentence in the post's methodology section:
"I also tested bug bounties, the Secure by Design pledge, company age and R&D spending and found no detectable effect."

Population: vulnerabilities of the class (no login, no click, internet-facing enterprise software) in products that
customers patch, published 2019-2025, from the vendors in the 86-vendor panel (data/vendor_panel.csv).
Vulnerabilities cluster within vendors, so the chance figure comes from shuffling each attribute across vendors.

Run:  python src/maturity.py     -> output/maturity.json
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import collections, random, statistics
from study import R, PANEL, cls, mass, write_json


def num(x):
    try:
        return float(x)
    except Exception:
        return None


def population():
    return [(r['pv'], r) for r in R if '2019-01-01' <= r['pub'] <= '2025-12-31' and cls(r) and r['upd'] == 'customer' and r['pv'] in PANEL]


def test(rows, attr, reps=4000, seed=5):
    """rows: [(vendor, vulnerability)], attr: vendor -> True / False / None. Counts and a vendor-clustered permutation p-value."""
    byv = collections.defaultdict(lambda: [0, 0])
    for v, r in rows:
        if attr(v) is None:
            continue
        byv[v][0] += 1
        byv[v][1] += mass(r)
    vs = sorted(byv)
    lab = [attr(v) for v in vs]

    def stat(lab):
        n1 = sum(byv[v][0] for v, l in zip(vs, lab) if l); m1 = sum(byv[v][1] for v, l in zip(vs, lab) if l)
        n0 = sum(byv[v][0] for v, l in zip(vs, lab) if not l); m0 = sum(byv[v][1] for v, l in zip(vs, lab) if not l)
        return n1, m1, n0, m0
    n1, m1, n0, m0 = stat(lab)
    if not n1 or not n0:
        return None
    d = m1 / n1 - m0 / n0
    rng = random.Random(seed)
    hits = 0
    for _ in range(reps):
        l2 = lab[:]
        rng.shuffle(l2)
        a1, b1, a0, b0 = stat(l2)
        if a1 and a0 and abs(b1 / a1 - b0 / a0) >= abs(d) - 1e-12:
            hits += 1
    return dict(with_n=n1, with_mass=m1, with_vendors=sum(lab), without_n=n0, without_mass=m0, without_vendors=len(lab) - sum(lab), p=(hits + 1) / (reps + 1))


def flag(col, yes='1.0', no='0.0'):
    return lambda v: True if PANEL[v][col] == yes else (False if PANEL[v][col] == no else None)


def above_median(col, rows):
    vals = {v: num(PANEL[v][col]) for v in PANEL}
    med = statistics.median([vals[v] for v in set(v for v, _ in rows) if vals[v] is not None])
    return (lambda v: None if vals[v] is None else vals[v] > med), med


def run():
    rows = population()
    out = collections.OrderedDict()
    out['population'] = dict(vulnerabilities=len(rows), vendors=len(set(v for v, _ in rows)), mass=sum(mass(r) for _, r in rows))
    out['public paid bug bounty'] = test(rows, flag('bounty', yes='2.0', no='0.0'))
    out['signed the Secure by Design pledge'] = test(rows, flag('pledge'))
    out['private-equity owned'] = test(rows, flag('pe'))
    out['flagship product acquired, not built'] = test(rows, flag('acquired'))
    for col, name in (('founded', 'company founded after the median year'), ('codebase_year', 'flagship codebase newer than the median'), ('rnd_pct', 'R&D share of revenue above the median'),
                      ('employees', 'more employees than the median'), ('revenue', 'revenue above the median')):
        f, med = above_median(col, rows)
        t = test(rows, f)
        t['median'] = med
        out[name] = t
    return out


if __name__ == '__main__':
    res = run()
    write_json('maturity.json', res)
    p = res['population']
    print(f"Population: {p['vulnerabilities']} vulnerabilities at {p['vendors']} vendors, {p['mass']} mass-exploited")
    for k, t in res.items():
        if k == 'population' or not t:
            continue
        m = f" (median {t['median']:g})" if 'median' in t else ''
        print(f"  {k + m:52s} with: {t['with_mass']:3d} of {t['with_n']:4d} ({100 * t['with_mass'] / t['with_n']:4.1f}%, {t['with_vendors']} vendors) | "
              f"without: {t['without_mass']:3d} of {t['without_n']:4d} ({100 * t['without_mass'] / t['without_n']:4.1f}%, {t['without_vendors']} vendors) | chance {100 * t['p']:.1f}%")
