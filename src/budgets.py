"""Chart 6's estimates of yearly application-security spending at five hyperscalers.

No company publishes this number. Each estimate combines two routes, every input given as a 90% range and
treated as lognormal (so the middle of a range is its geometric mean):

  A. engineers x share working on application security x cost per head x overhead
  B. software-development spending x share spent on application security

The two are pooled in log space, weighted by their precision (a Bayesian update of A by B), and the pooled
spread is widened by half because both routes rest on the same "one to two percent" judgment.
Inputs: data/budget_inputs.csv (company figures, from filings) and data/budget_assumptions.csv (the judgments).

Run:  python src/budgets.py
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv, math
from study import DATA, write_json

Z = 1.645          # a 90% range is +/- 1.645 standard deviations


def ln_range(lo, hi):
    """(mean, sd) of the log of a quantity whose 90% range is lo..hi."""
    return (math.log(lo) + math.log(hi)) / 2, (math.log(hi) - math.log(lo)) / (2 * Z)


def q(mu, sd):
    return [math.exp(mu - Z * sd), math.exp(mu), math.exp(mu + Z * sd)]


def estimate():
    A = {r['parameter']: (float(r['low']), float(r['high'])) for r in csv.DictReader(open(DATA / 'budget_assumptions.csv', encoding='utf-8'))}
    out = {}
    for r in csv.DictReader(open(DATA / 'budget_inputs.csv', encoding='utf-8')):
        parts_a = [ln_range(float(r['engineers_low']), float(r['engineers_high'])), ln_range(*A['appsec_staff_per_engineer']),
                   ln_range(*A['cost_per_head_usd']), ln_range(*A['overhead_multiplier'])]
        ma = sum(m for m, _ in parts_a) - math.log(1e9); sa = math.sqrt(sum(s * s for _, s in parts_a))
        parts_b = [ln_range(float(r['rd_low_bn']), float(r['rd_high_bn'])), ln_range(*A['appsec_share_of_rd'])]
        mb = sum(m for m, _ in parts_b); sb = math.sqrt(sum(s * s for _, s in parts_b))
        w = (1 / sa ** 2) / (1 / sa ** 2 + 1 / sb ** 2)
        m = w * ma + (1 - w) * mb
        s = math.sqrt(1 / (1 / sa ** 2 + 1 / sb ** 2)) * 1.5
        out[r['company']] = dict(label=r['label'], engineers_route=q(ma, sa), rd_route=q(mb, sb), combined=q(m, s), factor=math.exp(Z * s))
    return out


if __name__ == '__main__':
    E = estimate()
    write_json('budget_estimates.json', E)
    print('Estimated application-security spending, $bn a year (low, middle, high of the 90% range)')
    for c, e in E.items():
        f = lambda v: f"{v[1]:.2f} ({v[0]:.2f}-{v[2]:.2f})"
        print(f"  {c:10s} engineers route {f(e['engineers_route'])} | R&D route {f(e['rd_route'])} | combined {f(e['combined'])} | factor {e['factor']:.1f}")
