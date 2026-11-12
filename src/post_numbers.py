"""Every number quoted in the text of the post, recomputed from the data and checked against the wording.

Run:  python src/post_numbers.py
Writes output/numbers.json and NUMBERS.md, and prints one line per claim with OK or CHECK.
A CHECK means the data no longer support the wording as written (for instance after a data update).
The numbers drawn on the charts themselves are written by each chart script to output/chartN_numbers.json.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv, collections, math
import study
from study import R, DATA, ROOT, PANEL, cls, opn, mass, attacked, grp, quarter, write_json
import estimates as E
import budgets, maturity

CLAIMS = []


def claim(where, wording, value, ok, how):
    CLAIMS.append(dict(where=where, wording=wording, value=value, ok=bool(ok), how=how))


def pct(a, b):
    return f"{100 * a / b:.1f}% ({a:,} of {b:,})"


C = [r for r in R if cls(r)]
B = E.build()
write_json('estimates.json', B)
P = B['P']
y5, y6 = B['year2025'], B['year2026']

# ---------------------------------------------------------------- paragraph after Chart 1
q3 = P['2026Q3']
claim('After Chart 1', '30 of the third quarter\'s vulnerabilities already [attacked]', q3['any'], q3['any'] == 30,
      'class vulnerabilities published July-September 2026 that are attacked (study.attacked)')
claim('After Chart 1', 'against 12 a quarter last year', f"{y5['any'] / 4:.2f} ({y5['any']} in 2025)", round(y5['any'] / 4) == 12,
      'class vulnerabilities published in 2025 that are attacked, divided by four')
claim('After Chart 1', 'only four of those have reached mass exploitation', q3['mass'], q3['mass'] == 4, 'of the 30, those with evidence of scale (study.mass)')
claim('After Chart 1', 'where last year half did', pct(y5['mass'], y5['any']), 0.45 <= y5['mass'] / y5['any'] <= 0.55, 'class, published 2025: mass-exploited / attacked')

# ---------------------------------------------------------------- paragraph after Chart 3
Y26 = [r for r in R if r['pub'][:4] == '2026']
mm = [r for r in Y26 if grp(r) == 'midmarket']
m26 = [r for r in Y26 if mass(r)]
shown = [r for r in Y26 if grp(r) != 'device']
claim('After Chart 3', 'Mid-market and smaller vendors published about a tenth of this year\'s vulnerabilities', f"{pct(len(mm), len(Y26))}; {pct(len(mm), len(shown))} of those Chart 3 shows",
      0.08 <= len(mm) / len(Y26) <= 0.12, 'remotely exploitable vulnerabilities published January 1 to November 9, 2026, by maker group')
claim('After Chart 3', 'and have suffered half of the mass exploitation so far', pct(sum(mass(r) for r in mm), len(m26)), 0.45 <= sum(mass(r) for r in mm) / len(m26) <= 0.55,
      'of 2026\'s mass-exploited vulnerabilities, those from mid-market and smaller vendors')

# ---------------------------------------------------------------- paragraph before Chart 4
O = [r for r in R if '2019-01-01' <= r['pub'] <= '2025-12-31' and opn(r)]
zv = [r for r in O if r['zd'] and r['upd'] == 'vendor']; zc = [r for r in O if r['zd'] and r['upd'] == 'customer']
kv, kc = sum(map(mass, zv)), sum(map(mass, zc))
claim('Before Chart 4', 'a zero-day in software the vendor updates itself ... spread to mass exploitation about a quarter of the time', pct(kv, len(zv)), 0.22 <= kv / len(zv) <= 0.28,
      'no login, no click, 2019-2025, zero-days in vendor-updated products: share mass-exploited')
claim('Before Chart 4', 'when customers had to install the fix, more than five times in six', pct(kc, len(zc)), kc / len(zc) > 5 / 6, 'the same for products customers patch')
camp = list(csv.DictReader(open(DATA / 'campaigns.csv', encoding='utf-8')))
both = [r for r in camp if r['operated_by'] == 'both' and r['vendor_hosted_version_affected'] in ('Y', 'N', 'partly')]
hit = [r for r in both if r['vendor_hosted_version_affected'] in ('Y', 'partly')]
claim('Before Chart 4', 'campaigns reached the hosted version in only five of 33 cases', f"{len(hit)} of {len(both)}", (len(hit), len(both)) == (5, 33),
      'data/campaigns.csv: products sold both ways with a known outcome for the vendor-hosted version')
MS = [r for r in O if grp(r) == 'microsoft']; MSC = [r for r in MS if r['upd'] == 'customer']
REST = [r for r in O if grp(r) not in ('hyperscale', 'microsoft')]; FOUR = [r for r in O if grp(r) == 'hyperscale']
rate = lambda rs: sum(map(mass, rs)) / len(rs)
claim('Before Chart 4', 'in the server products [Microsoft] leaves customers to patch, vulnerabilities were mass-exploited far more often than everyone else\'s',
      f"{pct(sum(map(mass, MSC)), len(MSC))} against {pct(sum(map(mass, REST)), len(REST))}", rate(MSC) > 3 * rate(REST),
      'no login, no click, 2019-2025: Microsoft products with update model "customer" against every maker other than the five hyperscalers')

# ---------------------------------------------------------------- paragraph before Chart 5
f26 = [r for r in Y26 if grp(r) == 'hyperscale']; ms26 = [r for r in Y26 if grp(r) == 'microsoft' and mass(r)]
claim('Before Chart 5', 'Of the 2,319 vulnerabilities those four have published this year, none has been mass-exploited so far', f"{len(f26):,} published, {sum(map(mass, f26))} mass-exploited",
      len(f26) == 2319 and sum(map(mass, f26)) == 0, 'Google, Apple, Meta and Amazon, published 2026')
claim('Before Chart 5', 'Microsoft\'s two were both in a server product its customers patch themselves', '; '.join(f"{r['id']} {r['prod']} ({r['upd']})" for r in ms26),
      len(ms26) == 2 and all(r['upd'] == 'customer' and 'sharepoint server' in r['prod'] for r in ms26), 'Microsoft, published 2026, mass-exploited')

# ---------------------------------------------------------------- paragraph before Chart 6
EST = budgets.estimate()
mid = sorted(float(r['revenue']) for r in PANEL.values() if r['group'] in ('midsize', 'netsec') and r['revenue'] and float(r['revenue']) < 5000)
med = mid[len(mid) // 2] / 1000
four_est = {k: EST[k]['combined'][1] for k in ('Amazon', 'Alphabet', 'Meta', 'Apple')}
claim('Before Chart 6', 'The estimated application security budget of a single hyperscaler is about the size of the entire revenue of a typical mid-market enterprise software company',
      ', '.join(f"{k} ${v:.2f}bn" for k, v in four_est.items()) + f"; median revenue of {len(mid)} mid-market vendors ${med:.2f}bn",
      all(0.5 <= v / med <= 1.5 for v in four_est.values()), 'budgets.py estimates against the median revenue in data/vendor_panel.csv')

# ---------------------------------------------------------------- caveats and methodology
K = [r for r in csv.DictReader(open(DATA / 'kev_coverage.csv', encoding='utf-8')) if 2019 <= int(r['cve_year']) <= 2026 and r['role'] in ('edge', 'srv_exposed') and r['no_login_no_click'] == '1']
kout = sum(1 for r in K if r['in_flaw_table'] == '0')
claim('Methodology', 'About a quarter of the pre-login, internet-facing vulnerabilities that CISA lists as exploited fall outside my data', pct(kout, len(K)), 0.2 <= kout / len(K) <= 0.3,
      'data/kev_coverage.csv: CVEs from 2019-2026 in internet-facing enterprise products, no login and no click, not in the vulnerability table')
claim('Methodology', 'In a set of nearly 80,000', f"{len(R):,}", 78000 <= len(R) < 80000, 'rows in data/flaws.csv.gz')
claim('Methodology', 'I projected October to December from its first 40 days', B['days_elapsed'], B['days_elapsed'] == 40, 'October 1 to November 9, 2026')
bt = B['backtests']
claim('Methodology', 'Tested against 13 past quarters, the attack estimate came within a few percent in total but missed single quarters by about a fifth on average',
      f"{len(bt['rows'])} quarters; total estimate {bt['quarter_rule']['total_estimate']:.0f} against {bt['quarter_rule']['total_actual']:.0f}; typical miss {100 * (math.exp(bt['quarter_rule']['mean_abs_log_error']) - 1):.0f}%",
      len(bt['rows']) == 13 and abs(bt['quarter_rule']['ratio'] - 1) < 0.05 and 0.15 <= math.exp(bt['quarter_rule']['mean_abs_log_error']) - 1 <= 0.25,
      'estimates.backtests(): the full-quarter rule at day 40 of each quarter from 2023Q3 to 2026Q3, against CISA listings since')
ra, rm = B['ranges']['2026:any'], B['ranges']['2026:mass']
claim('Methodology', 'about 110 vulnerabilities of the most dangerous class will be attacked this year, with a plausible range of roughly 90 to 150', f"{y6['any']:.1f} (90% range {ra[0]:.0f} to {ra[2]:.0f})",
      105 <= y6['any'] <= 115 and 85 <= ra[0] <= 95 and 143 <= ra[2] <= 155, 'estimates.build(): sum of the four 2026 quarters')
claim('Methodology', 'and about 38 mass-exploited, with a range of roughly 25 to 65', f"{y6['mass']:.1f} (90% range {rm[0]:.0f} to {rm[2]:.0f})",
      round(y6['mass']) == 38 and 23 <= rm[0] <= 28 and 60 <= rm[2] <= 68, 'the same for mass exploitation')
q4 = P['2026Q4']
claim('Methodology', 'three-quarters of the last bar in Chart 2 is projection', f"{100 * (1 - q4['any'] / q4['est_any']):.0f}% ({q4['any']} observed of {q4['est_any']:.1f})", 0.70 <= 1 - q4['any'] / q4['est_any'] <= 0.80,
      'October-December: 1 - attacked so far / estimate')
q3c = [r for r in C if quarter(r['pub']) == '2026Q3']; orc = sum(1 for r in q3c if r['vendor'] == 'oracle')
claim('Methodology', 'Oracle published a third of the third quarter\'s most dangerous vulnerabilities', pct(orc, len(q3c)), 0.30 <= orc / len(q3c) <= 0.37, 'class, published July-September 2026, vendor oracle')
goog = sum(1 for r in f26 if r['company'] == 'Google')
claim('Methodology', 'Google accounts for nine-tenths of the four hyperscalers\' remotely exploitable ones this year', pct(goog, len(f26)), 0.87 <= goog / len(f26) <= 0.93, 'published 2026, group hyperscale, company Google')
claim('Methodology', '20 zero-days in vendor-updated products against 52 in customer-patched ones, and 33 campaigns', f"{len(zv)}, {len(zc)}, {len(both)}", (len(zv), len(zc), len(both)) == (20, 52, 33), 'as in Chart 4')
M = maturity.run()
nulls = ['public paid bug bounty', 'signed the Secure by Design pledge', 'company founded after the median year', 'R&D share of revenue above the median']
claim('Methodology', 'I also tested bug bounties, the Secure by Design pledge, company age and R&D spending and found no detectable effect',
      '; '.join(f"{k}: {100 * M[k]['with_mass'] / M[k]['with_n']:.0f}% against {100 * M[k]['without_mass'] / M[k]['without_n']:.0f}%, chance {100 * M[k]['p']:.0f}%" for k in nulls),
      all(M[k]['p'] > 0.2 for k in nulls), 'maturity.py: vendor-clustered permutation tests')
sz, pe = M['revenue above the median'], M['private-equity owned']
claim('Methodology', 'Two things did show up, though after nine tests they deserve caution: among vendors of internet-facing products that customers patch, the smaller half and the private-equity-owned ones had two to three times the share of vulnerabilities mass-exploited',
      f"smaller half {100 * sz['without_mass'] / sz['without_n']:.0f}% against {100 * sz['with_mass'] / sz['with_n']:.0f}% (chance {100 * sz['p']:.1f}%); "
      f"PE-owned {100 * pe['with_mass'] / pe['with_n']:.0f}% against {100 * pe['without_mass'] / pe['without_n']:.0f}% (chance {100 * pe['p']:.1f}%)",
      2 <= (sz['without_mass'] / sz['without_n']) / (sz['with_mass'] / sz['with_n']) <= 3 and 2 <= (pe['with_mass'] / pe['with_n']) / (pe['without_mass'] / pe['without_n']) <= 3 and sz['p'] < 0.05 and pe['p'] < 0.05 and len(M) - 1 == 9,
      'maturity.py')
small_vendors = len({r['vendor'] for r in R if grp(r) == 'midmarket' and r['group_basis'] != 'revenue' and r['vendor']})
claim('Methodology', '"Mid-market and smaller vendors" ... including about 1,800 for which I have no revenue figure', f"{small_vendors:,} vendor names without a revenue figure", 1700 <= small_vendors <= 1900,
      'distinct vendor names in the mid-market group whose group was not set from a revenue figure, 2019-2026')
unc = [r for r in Y26 if grp(r) == 'small' and r['role'] in ('other', 'other_web')]
wide_n = (len(mm) + len(unc)) / len(Y26); wide_m = (sum(mass(r) for r in mm) + sum(mass(r) for r in unc)) / len(m26)
claim('Methodology', 'A further 2,900 or so of this year\'s vulnerabilities are in software I could not classify ... counting all of it with the mid-market would raise that group\'s share of vulnerabilities from a tenth to a fifth and leave its share of mass exploitation at about half',
      f"{len(unc):,} unclassified; with them the group has {100 * wide_n:.0f}% of the vulnerabilities and {100 * wide_m:.0f}% of the mass exploitation",
      2800 <= len(unc) <= 3000 and 0.18 <= wide_n <= 0.24 and 0.45 <= wide_m <= 0.58, 'published 2026, group small, product role other or other_web (no kind of maker could be assigned)')
old_m = [r for r in C if r['pub'][:4] <= '2023' and mass(r)]; new_m = [r for r in C if r['pub'][:4] == '2026' and mass(r)]
sens = lambda r: 'sensor top-100 list' in study.scale_evidence(r)
only = lambda r: set(study.scale_evidence(r)) == {'sensor top-100 list'}
claim('Methodology', 'For vulnerabilities published before 2024 the evidence is mostly ransomware reports and government lists; for this year\'s it is mostly sensor rankings',
      f"published 2019-2023: {sum(not only(r) for r in old_m)} of {len(old_m)} have evidence other than a sensor ranking; published 2026: {sum(map(sens, new_m))} of {len(new_m)} have a sensor ranking, {sum(map(only, new_m))} nothing else",
      sum(not only(r) for r in old_m) / len(old_m) > 0.8 and sum(map(sens, new_m)) / len(new_m) > 0.6, 'class; kinds of evidence from study.scale_evidence')
am = EST['Amazon']['combined']; fac = sum(EST[k]['factor'] for k in ('Amazon', 'Alphabet', 'Meta', 'Apple')) / 4
claim('Methodology', 'The honest range is a factor of about 2.6 either way, so Amazon\'s $0.9bn could be $0.3bn or $2.4bn', f"factor {fac:.2f}; Amazon ${am[1]:.2f}bn (${am[0]:.2f}bn to ${am[2]:.2f}bn)",
      abs(fac - 2.6) < 0.1 and round(am[1], 1) == 0.9 and round(am[0], 1) == 0.3 and round(am[2], 1) == 2.4, 'budgets.py')

# ---------------------------------------------------------------- statements in the post as published
pub26 = sum(P[q]['n'] if q != '2026Q4' else B['est_pub'] for q in ('2026Q1', '2026Q2', '2026Q3', '2026Q4'))
NOW = []
def now(wording, value, ok, how):
    NOW.append(dict(where='In the post', wording=wording, value=value, ok=bool(ok), how=how))
now('the pace of discovery of the most dangerous remotely exploitable vulnerabilities has risen roughly 4x this year', f"{pub26 / y5['n']:.1f}x ({pub26:,.0f} expected in 2026 against {y5['n']} in 2025)",
    3.3 <= pub26 / y5['n'] <= 4.5, 'class (no login, no click, internet-facing enterprise software) by year published; October to December 2026 projected as October x 3')
now('but exploitation more like 2x in my data', f"{y6['any'] / y5['any']:.1f}x ({y6['any']:.0f} estimated for 2026 against {y5['any']} for 2025; 90% range {ra[0]:.0f} to {ra[2]:.0f})",
    1.7 <= y6['any'] / y5['any'] <= 2.7, 'class vulnerabilities with public evidence of exploitation (study.attacked), by year published; 2026 adjusted for reporting delay (src/estimates.py)')
now('paying hundreds of millions a year [for application security]', ', '.join(f"{k} ${v['combined'][1]:.2f}bn" for k, v in EST.items() if k != 'Microsoft'),
    all(0.2 <= v['combined'][1] <= 1.0 for k, v in EST.items() if k != 'Microsoft'), 'src/budgets.py: estimates, not reported figures')
now('[hyperscalers] have seen none of their vulnerabilities discovered in 2026 exploited at scale in the wild', f"{sum(map(mass, f26))} of {len(f26):,}", sum(map(mass, f26)) == 0,
    'group hyperscale, published 2026, study.mass')
now('the last quarter is mostly projection', f"{100 * (1 - q4['any'] / q4['est_any']):.0f}%", q4['any'] / q4['est_any'] < 0.5, 'observed attacked / estimated, October to December 2026')
KEEP = ('Of the 2,319', 'Microsoft\'s two', 'The estimated application security budget', '"Mid-market and smaller vendors"')
for c in CLAIMS:
    c['where'] = 'In the post' if c['wording'].startswith(KEEP) else 'Behind the charts (in earlier drafts of the post)'
CLAIMS[:] = NOW + [c for c in CLAIMS if c['where'] == 'In the post'] + [c for c in CLAIMS if c['where'] != 'In the post']
CLAIMS.append(dict(where='In the post', wording='they have 10-100x smaller appsec budgets', value='not measured', ok=None,
                   how='The author\'s estimate. This repository has mid-market revenue (median $0.6bn), not mid-market security budgets'))

# ---------------------------------------------------------------- write out
write_json('numbers.json', CLAIMS)
lines = ['# Every number in the text of the post', '',
         'Generated by `python src/post_numbers.py` from the data in this repository. Rows marked *In the post* are statements in the published text. Rows marked *Behind the charts* were in earlier drafts and still describe what the charts show.',
         'The numbers drawn on the charts are in `output/chartN_numbers.json`, written by each chart script.', '',
         '| Where | The post says | The data give | Supported | How it is computed |', '|---|---|---|---|---|']
for c in CLAIMS:
    lines.append(f"| {c['where']} | {c['wording']} | {str(c['value']).replace('|', '/')} | {'not measured' if c['ok'] is None else 'yes' if c['ok'] else 'CHECK'} | {c['how']} |")
(ROOT / 'NUMBERS.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
for c in CLAIMS:
    print(('n/a  ' if c['ok'] is None else 'OK   ' if c['ok'] else 'CHECK'), '|', c['where'], '|', c['wording'][:88], '->', str(c['value'])[:150])
T = [c for c in CLAIMS if c['ok'] is not None]
print(f"\n{sum(c['ok'] for c in T)} of {len(T)} statements supported; {len(CLAIMS) - len(T)} not measurable from this data")
