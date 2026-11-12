# Builds the frozen analysis tables in data/ from the upstream working files.
# This script is kept for provenance. It reads files that are not in this repository (parsed NVD and CVE records,
# research tables) and so cannot be re-run from the repository alone. Everything downstream of data/ can.
import sys, json, csv, gzip, collections, re, shutil
W = '/home/claude/research/'
sys.path.insert(0, W + 'scripts'); sys.path.insert(0, W + 'rce/scripts')
from load3 import load3
import panelmap
OUT = W + 'repo/data/'
rows, _ = load3()

# ---- 1. maker group: hyperscale tier split into the four model hyperscalers and Microsoft, then the documented overrides
COMPANY = {'Microsoft': 'Microsoft', 'Google': 'Google', 'Apple': 'Apple', 'Amazon (AWS)': 'Amazon'}
COMPANY_V = {'facebook': 'Meta', 'whatsapp': 'Meta', 'meta': 'Meta', 'android': 'Google', 'chromium': 'Google'}
OV = list(csv.DictReader(open(OUT + 'group_overrides.csv', encoding='utf-8')))
OVD = {o['vendor']: o for o in OV}
ROLE_OV = {(o['vendor'], o['product']): o['new_role'] for o in csv.DictReader(open(OUT + 'role_overrides.csv', encoding='utf-8'))}
n_ov = collections.Counter(); n_role = 0
for r in rows:
    v = (r['vendor'] or '').lower()
    if (v, r['prod'] or '') in ROLE_OV: r['role'] = ROLE_OV[(v, r['prod'] or '')]; n_role += 1
    if r['tier'] == 'hyperscale':
        co = COMPANY.get(r['pv']) or COMPANY_V.get(v)
        r['company'] = co or ''
        r['group'] = 'microsoft' if co == 'Microsoft' else 'hyperscale'
    else:
        r['company'] = ''; r['group'] = r['tier']
    r['group_basis'] = 'revenue' if (r['pv'] and r['tier'] in ('large', 'midmarket')) else ('named' if r['tier'] == 'hyperscale' else 'rule')
    o = OVD.get(v)
    if o and (o['applies_to_group'] == '*' or o['applies_to_group'] == r['group']):
        r['group'] = o['new_group']; r['company'] = o['company'] or ('' if o['new_group'] not in ('hyperscale', 'microsoft') else r['company'])
        r['group_basis'] = 'override'; n_ov[v] += 1
        if o['new_group'] not in ('hyperscale', 'microsoft'): r['pv'] = None if r['tier'] == 'hyperscale' else r['pv']
print('group overrides applied:', sum(n_ov.values()), dict(n_ov.most_common(8)), '| role overrides:', n_role)

# ---- 2. write the flaw table
COLS = ['id', 'pub', 'src', 'vendor', 'prod', 'rce', 'basis', 'pop2', 'score', 'av', 'ac', 'pr', 'ui', 'c', 'i', 'a', 'delivery', 'wk', 'role',
        'group', 'group_basis', 'company', 'pv', 'upd', 'upd_basis', 'kev', 'kev_date', 'kev_rw', 'expl', 'zd', 'ev_wide', 'camp', 'victims', 'pkp', 'cna']
def cell(r, k):
    x = r.get(k)
    if k == 'ev_wide': return '|'.join(x or [])
    if isinstance(x, bool): return int(x)
    if x is None: return ''
    if k == 'victims': return int(x)
    return x
with gzip.open(OUT + 'flaws.csv.gz', 'wt', encoding='utf-8', newline='') as f:
    w = csv.writer(f); w.writerow(COLS)
    for r in sorted(rows, key=lambda r: (r['pub'], r['id'])): w.writerow([cell(r, k) for k in COLS])
print('flaws', len(rows))

# ---- 3. sensor lists: CIRCL's lists of the 100 most-sighted exploited flaws, tagged by kind of period
src = W + 'research_notes/RCE flaw vendors attackers and volume/circl_exploited_sightings.csv'
with open(OUT + 'sensor_lists.csv', 'w', encoding='utf-8', newline='') as f:
    w = csv.writer(f); w.writerow(['id', 'period_start', 'period_end', 'count', 'kind'])
    for r in csv.DictReader(open(src, encoding='utf-8')):
        s, e = r['period_start'], r['period_end']
        kind = 'all_time' if (s <= '2024-01-01' and e >= '2026-01-01') else ('pre_feed' if s < '2024-10-01' else 'quarter')
        w.writerow([r['id'].strip().upper(), s, e, r['count'], kind])

# ---- 4. CISA's catalog, for the coverage check; campaign table; vendor panel
K = json.load(open(W + 'out/kev_rows.json')); ids = {r['id'] for r in rows}
with open(OUT + 'kev_coverage.csv', 'w', encoding='utf-8', newline='') as f:
    w = csv.writer(f); w.writerow(['id', 'vendor', 'product', 'date_added', 'cve_year', 'ransomware_flag', 'role', 'no_login', 'no_login_no_click', 'in_flaw_table'])
    for k in sorted(K, key=lambda k: k['id']):
        w.writerow([k['id'], k['vendor'], k['product'], k['added'], k['cy'], int(bool(k['rw'])), k['role'], int(bool(k.get('pre'))), int(bool(k.get('pre_noui'))), int(k['id'] in ids)])
shutil.copy(W + 'research_notes/Vendor exploitation outcome drivers/mass_exploitation_campaigns.csv', OUT + 'campaigns.csv')
# the vendor panel, keeping the columns this study uses
KEEP = ['vendor', 'group', 'revenue', 'rev_cert', 'rev_period', 'employees', 'rnd_pct', 'founded', 'codebase_year', 'acquired', 'pe', 'ownership',
        'pe_sponsor', 'bounty', 'bounty_raw', 'bounty_max', 'pledge']
with open(OUT + 'vendor_panel.csv', 'w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=KEEP); w.writeheader()
    for r in csv.DictReader(open(W + 'out/vendor_panel.csv', encoding='utf-8')): w.writerow({k: r[k] for k in KEEP})
print('done')
