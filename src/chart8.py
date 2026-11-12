"""Chart 8. The largest mass-exploitation incidents with an identified vulnerability, and the kind of vulnerability used.
Counts and sources come from data/campaigns.csv."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv, re
from style import *
from study import DATA, words, write_json

rows_csv = list(csv.DictReader(open(DATA / 'campaigns.csv', encoding='utf-8')))


def find(key):
    r = [x for x in rows_csv if key in x['event']]
    assert len(r) == 1, (key, len(r))
    return r[0]


# (key in the campaign table, label, kind of vulnerability, unit, whether CISA and the FBI have named the kind in a Secure by Design alert)
SPEC = [('CVE-2018-13379', 'Fortinet VPN, 2019–21', 'Path traversal', 'devices', True),
        ('Asnarok', 'Sophos firewalls, 2020', 'SQL injection', 'firewalls', True),
        ('cPanel', 'cPanel web hosting, 2026', 'Missing authentication', 'servers', False),
        ('Cisco IOS XE', 'Cisco IOS XE, 2023', 'Access-control flaw + command injection', 'devices', True),
        ('ProxyLogon', 'Microsoft Exchange, 2021', 'Request forgery, then file write', 'organizations in the US alone', False),
        ('COATHANGER', 'Fortinet VPN, 2022–23', 'Buffer overflow', 'devices', True),
        ('CVE-2022-40684', 'Fortinet firewalls, 2022', 'Authentication bypass', 'devices', False),
        ('ESXiArgs', 'VMware ESXi, 2023', 'Buffer overflow, fixed two years earlier', 'servers', True),
        ('MOVEit', 'Progress MOVEit, 2023', 'SQL injection', 'organizations', True),
        ('CVE-2024-0012', 'Palo Alto firewalls, 2024', 'Authentication bypass + command injection', 'firewalls', True),
        ('CVE-2023-3519', 'Citrix NetScaler, 2023', 'Code injection', 'devices', False),
        ('Ivanti Connect Secure zero-days', 'Ivanti VPN, 2024', 'Authentication bypass + command injection', 'devices', True)]
ROWS = []
for key, lab, kind, unit, named in SPEC:
    r = find(key)
    n = float(re.sub(r'[^0-9.]', '', r['compromised_count']))
    ROWS.append(dict(label=lab, kind=kind, count=n, unit=unit, named=named, cves=r['cves'], operated_by=r['operated_by'], hosted_hit=r['vendor_hosted_version_affected'], source=r['compromised_source_url']))
ROWS.sort(key=lambda x: -x['count'])
named = sum(1 for x in ROWS if x['named'])
both = [x for x in ROWS if x['operated_by'] == 'both']
hosted_hit = [x['label'] for x in ROWS if x['hosted_hit'] in ('Y', 'partly')]
assert hosted_hit == ['Progress MOVEit, 2023'], hosted_hit
write_json('chart8_numbers.json', dict(incidents=ROWS, named_kinds=named, total=len(ROWS)))
print('Chart 8:', [(x['label'], int(x['count'])) for x in ROWS], '| kinds named in Secure by Design alerts:', named, 'of', len(ROWS), '| run by', set(x['operated_by'] for x in ROWS))

T = "The biggest mass break-ins came through\ntextbook vulnerabilities"
SUB = ("Largest mass-exploitation incidents with a known vulnerability, by systems or\n"
       "organizations compromised, and the kind of vulnerability the attackers used")
FT = wrap("Counts come from the vendor, a government or a scanning group for each incident (Fortinet, US Department of Justice, Shadowserver, Censys, Krebs on Security, Dutch "
          "intelligence services, BleepingComputer, Emsisoft, Fox-IT, Volexity). They measure different things, such as implanted devices, leaked credentials or breached "
          "organizations, and most are lower bounds; cPanel's is servers seen attacking others. Incidents with no identified vulnerability are left out. All hit products that customers run "
          f"themselves; of the {words(len(both))} also sold as a service the vendor hosts, only MOVEit's hosted version was hit too. {words(named).capitalize()} of the {len(ROWS)} used a kind of vulnerability (SQL injection, path traversal, command injection or buffer overflow) "
          "that CISA and the FBI have told software makers they can eliminate. Sources: as listed; NVD; CISA.")
RH = 88
plot_h = RH * len(ROWS) + 6
H = int(head_h(T, SUB) + 50 + plot_h + 104 + 44 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
top = ys + 50
LEFT = 610; WID = 560; XMAX = 90000
a = axes_px(fig, H, LEFT, top, WID, plot_h)
a.set_xlim(0, XMAX); a.set_ylim(plot_h, 0); a.set_yticks([]); a.set_xticks([0, 20000, 40000, 60000, 80000]); a.set_xticklabels(['0', '20,000', '40,000', '60,000', '80,000']); xgrid(a)
y = 0
for x in ROWS:
    yc = y + RH / 2 - 4
    a.barh(yc, x['count'], height=44, color=CLAY, zorder=3)
    fy = 1 - (top + yc) / H
    fig.text((LEFT - 20) / 1456, fy + 13 / H, x['label'], ha='right', va='center', fontsize=px(LAB - 2), fontweight=900, color=INK)
    fig.text((LEFT - 20) / 1456, fy - 21 / H, x['kind'], ha='right', va='center', fontsize=px(22), color=MUTED)
    t1 = a.text(x['count'] + 900, yc, f"{x['count']:,.0f}", ha='left', va='center', fontsize=px(LAB), fontweight=900, color=INK, clip_on=False, zorder=6)
    fig.canvas.draw(); bb = t1.get_window_extent(fig.canvas.get_renderer()); xr = a.transData.inverted().transform((bb.x1, 0))[0]
    a.text(xr + 700, yc, x['unit'], ha='left', va='center', fontsize=px(LAB - 5), color=MUTED, clip_on=False, zorder=6)
    y += RH
foot(fig, H, FT)
print(save(fig, 'chart8_largest_incidents'))
