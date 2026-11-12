"""Chart 4. Three things about a vendor, set against mass exploitation of vulnerabilities that need no login and no click, 2019-2025.
  1. who installs the fix (zero-days that spread to mass exploitation);
  2. who runs the product (campaigns that reached the vendor-hosted version);
  3. who the vendor is (Google, Apple, Meta, Amazon against Microsoft and everyone else)."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv, collections
from style import *
from study import R, DATA, mass, opn, cls, grp, words, write_json

O = [r for r in R if '2019-01-01' <= r['pub'] <= '2025-12-31' and opn(r)]


def cell(rs):
    zd = [r for r in rs if r['zd']]; nd = [r for r in rs if not r['zd']]
    return dict(n=len(rs), mass=sum(mass(r) for r in rs), zd=len(zd), zd_mass=sum(mass(r) for r in zd), nd=len(nd), nd_mass=sum(mass(r) for r in nd))


v = cell([r for r in O if r['upd'] == 'vendor']); c = cell([r for r in O if r['upd'] == 'customer'])
# campaigns against products the vendor also hosts, where the fate of the hosted version is known
camp = list(csv.DictReader(open(DATA / 'campaigns.csv', encoding='utf-8')))
both = [r for r in camp if r['operated_by'] == 'both' and r['vendor_hosted_version_affected'] in ('Y', 'N', 'partly')]
hit = [r for r in both if r['vendor_hosted_version_affected'] in ('Y', 'partly')]
yrs = sorted(r['start_month'][:4] for r in both)
FOUR = [r for r in O if grp(r) == 'hyperscale']; MS = [r for r in O if grp(r) == 'microsoft']; REST = [r for r in O if grp(r) not in ('hyperscale', 'microsoft')]
MSC = [r for r in MS if r['upd'] == 'customer']
k = lambda rs: (sum(mass(r) for r in rs), len(rs))
four, ms, rest, msc = k(FOUR), k(MS), k(REST), k(MSC)
nx = sum(1 for r in MSC if mass(r) and ('exchange' in r['prod'] or 'sharepoint' in r['prod']))
by_company = {co: k([r for r in FOUR + MS if r['company'] == co]) for co in ('Google', 'Apple', 'Meta', 'Amazon', 'Microsoft')}
four_cases = [(r['id'], r['company'], r['prod'], r['upd']) for r in FOUR if mass(r)]
C19 = cell([r for r in O if cls(r)])
numbers = dict(vendor_installs=v, customer_installs=c, hosted=dict(hit=len(hit), campaigns=len(both), years=[yrs[0], yrs[-1]], hit_events=[r['event'] for r in hit]),
               four=four, microsoft=ms, everyone_else=rest, microsoft_customer_patched=msc, microsoft_customer_patched_exchange_sharepoint=nx,
               by_company=by_company, four_cases=four_cases, four_by_update_model=dict(collections.Counter(r['upd'] for r in FOUR)),
               rest_customer=k([r for r in REST if r['upd'] == 'customer']), rest_vendor=k([r for r in REST if r['upd'] == 'vendor']),
               four_vendor=k([r for r in FOUR if r['upd'] == 'vendor']), microsoft_vendor=k([r for r in MS if r['upd'] == 'vendor']), class_2019_2025=C19)
write_json('chart4_numbers.json', numbers)
print('Chart 4: zero-days spread, vendor installs', v['zd_mass'], 'of', v['zd'], '| customer installs', c['zd_mass'], 'of', c['zd'], '| hosted', len(hit), 'of', len(both),
      '| four', four, 'everyone else', rest, 'Microsoft', ms, 'Microsoft customer-patched', msc, '| by company', by_company, '| four cases', four_cases)

PANELS = [
 ("The vendor installs the fix", "Large effect", GREEN, "Zero-days (attackers had the vulnerability before any fix): the share that spread to mass exploitation",
  [("Vendor installs", v['zd_mass'], v['zd']), ("Customer installs", c['zd_mass'], c['zd'])]),
 ("The vendor runs the product itself", "Large effect", GREEN, "Mass-exploitation campaigns against products sold both ways: share that reached each version",
  [("Vendor-hosted version", len(hit), len(both)), ("Customer-run version", len(both), len(both))]),
 ("The vendor is Google, Apple, Meta or Amazon", "Lower, on few makers", GREEN, "Share of vulnerabilities mass-exploited: those four against Microsoft and every other maker",
  [("Google, Apple,\nMeta, Amazon", four[0], four[1]), ("Everyone else", rest[0], rest[1]), ("Microsoft", ms[0], ms[1]), ("Microsoft products\nthat customers patch", msc[0], msc[1])]),
]
T = "Delivering the fix cuts mass attacks.\nA big budget alone does not"
SUB = ("Three things about a vendor set against mass exploitation of vulnerabilities that\n"
       "need no login and no click, 2019–2025")
FT = wrap("Vulnerabilities: remotely exploitable ones (code execution, login bypass, SQL injection and similar) that need neither a login nor a user's click, published 2019–2025. "
          "Top panel: any product; products that update themselves are mostly phones, browsers and PCs, so the two groups differ in more than who installs the fix. "
          f"Middle panel: {len(both)} campaigns, {yrs[0]}–{yrs[-1]}, against products the vendor also hosts and where the hosted version's fate is known; every campaign hit the "
          f"customer-run version by definition. Third panel: any product; the four's record rests mostly on Google and Apple and cannot be separated from the kind of product they make; "
          f"their {words(four[0])} case was in React, Meta's open-source library, which others must update; everyone else excludes Microsoft; {words(nx)} of the {words(msc[0])} cases in Microsoft "
          "products that customers patch were in Exchange and SharePoint. Mass exploitation: evidence of attacks at scale, such as ransomware or botnet use, a place among the 100 "
          "most-sighted exploited vulnerabilities in sensor data, or a named campaign with a victim count. Sources: NVD; CISA; CIRCL; vendor statements; author's analysis.")
PH = 300; LASTH = 150
PHS = [PH + 74 * (len(b) - 2) for *_, b in PANELS]
H = int(head_h(T, SUB) + 50 + sum(PHS) + LASTH + 74 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
a = fig.add_axes([0, 0, 1, 1]); a.set_xlim(0, 1456); a.set_ylim(H, 0); a.axis('off'); a.patch.set_alpha(0)
X0 = 48; X1 = 1456 - 40; BL = 430; BW = 640
y = ys + 50


def rule(yy, col=GRID, lw=1.4):
    a.plot([X0, X1], [yy, yy], color=col, linewidth=lw)


rule(y, INK, 2.2)
for (name, verdict, vcol, measure, bars), ph in zip(PANELS, PHS):
    a.text(X0, y + 48, name, ha='left', va='center', fontsize=px(LAB + 2), fontweight=900, color=INK)
    a.text(X1, y + 48, verdict, ha='right', va='center', fontsize=px(LAB - 1), fontweight=900, color=vcol)
    a.text(X0, y + 94, measure, ha='left', va='center', fontsize=px(22.5), color=MUTED)
    for g in (0, 25, 50, 75, 100):
        a.plot([BL + BW * g / 100] * 2, [y + 124, y + ph - 28], color=(INK if g == 0 else GRID), linewidth=(2.2 if g == 0 else 1.4), zorder=2)
        if g and name.startswith('The vendor installs'):
            a.text(BL + BW * g / 100, y + 289, (f'{g}%' if g == 100 else str(g)), ha='center', va='center', fontsize=px(20), color=MUTED)
    for i, (lab, kk, n) in enumerate(bars):
        yc = y + 162 + i * 74
        share = 100 * kk / n
        pale = lab in ('Everyone else', 'Customer-run version', 'Customer installs')
        a.add_patch(Rectangle((BL, yc - 25), BW * share / 100, 50, facecolor=(PALE if pale else INK), edgecolor='none', zorder=3))
        a.text(BL - 18, yc, lab, ha='right', va='center', fontsize=px(LAB - 3), fontweight=700, color=INK, linespacing=1.1)
        t1 = a.text(BL + BW * share / 100 + 14, yc, (f"{share:.0f}%" if share >= 9.5 else f"{share:.1f}%"), ha='left', va='center', fontsize=px(LAB + 1), fontweight=900, color=INK, zorder=6)
        fig.canvas.draw(); bb = t1.get_window_extent(fig.canvas.get_renderer()); xr = a.transData.inverted().transform((bb.x1, 0))[0]
        a.text(xr + 12, yc, f"{kk:,} of {n:,}", ha='left', va='center', fontsize=px(LAB - 5), color=MUTED, zorder=6)
    y += ph
    rule(y)
a.text(X0, y + 48, "The vendor mines product telemetry for attacks", ha='left', va='center', fontsize=px(LAB + 2), fontweight=900, color=INK)
a.text(X1, y + 48, "Untested", ha='right', va='center', fontsize=px(LAB - 1), fontweight=900, color=MUTED)
a.text(X0, y + 94, "No public record says which vendors do this, so it cannot be measured here", ha='left', va='center', fontsize=px(22.5), color=MUTED)
y += LASTH - 10
rule(y, INK, 2.2)
foot(fig, H, FT)
print(save(fig, 'chart4_what_cuts_mass_exploitation'))
