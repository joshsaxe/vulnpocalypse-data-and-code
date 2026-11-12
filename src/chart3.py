"""Chart 3. Where 2026's new vulnerabilities were published, and where mass exploitation has landed so far, by kind of maker."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from style import *
from study import R, mass, grp, GROUP_NAMES, write_json

DROP = {'device'}     # left out of the chart: botnet evidence for device vulnerabilities arrives months late, so the row would read 0
tab = {}
for y in ('2025', '2026'):
    tab[y] = {}
    for g in GROUP_NAMES:
        rs = [r for r in R if r['pub'][:4] == y and grp(r) == g]
        tab[y][g] = [len(rs), sum(mass(r) for r in rs)]
rows = [(g, tab['2026'][g][0], tab['2026'][g][1], tab['2025'][g][0], tab['2025'][g][1]) for g in GROUP_NAMES if g not in DROP]
rows.sort(key=lambda r: (-r[2], -r[1]))
N = sum(r[1] for r in rows); M = sum(r[2] for r in rows); N25 = sum(r[3] for r in rows); M25 = sum(r[4] for r in rows)
ALL = sum(v[0] for v in tab['2026'].values()); ND = tab['2026']['device'][0]
mm = tab['2026']['midmarket']
revenue_known = sum(1 for r in R if r['pub'][:4] == '2026' and grp(r) == 'midmarket' and r['group_basis'] == 'revenue')
# the small-projects group is partly a catch-all: software whose kind of maker could not be classified
unclassified = [r for r in R if r['pub'][:4] == '2026' and grp(r) == 'small' and r['role'] in ('other', 'other_web')]
U = len(unclassified); UM = sum(mass(r) for r in unclassified)
numbers = dict(by_group=tab, shown_total=[N, M], shown_total_2025=[N25, M25], all_2026=ALL, device_2026=ND,
               midmarket_share_of_all=mm[0] / ALL, midmarket_share_of_shown=mm[0] / N, midmarket_share_of_mass=mm[1] / M,
               midmarket_with_known_revenue=revenue_known, small_unclassified=[U, UM],
               midmarket_plus_unclassified_share_of_all=(mm[0] + U) / ALL, midmarket_plus_unclassified_share_of_mass=(mm[1] + UM) / M)
write_json('chart3_numbers.json', numbers)
print('Chart 3:', {g: tab['2026'][g] + [round(tab['2026'][g][0] / tab['2025'][g][0], 2)] for g in GROUP_NAMES}, '| shown', N, M, '| all', ALL,
      f"| mid-market share of all {100 * mm[0] / ALL:.1f}%, of shown {100 * mm[0] / N:.1f}%, of mass {100 * mm[1] / M:.0f}%")

T = "The flood hit the big platforms. The mass\nexploitation hit the mid-market"
SUB = ("Remotely exploitable vulnerabilities published in 2026, by kind of maker, and the\n"
       "number already mass-exploited")
FT = wrap(f"Vulnerabilities: {N:,} published from January 1 to November 9, 2026 that are remotely exploitable (code execution, login bypass, SQL injection and similar), sorted by maker; "
          f"multiples compare with all of 2025. Mid-market and smaller vendors are commercial makers of enterprise and industrial software with revenue under $5bn or none on record; large vendors have more. "
          f"Plug-ins and small projects include {U:,} vulnerabilities in software the author could not classify, some of it from small commercial vendors. "
          "Microsoft is shown apart from the other hyperscalers because it leaves customers to patch its server products. "
          f"Device makers ({ND:,}) are left out: the botnets that use their vulnerabilities are identified months later, so none shows yet. "
          f"Mass exploitation: evidence of attacks at scale (ransomware or botnet use, a place among the 100 most-sighted exploited vulnerabilities in honeypot sensor data, or a named campaign with a "
          f"victim count); {M} so far, against {M25} of 2025's. Sources: NVD; CISA; CIRCL; Shadowserver; author's classification.")
RH = 100; HEADH = 96
plot_h = RH * len(rows)
H = int(head_h(T, SUB) + 40 + HEADH + plot_h + 84 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
top = ys + 40 + HEADH
L1 = 540; W1 = 370; L2 = 1050; W2 = 290
a1 = axes_px(fig, H, L1, top, W1, plot_h); a2 = axes_px(fig, H, L2, top, W2, plot_h)
X1 = 1.18 * max(r[1] for r in rows); X2 = 1.15 * max(r[2] for r in rows)
for a, xm in ((a1, X1), (a2, X2)):
    a.set_xlim(0, xm); a.set_ylim(plot_h, 0); a.set_yticks([]); a.set_xticks([]); a.spines['bottom'].set_visible(False)
    a.spines['left'].set_linewidth(2.2); a.spines['left'].set_color(INK)
fig.text(L1 / 1456, 1 - (top - HEADH / 2 - 4) / H, "New vulnerabilities\npublished in 2026", fontsize=px(LAB - 3), fontweight=900, color=INK, va='center', ha='left', linespacing=1.15)
fig.text(L2 / 1456, 1 - (top - HEADH / 2 - 4) / H, "Mass-exploited\nso far", fontsize=px(LAB - 3), fontweight=900, color=DEEP, va='center', ha='left', linespacing=1.15)
y = 0
for g, n, m, n5, m5 in rows:
    yc = y + RH / 2
    a1.barh(yc, n, height=48, color=INK, zorder=3); a2.barh(yc, m, height=48, color=DEEP, zorder=3)
    fy = 1 - (top + yc) / H
    fig.text((L1 - 22) / 1456, fy + 14 / H, GROUP_NAMES[g][0], ha='right', va='center', fontsize=px(LAB - 1), fontweight=900, color=INK)
    fig.text((L1 - 22) / 1456, fy - 22 / H, GROUP_NAMES[g][1], ha='right', va='center', fontsize=px(22.5), color=MUTED)
    t1 = a1.text(n + X1 * 0.02, yc, f"{n:,}", ha='left', va='center', fontsize=px(LAB), fontweight=900, color=INK, clip_on=False, zorder=6)
    fig.canvas.draw(); bb = t1.get_window_extent(fig.canvas.get_renderer()); xr = a1.transData.inverted().transform((bb.x1, 0))[0]
    a1.text(xr + X1 * 0.012, yc, f"{n / n5:.1f}×", ha='left', va='center', fontsize=px(LAB - 5), color=MUTED, clip_on=False, zorder=6)
    a2.text(m + X2 * 0.03, yc, f"{m}", ha='left', va='center', fontsize=px(LAB + 2), fontweight=900, color=DEEP, clip_on=False, zorder=6)
    y += RH
foot(fig, H, FT)
print(save(fig, 'chart3_flood_and_mass_exploitation_by_maker'))
