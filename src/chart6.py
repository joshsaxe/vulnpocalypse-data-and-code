"""Chart 6. Estimated application-security budgets at four hyperscalers, against the entire revenue of
mid-market software vendors and the budgets behind open source."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv
from style import *
from study import PANEL, DATA, write_json
import budgets

EST = budgets.estimate()
write_json('budget_estimates.json', EST)


def rev(name):
    return float(PANEL[name]['revenue']) / 1000.0


mid = [float(r['revenue']) for r in PANEL.values() if r['group'] in ('midsize', 'netsec') and r['revenue'] and float(r['revenue']) < 5000]
med = float(np.median(mid)) / 1000.0
q1, q3 = (float(v) / 1000.0 for v in np.percentile(mid, [25, 75]))
FOUR = ('Amazon', 'Alphabet', 'Meta', 'Apple')
G1 = [(EST[k]['label'], None, round(EST[k]['combined'][1], 1), 'est') for k in FOUR]
RNG = {EST[k]['label']: (EST[k]['combined'][0], EST[k]['combined'][2]) for k in FOUR}
MS = EST['Microsoft']['combined']
G2 = [('Progress Software', 'maker of MOVEit', rev('Progress'), 'rev'), ('GitLab', None, rev('GitLab'), 'rev'), ('Ivanti', 'private; estimate', rev('Ivanti'), 'est2'),
      ('SolarWinds', None, rev('SolarWinds'), 'rev'), (f'Median of {len(mid)} vendors', None, med, 'med'), ('JFrog', None, rev('JFrog'), 'rev'), ('N-able', None, rev('N-able'), 'rev')]
G3 = [(r['name'], r['note'], float(r['usd_m']) / 1000.0, 'oss') for r in csv.DictReader(open(DATA / 'open_source_budgets.csv', encoding='utf-8'))]
exceed = {EST[k]['label']: sum(1 for m in mid if m < EST[k]['combined'][1] * 1000) for k in FOUR}
factor = float(np.mean([EST[k]['factor'] for k in FOUR]))
write_json('chart6_numbers.json', dict(estimates={k: EST[k] for k in EST}, midmarket_median_bn=med, midmarket_quartiles_bn=[q1, q3], midmarket_n=len(mid),
                                        estimate_exceeds_revenue_of_n_vendors=exceed, revenue_bn={g[0]: g[2] for g in G2}, open_source_bn={g[0]: g[2] for g in G3}, typical_factor=factor))
print('Chart 6:', {k: [round(x, 2) for x in EST[k]['combined']] for k in EST}, '| mid-market median', med, 'n', len(mid), '| estimate exceeds revenue of', exceed, 'vendors | factor', round(factor, 2))

T = "A security budget the size of\na software company"
SUB = ("Estimated yearly application-security spending at four hyperscalers, against the\n"
       "entire revenue of mid-market software vendors and the money behind open source")
FT = wrap("Hyperscaler budgets are the author's estimates; no company publishes one. Each combines two routes: engineers times an assumed 1–4% working on application security times "
          f"cost per head, and software-development spending times an assumed 0.6–3.5%. Lines show the 90% range, about a factor of {factor:.1f} either way. Google is Alphabet. "
          f"Microsoft on the same method: about \\${MS[1]:.1f}bn (\\${MS[0]:.1f}bn to \\${MS[2]:.1f}bn). For scale, in 2021 Google pledged \\$10bn over five years to security of all kinds. "
          f"Revenue: latest fiscal year in company filings; Ivanti is private, estimated from two reported quarters. Median: {len(mid)} mid-market vendors of enterprise and "
          "network-security software in the author's panel. Apache: spending implied by reported revenue and net income for the year to April 2026. Alpha-Omega is the Open Source "
          "Security Foundation's grant program. Sources: company filings; BSIMM; Apache Software Foundation; OpenSSF; author's estimates.")
RH = 78; GH = 74
groups = [("Estimated application-security budget, a year", G1), ("Entire annual revenue: mid-market software vendors", G2), ("Open source: the whole budget", G3)]
plot_h = sum(GH + RH * len(g) for _, g in groups) + 10
H = int(head_h(T, SUB) + 44 + plot_h + 104 + 44 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
top = ys + 44
LEFT = 480; WID = 700; XMAX = 2.6
a = axes_px(fig, H, LEFT, top, WID, plot_h)
a.set_xlim(0, XMAX); a.set_ylim(plot_h, 0); a.set_yticks([]); a.set_xticks([0, 0.5, 1.0, 1.5, 2.0, 2.5]); a.set_xticklabels(['0', '0.5', '1.0', '1.5', '2.0', '$2.5bn']); xgrid(a)
a.spines['left'].set_visible(False)
y = 0
for gname, rows in groups:
    fig.text(48 / 1456, 1 - (top + y + GH / 2 + 6) / H, gname, fontsize=px(LAB - 2), fontweight=900, color=TREND, va='center')
    a.add_patch(Rectangle((-0.01, y), XMAX + 0.05, GH - 6, facecolor=BG, edgecolor='none', zorder=2))
    y += GH
    a.plot([0, 0], [y - 4, y + RH * len(rows) - 8], color=INK, linewidth=2.2, zorder=5, clip_on=False)
    for lab, sub, v, kind in rows:
        yc = y + RH / 2 - 6
        if kind == 'est':
            a.barh(yc, v, height=44, color=CLAY, zorder=3)
            a.plot(RNG[lab], [yc, yc], color=DEEP, linewidth=3.2, zorder=4, solid_capstyle='butt')
            for xx in RNG[lab]:
                a.plot([xx, xx], [yc - 10, yc + 10], color=DEEP, linewidth=3.2, zorder=4)
        elif kind == 'med':
            a.barh(yc, v, height=44, color=GOLD, zorder=3)
        elif kind == 'oss':
            a.barh(yc, max(v, 0.004), height=44, color=GREEN, zorder=3)
        else:
            a.barh(yc, v, height=44, color=INK, zorder=3)
        fy = 1 - (top + yc) / H
        if sub:
            fig.text((LEFT - 20) / 1456, fy + 13 / H, lab, ha='right', va='center', fontsize=px(LAB - 2), fontweight=900, color=INK)
            fig.text((LEFT - 20) / 1456, fy - 20 / H, sub, ha='right', va='center', fontsize=px(21.5), color=MUTED)
        else:
            fig.text((LEFT - 20) / 1456, fy, lab, ha='right', va='center', fontsize=px(LAB - 2), fontweight=900, color=INK)
        if kind == 'oss':
            s = f"${v * 1000:.1f}m" if v * 1000 < 3 else f"${v * 1000:.0f}m"
        elif kind in ('est', 'est2'):
            s = f"about ${v:.1f}bn"
        else:
            s = f"${v:.2f}bn"
        a.text((RNG[lab][1] if kind == 'est' else max(v, 0.004)) + 0.03, yc, s, ha='left', va='center', fontsize=px(LAB), fontweight=900, color=(CLAY if kind == 'est' else INK), clip_on=False, zorder=6)
        y += RH
foot(fig, H, FT)
print(save(fig, 'chart6_security_budget_and_revenue'))
