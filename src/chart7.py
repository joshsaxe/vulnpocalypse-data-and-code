"""Chart 7. The layers of a well-defended software security operation, and how far AI can automate each.
Where each layer sits is the author's judgment. To move one, change its 'placement' in data/layers.csv:
0 = AI does most of it today, 1 = within reach soon, 2 = people still lead."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import csv, collections
from style import *
from study import R, DATA, mass, opn, write_json

O = [r for r in R if '2019-01-01' <= r['pub'] <= '2025-12-31' and opn(r) and r['zd']]
share = lambda u: round(100 * sum(mass(r) for r in O if r['upd'] == u) / sum(1 for r in O if r['upd'] == u))
fill = dict(with_pct=share('vendor'), without_pct=share('customer'))
GROUPS = collections.OrderedDict()
for r in csv.DictReader(open(DATA / 'layers.csv', encoding='utf-8')):
    GROUPS.setdefault(r['group'], []).append((r['layer'], r['evidence'].format(**fill), int(r['placement'])))
COLS = ["AI does most\nof it today", "Within\nreach soon", "People\nstill lead"]
CC = [DEEP, GOLD, PALE_EDGE]
n = [sum(1 for rows in GROUPS.values() for r in rows if r[2] == k) for k in range(3)]
write_json('chart7_numbers.json', dict(placement_counts=n, update_shares=fill))
print('Chart 7: placements', n, fill)

T = "AI can staff much of the fortress,\nbut not all of it"
SUB = ("Nine layers of a well-defended software security operation, and how far AI agents\n"
       "can automate each. Author's assessment")
FT = wrap("Where each layer sits is the author's judgment, informed by the public results quoted beneath it; it is not a measurement. \"Soon\" means plausible within a year or two with "
          "today's best models. The dependency figure is Anthropic's count of vulnerabilities it reported to open-source maintainers and those fixed by October 2, 2026. The update figure is the "
          "share of zero-days needing no login and no click, 2019–2025, that spread to mass exploitation where the vendor installs the fix and where the customer must (Chart 4). "
          "Sources: DARPA; Mozilla, via CyberScoop; Google DeepMind; Google Threat Intelligence Group; Anthropic, via VentureBeat; author's analysis of NVD, CISA and CIRCL data.")
RH = 104; GH = 66; HEADH = 96
body_h = sum(GH + RH * len(rows) for rows in GROUPS.values())
H = int(head_h(T, SUB) + 40 + HEADH + body_h + 56 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
a = fig.add_axes([0, 0, 1, 1]); a.set_xlim(0, 1456); a.set_ylim(H, 0); a.axis('off'); a.patch.set_alpha(0)
CX = [1010, 1190, 1362]; X0 = 48; X1 = 1456 - 40
y = ys + 40
for cx, lab, col in zip(CX, COLS, CC):
    a.text(cx, y + HEADH / 2 - 6, lab, ha='center', va='center', fontsize=px(25), fontweight=900, color=INK, linespacing=1.12)
y += HEADH
a.plot([X0, X1], [y, y], color=INK, linewidth=2.2)
for gname, rows in GROUPS.items():
    a.add_patch(Rectangle((X0, y), X1 - X0, GH, facecolor='#efe9d8', edgecolor='none', zorder=1))
    a.text(X0 + 14, y + GH / 2, gname.upper(), ha='left', va='center', fontsize=px(24), fontweight=900, color=TREND)
    y += GH
    for name, ev, k in rows:
        a.text(X0, y + 36, name, ha='left', va='center', fontsize=px(LAB - 1), fontweight=900, color=INK)
        a.text(X0, y + 74, ev, ha='left', va='center', fontsize=px(21), color=MUTED)
        for j, cx in enumerate(CX):
            if j == k:
                a.scatter([cx], [y + RH / 2], s=(46 * PX) ** 2, color=CC[j], zorder=4)
            else:
                a.scatter([cx], [y + RH / 2], s=(13 * PX) ** 2, color=GRID, zorder=3)
        y += RH
        a.plot([X0, X1], [y, y], color=GRID, linewidth=1.4)
a.plot([X0, X1], [y, y], color=INK, linewidth=2.2)
foot(fig, H, FT)
print(save(fig, 'chart7_layers_and_ai'))
