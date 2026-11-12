"""Chart 5. The four model hyperscalers (Google, Apple, Meta, Amazon): vulnerabilities published and mass-exploited, by year published."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import collections
from style import *
from study import R, mass, grp, words, write_json

YRS = [str(y) for y in range(2019, 2027)]


def series(test):
    return [[sum(1 for r in R if r['pub'][:4] == y and test(r)), sum(1 for r in R if r['pub'][:4] == y and test(r) and mass(r))] for y in YRS]


four = series(lambda r: grp(r) == 'hyperscale'); ms = series(lambda r: grp(r) == 'microsoft'); rest = series(lambda r: grp(r) not in ('hyperscale', 'microsoft'))
n = [a for a, _ in four]; m = [b for _, b in four]
co26 = collections.Counter(r['company'] for r in R if grp(r) == 'hyperscale' and r['pub'][:4] == '2026')
co25 = collections.Counter(r['company'] for r in R if grp(r) == 'hyperscale' and r['pub'][:4] == '2025')
cases = [(r['id'], r['pub'][:4], r['company'], r['prod']) for r in R if grp(r) == 'hyperscale' and mass(r)]
numbers = dict(years=YRS, four=four, microsoft=ms, everyone_else=rest, by_company_2026=dict(co26), by_company_2025=dict(co25), four_mass_cases=cases,
               four_multiple=n[-1] / n[-2], microsoft_multiple=ms[-1][0] / ms[-2][0], everyone_else_multiple=rest[-1][0] / rest[-2][0],
               microsoft_2026_cases=[(r['id'], r['prod']) for r in R if grp(r) == 'microsoft' and r['pub'][:4] == '2026' and mass(r)])
write_json('chart5_numbers.json', numbers)
print('Chart 5: four', four, '| Microsoft', ms[-2:], '| everyone else', rest[-2:], '| 2026 by company', dict(co26), '| cases', cases)

T = "Four hyperscalers' vulnerabilities multiplied.\nMass exploitation of them did not"
SUB = ("Remotely exploitable vulnerabilities in the products of Google, Apple, Meta and\n"
       "Amazon, by year published")
FT = wrap("Vulnerabilities: remotely exploitable ones (code execution, login bypass, SQL injection and similar). 2026 is January 1 to November 9. Mass exploitation: evidence of attacks at scale "
          "(ransomware or botnet use, a place among the 100 most-sighted exploited vulnerabilities in honeypot sensor data, a government or Rapid7 list, or a named campaign with a victim count). "
          f"That evidence arrives late, so 2026's count may rise. Google accounts for {co26['Google']:,} of 2026's {n[-1]:,}. The {words(sum(m))} mass-exploited cases were in Chrome (2022), "
          "the iPhone (two in 2023) and React, Meta's open-source library, which others must update (2025). "
          f"Microsoft is left out because it leaves customers to patch its server products: its count rose {ms[-1][0] / ms[-2][0]:.1f} times ({ms[-2][0]:,} to {ms[-1][0]:,}) and "
          f"{words(ms[-1][1])} have been mass-exploited so far, both in SharePoint Server. For every other maker the count rose {rest[-1][0] / rest[-2][0]:.1f} times ({rest[-2][0]:,} to {rest[-1][0]:,}) "
          f"and {rest[-1][1]} have been mass-exploited so far, against {rest[-2][1]} of 2025's. Sources: NVD; CISA; CIRCL and Shadowserver sensor data; Rapid7; author's classification.")
h1 = 380; h2 = 260; gap = 150
H = int(head_h(T, SUB) + 100 + h1 + gap + h2 + 78 + 40 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
x = np.arange(len(YRS)); LEFT = 130; WID = 1456 - LEFT - 70
top1 = ys + 100
a = axes_px(fig, H, LEFT, top1, WID, h1)
a.set_xlim(-0.6, len(YRS) - 0.4); a.set_ylim(0, 2700); a.set_yticks([0, 500, 1000, 1500, 2000, 2500]); a.set_yticklabels(['0', '500', '1,000', '1,500', '2,000', '2,500']); ygrid(a)
a.set_xticks(x); a.set_xticklabels(YRS)
a.bar(x, n, width=0.66, color=INK, zorder=3)
fig.text(LEFT / 1456, 1 - (top1 - 46) / H, "Vulnerabilities published", fontsize=px(LAB + 1), fontweight=900, color=INK, va='center')
a.text(x[-1] - 0.45, n[-1] - 60, f"{n[-1]:,} so far:\n{words(round(n[-1] / n[-2]))} times 2025", ha='right', va='top', fontsize=px(LAB), fontweight=900, color=INK, linespacing=1.15)
top2 = top1 + h1 + gap
b = axes_px(fig, H, LEFT, top2, WID, h2)
ymax = max(4, max(m) + 2)
b.set_xlim(-0.6, len(YRS) - 0.4); b.set_ylim(0, ymax + 0.2); b.set_yticks(list(range(0, ymax + 1, 1 if ymax <= 5 else 2))); ygrid(b)
b.set_xticks(x); b.set_xticklabels(YRS)
b.bar(x[:-1], m[:-1], width=0.66, color=CLAY, zorder=3); b.bar(x[-1:], m[-1:], width=0.66, color=DEEP, zorder=3)
for xi, vv in zip(x, m):
    b.text(xi, vv + 0.12, (f"{vv} so far" if xi == x[-1] else str(vv)), ha='center', va='bottom', fontsize=px(LAB - 2), fontweight=900, color=(DEEP if xi == x[-1] else CLAY))
fig.text(LEFT / 1456, 1 - (top2 - 46) / H, "Of which mass-exploited", fontsize=px(LAB + 1), fontweight=900, color=CLAY, va='center')
foot(fig, H, FT)
print(save(fig, 'chart5_four_hyperscalers'))
