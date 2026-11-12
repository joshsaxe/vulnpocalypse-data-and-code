"""Chart 1. Vulnerabilities of the most dangerous class, by quarter published.
The class: no login, no click, in internet-facing enterprise software (study.cls)."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import collections, json, math
from style import *
from study import R, cls, quarter, words, write_json
import estimates as E

C = [r for r in R if cls(r)]
QS = E.QS
pub = collections.Counter(quarter(r['pub']) for r in C)
P = [pub[q] for q in QS]
p25 = np.mean([pub[f'2025Q{q}'] for q in range(1, 5)])
est_pub, october = E.project_publications(C)
bt = E.backtests(C)['publications']
oracle = sum(1 for r in C if quarter(r['pub']) == '2026Q3' and r['vendor'] == 'oracle')
no_orc = lambda q: sum(1 for r in C if quarter(r['pub']) == q and r['vendor'] != 'oracle')
mult = pub['2026Q3'] / p25
mult_no_oracle = no_orc('2026Q3') / np.mean([no_orc(f'2025Q{q}') for q in range(1, 5)])
miss = 100 * (math.exp(bt['mean_abs_log_error']) - 1)
N = dict(per_quarter=dict(zip(QS, P)), avg_2025=float(p25), q3_2026=pub['2026Q3'], multiple=float(mult), oracle_q3=oracle,
         multiple_without_oracle=float(mult_no_oracle), october=october, est_q4=est_pub, q4_so_far=pub['2026Q4'], backtest_typical_miss_pct=miss,
         code_execution_q3=sum(1 for r in C if quarter(r['pub']) == '2026Q3' and r['rce']))
write_json('chart1_numbers.json', N)
print('Chart 1:', {k: (round(v, 2) if isinstance(v, float) else v) for k, v in N.items() if k != 'per_quarter'})

x = np.arange(len(QS)); iq3 = QS.index('2026Q3'); iq4 = QS.index('2026Q4')
T = f"The most dangerous vulnerabilities are now\nbeing published {words(round(mult))} times as fast"
SUB = ("New vulnerabilities that let a stranger break into an internet-facing business\n"
       "system with no login and no click. Number published per quarter")
FT = wrap("Vulnerabilities: CVE records, by date published, that need neither a login nor a user's click and give a remote attacker code execution or full control "
          "of internet-facing enterprise software (firewalls, VPN gateways, mail, file-transfer and web servers): remote code execution, login bypasses, SQL injection "
          f"and similar; classification by the author. Oracle alone published {oracle} of the {pub['2026Q3']} in July–September 2026; without Oracle the rise is {mult_no_oracle:.1f}-fold. "
          f"The October–December 2026 bar is an estimate at October's pace ({october} in the month); tested on 13 earlier quarters, that rule's typical miss was {miss:.0f}%. "
          f"By November 9, {pub['2026Q4']} had been published. Sources: NVD; CVE Program; author's analysis.")
hgt = 700; YMAX = 860
H = int(head_h(T, SUB) + 56 + hgt + 78 + 40 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
a = axes_px(fig, H, 110, ys + 56, 1456 - 110 - 60, hgt)
yt = [0, 200, 400, 600, 800]
a.set_xlim(-0.75, len(QS) - 0.25); a.set_ylim(0, YMAX); a.set_yticks(yt); a.set_yticklabels([f'{t:,}' for t in yt]); ygrid(a)
a.set_xticks([4 * i + 1.5 for i in range(5)]); a.set_xticklabels(['2022', '2023', '2024', '2025', '2026'])
for i in range(1, 5):
    a.plot([4 * i - 0.5] * 2, [0, -YMAX * 0.035], color=INK, linewidth=1.6, clip_on=False)
foot(fig, H, FT)
a.bar(x[:iq4], P[:iq4], width=0.74, color=INK, zorder=3)
a.bar([iq4], [est_pub], width=0.74, color=INK, zorder=3)
a.plot([QS.index('2025Q1') - 0.45, QS.index('2025Q4') + 0.45], [p25, p25], color=CLAY, linewidth=px(5), zorder=5, solid_capstyle='butt')
a.annotate(f"2025 average:\n{p25:.0f} a quarter", xy=(QS.index('2025Q2') + 0.5, p25 + 8), xytext=(QS.index('2024Q4') + 0.2, 330), ha='center', va='bottom',
           fontsize=px(LAB), fontweight=900, color=CLAY, linespacing=1.15, arrowprops=dict(arrowstyle='-', color=CLAY, lw=px(2.4), shrinkA=4, shrinkB=2))
a.text(iq3 - 0.55, P[iq3] + 8, f"{P[iq3]} in Jul–Sep 2026", ha='right', va='bottom', fontsize=px(LAB + 2), fontweight=900, color=INK)
yb = est_pub + 20
bracket(a, iq4 - 0.42, iq4 + 0.42, yb, 15)
a.text(iq4 + 0.42, yb + 12, f"Estimate: Oct–Dec at October's pace, about {round(est_pub, -1):.0f}", ha='right', va='bottom', fontsize=px(LAB - 3), fontweight=900, color=INK,
       bbox=dict(facecolor=BG, edgecolor='none', pad=3), zorder=7)
print(save(fig, 'chart1_vulnerabilities_published'))
