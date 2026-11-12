"""Chart 2. The same class, by quarter published: no known exploitation, some exploitation, mass exploitation.
Top panel: every vulnerability. Bottom panel: the attacked ones, enlarged.
The 2026 bars are estimates (estimates.py); a bracket and a callout mark them."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from style import *
from study import words, write_json
import estimates as E

B = E.build()
write_json('estimates.json', B)
QS = E.QS
P = B['P']; x = np.arange(len(QS)); i26 = QS.index('2026Q1'); iq3 = QS.index('2026Q3'); iq4 = QS.index('2026Q4')
n = [P[q]['n'] for q in QS]; a_obs = [P[q]['any'] for q in QS]; m_obs = [P[q]['mass'] for q in QS]
a_est = [P[q]['est_any'] if q >= '2026Q1' else P[q]['any'] for q in QS]
m_est = [P[q]['est_mass'] if q >= '2026Q1' else P[q]['mass'] for q in QS]
EST_PUB = B['est_pub']
n_est = list(n); n_est[iq4] = EST_PUB                      # October-December at October's pace, as in Chart 1
y5, y6 = B['year2025'], B['year2026']
a25 = y5['any'] / 4; m25 = y5['mass'] / 4
print(f"Chart 2: 2025 {y5} | 2026 estimate n {y6['n']} attacked {y6['any']:.1f} mass {y6['mass']:.1f} | multiples "
      f"{y6['n'] / y5['n']:.2f} {y6['any'] / y5['any']:.2f} {y6['mass'] / y5['mass']:.2f}")
print('  2026 by quarter, attacked:', [round(v, 1) for v in a_est[i26:]], 'mass:', [round(v, 1) for v in m_est[i26:]], 'days elapsed in Oct-Dec:', B['days_elapsed'])

days = B['days_elapsed']
T = "Attacks have grown far less than the flood.\nMass exploitation has grown least"
SUB = ("The same kind of vulnerability (internet-facing, no login, no click), by quarter\n"
       "published and by what attackers have done with it")
FT = wrap("Some exploitation: known to have been attacked, with no evidence of scale. Mass exploitation: evidence of attacks at scale (ransomware or botnet use, "
          "a place among the 100 most-sighted exploited vulnerabilities in honeypot sensor data, a government or Rapid7 list, or a named campaign with a victim count). "
          "Estimates: the 2026 bars add the evidence still to come for vulnerabilities already published, judged by how long it took for earlier ones "
          f"(CISA listings since 2022, sensor rankings since late 2024). October–December is projected from its first {days} days: publications continue at October's pace "
          f"and attacked vulnerabilities keep arriving at the July–September pace. It rests on {words(int(a_obs[iq4]))} attacked so far and is the least certain bar. "
          "Data to November 9, 2026. Sources: NVD; CISA; CIRCL and Shadowserver sensor data; Rapid7; government advisories; author's analysis.")
hA, hB = 300, 580
H = int(head_h(T, SUB) + 50 + 46 + hA + 66 + 46 + hB + 78 + 40 + foot_h(FT) + 34)
fig = fig_h(H); ys = head(fig, H, T, SUB)
L, Wd = 110, 1456 - 110 - 60
W = 0.74


def base_axes(top, hgt, ymax, yticks, xlabels):
    a = axes_px(fig, H, L, top, Wd, hgt)
    a.set_xlim(-0.75, len(QS) - 0.25); a.set_ylim(0, ymax); a.set_yticks(yticks); a.set_yticklabels([f'{t:,}' for t in yticks]); ygrid(a)
    if xlabels:
        a.set_xticks([4 * i + 1.5 for i in range(5)]); a.set_xticklabels(['2022', '2023', '2024', '2025', '2026'])
    else:
        a.set_xticks([])
    for i in range(1, 5):
        a.plot([4 * i - 0.5] * 2, [0, -ymax * 0.035], color=INK, linewidth=1.6, clip_on=False)
    return a


# ---------------- panel A: every vulnerability
yA = ys + 50
fig.text(L / 1456, 1 - yA / H, "Every vulnerability published", fontsize=px(LAB), fontweight=900, color=INK, va='top', ha='left')
YA = 1.16 * EST_PUB
A = base_axes(yA + 46, hA, YA, [t for t in range(0, int(YA) + 1, 200)], False)
for i, q in enumerate(QS):
    A.bar([i], [m_est[i]], width=W, color=DEEP, zorder=4)
    A.bar([i], [a_est[i] - m_est[i]], bottom=[m_est[i]], width=W, color=CLAY, zorder=4)
    A.bar([i], [n_est[i] - a_est[i]], bottom=[a_est[i]], width=W, color=PALE, zorder=3)
A.text(iq3 - 0.58, max(n[iq3 - 1], n[iq3 - 2]) + 0.29 * YA, "No known\nexploitation", ha='right', va='top', fontsize=px(LAB - 2), fontweight=900, color=MUTED, linespacing=1.15)
A.text(9.0, 0.42 * YA, "Attacked: the colored base of each bar", ha='center', va='bottom', fontsize=px(LAB - 2), fontweight=900, color=CLAY)
A.plot([9.0, 9.0], [0.41 * YA, 0.028 * YA], color=CLAY, linewidth=px(2.4), zorder=6)
A.text(iq4 + 0.42, EST_PUB + 0.025 * YA, "Oct–Dec: estimate, at October's pace", ha='right', va='bottom', fontsize=px(LAB - 6), fontweight=900, color=INK,
       bbox=dict(facecolor=BG, edgecolor='none', pad=3), zorder=7)

# ---------------- panel B: the attacked vulnerabilities, enlarged
yB = yA + 46 + hA + 66
fig.text(L / 1456, 1 - yB / H, "The attacked vulnerabilities, enlarged", fontsize=px(LAB), fontweight=900, color=INK, va='top', ha='left')
top_bar = max(a_est)
K = top_bar / 29.7                                          # vertical unit, so labels keep their place if the data change
YM = 39.5 * K
Bx = base_axes(yB + 46, hB, YM, list(range(0, int(YM) + 1, 10 if YM <= 65 else 20)), True)
for i, q in enumerate(QS):
    Bx.bar([i], [m_est[i]], width=W, color=DEEP, zorder=4)
    Bx.bar([i], [a_est[i] - m_est[i]], bottom=[m_est[i]], width=W, color=CLAY, zorder=4)
lx, ly, dy = -0.35, 35.6 * K, 3.6 * K


def key(row, label, color):
    y0 = ly - row * dy
    Bx.bar([lx + 0.3], [1.9 * K], bottom=[y0 - 0.95 * K], width=0.6, color=color, zorder=5)
    Bx.text(lx + 0.9, y0, label, ha='left', va='center', fontsize=px(LAB - 2), fontweight=900, color=color)


key(0, "Some exploitation", CLAY); key(1, "Mass exploitation", DEEP)
Bx.text(12.55, 12.5 * K, f"2025: {a25:.0f} attacked a quarter,\n{m25:.0f} of them at scale", ha='center', va='bottom', fontsize=px(LAB - 3), fontweight=900, color=INK, linespacing=1.15)
Bx.text(iq3 - 0.55, 28.4 * K, f"Jul–Sep: {a_obs[iq3]:.0f} attacked so far,\nabout {a_est[iq3]:.0f} expected", ha='right', va='top', fontsize=px(LAB - 3), fontweight=900, color=INK, linespacing=1.15,
        bbox=dict(facecolor=BG, edgecolor='none', pad=3), zorder=7)
yb = top_bar + 1.5 * K
bracket(Bx, i26 - 0.42, iq4 + 0.42, yb, 0.8 * K)
Bx.text(iq4 + 0.42, yb + 0.7 * K, "Estimates: the 2026 bars add attacks not yet reported.\n"
        f"Oct–Dec is projected from its first {days} days: about {a_est[iq4]:.0f}, {m_est[iq4]:.0f} at scale",
        ha='right', va='bottom', fontsize=px(LAB - 3), fontweight=900, color=INK, linespacing=1.15, bbox=dict(facecolor=BG, edgecolor='none', pad=3), zorder=7)
foot(fig, H, FT)
print(save(fig, 'chart2_no_some_mass_exploitation'))
