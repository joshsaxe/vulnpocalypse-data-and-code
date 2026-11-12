"""House style for the charts: cream background, Lato, large type for reading on a phone.
Every chart is 1,456 design pixels wide and saved at twice that (2,912 px)."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import textwrap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
from matplotlib.patches import Rectangle
import numpy as np
from study import ROOT, OUT

_fonts = sorted((ROOT / 'fonts').glob('Lato-*.ttf'))
for f in _fonts:
    fm.fontManager.addfont(str(f))
FONT = 'Lato' if _fonts else 'DejaVu Sans'      # falls back if the bundled fonts are missing; layout will shift

BG = '#f9f7f1'; INK = '#2b2a27'; MUTED = '#5c5a54'; GRID = '#dcd7c9'
CLAY = '#a8644a'; DEEP = '#4f2116'; PALE = '#cdc8ba'; PALE_EDGE = '#8f8a7c'
GOLD = '#c99a3f'; GREEN = '#55633f'; TREND = '#8a4f3a'
W_IN = 14.56          # 1456 px at dpi 100
PX = 72 / 100.0       # points per design pixel
T_SIZE = 54; S_SIZE = 31; TICK = 29; LAB = 30; FOOT = 22

plt.rcParams.update({
    'font.family': FONT, 'font.size': 22 * PX, 'text.color': INK, 'axes.edgecolor': INK, 'axes.labelcolor': INK,
    'xtick.color': INK, 'ytick.color': INK, 'figure.facecolor': BG, 'axes.facecolor': BG, 'savefig.facecolor': BG,
    'axes.spines.top': False, 'axes.spines.right': False, 'axes.linewidth': 1.5, 'xtick.major.width': 1.5, 'ytick.major.width': 1.5,
    'xtick.major.size': 6, 'ytick.major.size': 6, 'axes.grid': False,
})


def px(v):
    return v * PX


def fig_h(H):
    fig = plt.figure(figsize=(W_IN, H / 100))
    fig.patch.set_facecolor(BG)
    return fig


def head(fig, H, title, sub):
    """Accent tag, headline, subtitle. Returns y (px from top) where the subtitle ends."""
    fig.patches.append(Rectangle((48 / 1456, 1 - 40 / H), 84 / 1456, 12 / H, transform=fig.transFigure, facecolor=CLAY, edgecolor='none'))
    y = 70
    fig.text(48 / 1456, 1 - y / H, title, fontsize=px(T_SIZE), fontweight=900, color=INK, va='top', ha='left', linespacing=1.1)
    y += (title.count('\n') + 1) * T_SIZE * 1.16 + 16
    fig.text(48 / 1456, 1 - y / H, sub, fontsize=px(S_SIZE), color=MUTED, va='top', ha='left', linespacing=1.25)
    y += (sub.count('\n') + 1) * S_SIZE * 1.27
    return y


def head_h(title, sub):
    return 70 + (title.count('\n') + 1) * T_SIZE * 1.16 + 16 + (sub.count('\n') + 1) * S_SIZE * 1.27


def wrap(text, width=118):
    return '\n'.join(textwrap.wrap(text, width, break_on_hyphens=False))


def foot(fig, H, text, y=34):
    fig.text(48 / 1456, y / H, text, fontsize=px(FOOT), color=MUTED, va='bottom', ha='left', linespacing=1.3)


def foot_h(text):
    return (text.count('\n') + 1) * FOOT * 1.32


def axes_px(fig, H, left, top, width, height):
    return fig.add_axes([left / 1456, 1 - (top + height) / H, width / 1456, height / H])


def ygrid(ax):
    ax.yaxis.grid(True, color=GRID, linewidth=1.4); ax.set_axisbelow(True)
    ax.spines['left'].set_visible(False); ax.tick_params(axis='y', length=0, labelsize=px(TICK), pad=10)
    ax.tick_params(axis='x', labelsize=px(TICK), pad=10, length=0)
    ax.spines['bottom'].set_linewidth(2.2); ax.spines['bottom'].set_color(INK)


def xgrid(ax):
    ax.xaxis.grid(True, color=GRID, linewidth=1.4); ax.set_axisbelow(True)
    ax.spines['bottom'].set_visible(False); ax.tick_params(axis='x', length=0, labelsize=px(TICK), pad=10)
    ax.tick_params(axis='y', length=0)
    ax.spines['left'].set_linewidth(2.2); ax.spines['left'].set_color(INK)


def bracket(ax, x0, x1, y, drop, lw=2.6):
    """A square bracket over the bars that are estimates."""
    ax.plot([x0, x1], [y, y], color=INK, linewidth=px(lw), zorder=6, solid_capstyle='butt')
    for xe in (x0, x1):
        ax.plot([xe, xe], [y, y - drop], color=INK, linewidth=px(lw), zorder=6, solid_capstyle='butt')


def save(fig, name):
    p = OUT / f'{name}.png'
    fig.savefig(p, dpi=200, facecolor=BG)
    plt.close(fig)
    return p
