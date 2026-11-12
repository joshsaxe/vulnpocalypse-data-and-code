"""Rebuild every chart and every number in the post from the data in this repository.

    python run_all.py            # about three minutes; writes output/*.png, output/*.json and NUMBERS.md

Each step is an ordinary script in src/ and can also be run on its own, for example:

    python src/chart3.py

The run stops at the first error. It finishes by printing one line per statement in the post, marked OK or CHECK.
"""
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
STEPS = [
    ('estimates.py', 'delay curves, the 2026 estimates and their back-tests'),
    ('budgets.py', 'application-security budget estimates'),
    ('maturity.py', 'tests of vendor attributes against mass exploitation'),
    ('chart1.py', 'Chart 1'), ('chart2.py', 'Chart 2'), ('chart3.py', 'Chart 3'), ('chart4.py', 'Chart 4'),
    ('chart5.py', 'Chart 5'), ('chart6.py', 'Chart 6'), ('chart7.py', 'Chart 7'), ('chart8.py', 'Chart 8'),
    ('post_numbers.py', 'every number in the text of the post'),
]


def main():
    env = dict(os.environ)
    env.setdefault('MPLBACKEND', 'Agg')
    t0 = time.time()
    for script, what in STEPS:
        print(f"\n=== {script}: {what}", flush=True)
        t = time.time()
        done = subprocess.run([sys.executable, str(ROOT / 'src' / script)], cwd=ROOT, env=env)
        if done.returncode != 0:
            sys.exit(f"{script} failed; stopping")
        print(f"    ({time.time() - t:.0f}s)", flush=True)
    made = sorted(p.name for p in (ROOT / 'output').iterdir())
    print(f"\nDone in {time.time() - t0:.0f}s. {len(made)} files in output/:")
    for name in made:
        print('   ', name)


if __name__ == '__main__':
    main()
