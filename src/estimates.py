"""Estimates for 2026: how many vulnerabilities of the class will end up attacked, and mass-exploited,
once evidence that is still arriving has arrived. Used by Charts 1 and 2.

Three pieces, each back-tested where the data allow (see backtests() below):

1. Publications in October-December are projected at October's pace (first month x 3).
2. For vulnerabilities already published, the observed counts are scaled up by the share of evidence that
   should have arrived by now. Two reporting-delay curves, both corrected for right truncation:
     - attacked at all: days from publication to listing in CISA's catalog (class, published since 2022);
     - mass exploitation: quarters from publication to first appearance in a sensor top-100 list (since 2024Q4).
3. For the rest of October-December, attacked vulnerabilities are assumed to keep arriving at the previous
   quarter's pace. (An earlier draft applied the previous quarter's rate per vulnerability to the projected
   publications; back-tested, that ran 16% high, because attacks have not kept pace with publications.)

Run:  python src/estimates.py      -> output/estimates.json and a printed summary
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import collections, datetime, math, statistics
import numpy as np
from study import R, SENSOR, SNAPSHOT, cls, mass, attacked, quarter, D, write_json

CUT = SNAPSHOT
QS = [f'{y}Q{q}' for y in range(2022, 2027) for q in range(1, 5)]
KEV_FROM = '2022-01-01'      # CISA's catalog began in November 2021; earlier vulnerabilities were listed in bulk
SENSOR_FROM = '2024Q4'       # first quarter with the Shadowserver honeypot feed


def qidx(q):
    return int(q[:4]) * 4 + int(q[5]) - 1


def qname(i):
    return f'{i // 4}Q{i % 4 + 1}'


def qstart(q):
    return datetime.date(int(q[:4]), 3 * (int(q[5]) - 1) + 1, 1)


def qdays(q):
    return (qstart(qname(qidx(q) + 1)) - qstart(q)).days


def kevd(r):
    return r['kev'] and r['kev_date']


# ------------------------------------------------------------------------------------------- delay curves

def kev_delays(pop, cut=CUT, lo=KEV_FROM):
    """(days from publication to CISA listing, longest delay observable by the cutoff) for listed vulnerabilities."""
    out = []
    for r in pop:
        if not kevd(r) or r['pub'] < lo or D(r['pub']) > cut or D(r['kev_date']) > cut:
            continue
        out.append((max((D(r['kev_date']) - D(r['pub'])).days, 0), (cut - D(r['pub'])).days))
    return out


def trunc_cdf(pairs, dmax):
    """Product-limit estimate of F(d) = P(delay <= d | delay <= dmax) from right-truncated (delay, limit) pairs."""
    pairs = [(d, t) for d, t in pairs if d <= dmax]
    F = {}
    cur = 1.0
    for m in sorted(set(d for d, _ in pairs), reverse=True):
        F[m] = cur
        dm = sum(1 for d, t in pairs if d == m and t >= m)
        nm = sum(1 for d, t in pairs if d <= m and t >= m)
        if nm:
            cur *= (1 - dm / nm)
    keys = sorted(F)

    def f(x):
        x = min(x, dmax)
        best = 0.0
        for k in keys:
            if k <= x:
                best = F[k]
            else:
                break
        return best
    return f, len(pairs)


FIRST_SENSOR_Q = {i: quarter(min(per)) for i, per in SENSOR.items()}


def sensor_lags(pop, last_q='2026Q4', lo=SENSOR_FROM):
    """(quarters from publication to first sensor top-100 list, most quarters observable)."""
    out = []
    for r in pop:
        q = quarter(r['pub'])
        if q < lo or r['id'] not in FIRST_SENSOR_Q or r['role'] == 'client_os':
            continue
        out.append((max(qidx(FIRST_SENSOR_Q[r['id']]) - qidx(q), 0), qidx(last_q) - qidx(q)))
    return out


# ------------------------------------------------------------------------------------------- the estimates

def project_publications(C, q='2026Q4'):
    """October-December publications at October's pace."""
    m1 = qstart(q).month
    first_month = sum(1 for r in C if quarter(r['pub']) == q and D(r['pub']).month == m1)
    return 3 * first_month, first_month


def point(C, Fk, Fm, est_pub, counts=None, last_q='2026Q4', cut=CUT):
    byq = collections.defaultdict(list)
    for r in C:
        byq[quarter(r['pub'])].append(r)
    out = {}
    for q in QS:
        rs = byq[q]
        n = len(rs)
        a = sum(attacked(r) for r in rs)
        m = sum(mass(r) for r in rs)
        if counts:
            a, m = counts[q]
        ca = sum(Fk((cut - D(r['pub'])).days) for r in rs) / n if n else 1.0
        cm = Fm(qidx(last_q) - qidx(q))
        ea = a / ca if ca else a
        em = m / cm if cm else m
        out[q] = dict(n=n, any=a, mass=m, c_any=ca, c_mass=cm, est_any=ea, est_mass=(em if counts else min(em, ea)))
    # October-December: what is already published, lag-adjusted, plus the rest of the quarter at the
    # previous quarter's pace of attacked vulnerabilities.
    q3, q4 = out['2026Q3'], out[last_q]
    left = (qdays(last_q) - ((cut - qstart(last_q)).days + 1)) / qdays(last_q)
    q4['est_any_pub'], q4['est_mass_pub'] = q4['est_any'], q4['est_mass']
    q4['est_any'] = q4['est_any_pub'] + left * q3['est_any']
    q4['est_mass'] = q4['est_mass_pub'] + left * q3['est_mass']
    q4['est_n'] = est_pub
    q4['share_of_quarter_left'] = left
    return out


def build(seed=11, reps=4000):
    C = [r for r in R if cls(r)]
    est_pub, october = project_publications(C)
    kev_pairs = kev_delays(C)
    lag_pairs = sensor_lags(R)
    Fk, nk = trunc_cdf(kev_pairs, 730)
    Fm, nm = trunc_cdf(lag_pairs, 8)
    P = point(C, Fk, Fm, est_pub)
    bt = backtests(C)
    s_q = bt['quarter_rule']['log_error_sd']          # spread of the full-quarter rule in the back-test
    s_p = bt['publications']['log_error_sd']
    # uncertainty: resample both delay samples; observed counts as gamma(count + 0.5);
    # October-December widened by the back-tested error of the full-quarter rule
    rng = np.random.default_rng(seed)
    sims = collections.defaultdict(list)
    obs = {q: (P[q]['any'], P[q]['mass']) for q in QS}
    for _ in range(reps):
        kp = [kev_pairs[i] for i in rng.integers(0, len(kev_pairs), len(kev_pairs))]
        lp = [lag_pairs[i] for i in rng.integers(0, len(lag_pairs), len(lag_pairs))]
        fk, _ = trunc_cdf(kp, 730)
        fm, _ = trunc_cdf(lp, 8)
        cnt = {}
        for q in QS:
            a, m = obs[q]
            if q >= '2026Q1':
                m2 = rng.gamma(m + 0.5, 1.0)
                s2 = rng.gamma((a - m) + 0.5, 1.0)
                cnt[q] = (m2 + s2, m2)
            else:
                cnt[q] = (a, m)
        S = point(C, fk, fm, est_pub, cnt)
        w = math.exp(rng.normal(0, s_q))
        S['2026Q4']['est_any'] *= w
        S['2026Q4']['est_mass'] *= w
        for q in QS:
            if q >= '2026Q1':
                sims[q + ':any'].append(S[q]['est_any'])
                sims[q + ':mass'].append(S[q]['est_mass'])
        sims['2026:any'].append(sum(S[f'2026Q{k}']['est_any'] for k in range(1, 5)))
        sims['2026:mass'].append(sum(S[f'2026Q{k}']['est_mass'] for k in range(1, 5)))
        sims['2026todate:any'].append(sum(S[f'2026Q{k}']['est_any'] for k in range(1, 4)) + S['2026Q4']['est_any_pub'])
        sims['2026todate:mass'].append(sum(S[f'2026Q{k}']['est_mass'] for k in range(1, 4)) + S['2026Q4']['est_mass_pub'])
        sims['2026Q4:n'].append(est_pub * math.exp(rng.normal(0, s_p)))
    ranges = {k: [float(x) for x in np.percentile(v, [5, 50, 95])] for k, v in sims.items()}
    y25 = {f: sum(P[f'2025Q{k}'][f] for k in range(1, 5)) for f in ('n', 'any', 'mass')}
    y26 = dict(n=sum(P[f'2026Q{k}']['n'] for k in range(1, 4)) + est_pub,
               any=sum(P[f'2026Q{k}']['est_any'] for k in range(1, 5)), mass=sum(P[f'2026Q{k}']['est_mass'] for k in range(1, 5)),
               n_so_far=sum(P[f'2026Q{k}']['n'] for k in range(1, 5)),
               any_so_far=sum(P[f'2026Q{k}']['any'] for k in range(1, 5)), mass_so_far=sum(P[f'2026Q{k}']['mass'] for k in range(1, 5)),
               any_published_only=sum(P[f'2026Q{k}']['est_any'] for k in range(1, 4)) + P['2026Q4']['est_any_pub'],
               mass_published_only=sum(P[f'2026Q{k}']['est_mass'] for k in range(1, 4)) + P['2026Q4']['est_mass_pub'])
    return dict(P=P, ranges=ranges, n_kev_delays=nk, n_sensor_lags=nm, est_pub=est_pub, october=october,
                days_elapsed=(CUT - qstart('2026Q4')).days + 1,
                Fk={str(d): Fk(d) for d in (7, 30, 90, 180, 365)}, Fm={str(k): Fm(k) for k in range(0, 5)},
                year2025=y25, year2026=y26, backtests=bt)


# ------------------------------------------------------------------------------------------- back-tests

def backtests(C):
    """What the rules above would have said at day 40 of past quarters, against what is known now.
    Only CISA listings carry dates, so the tests cover 'attacked' and publications, not mass exploitation."""
    now_pairs = kev_delays(C)
    Fnow, _ = trunc_cdf(now_pairs, 730)
    rows = []
    for i in range(qidx('2023Q3'), qidx('2026Q3') + 1):
        q = qname(i)
        T = qstart(q) + datetime.timedelta(days=39)
        F, n = trunc_cdf(kev_delays(C, cut=T), 730)

        def part(qq, T=T, F=F):
            pop = [r for r in C if quarter(r['pub']) == qq and D(r['pub']) <= T]
            obs = sum(1 for r in pop if kevd(r) and D(r['kev_date']) <= T)
            comp = sum(F((T - D(r['pub'])).days) for r in pop) / len(pop)
            now = sum(1 for r in pop if kevd(r))
            return len(pop), obs, obs / comp, now
        n0, o0, e0, t0 = part(q)
        n1, o1, e1, t1 = part(qname(i - 1))
        full = [r for r in C if quarter(r['pub']) == q]
        listed = sum(1 for r in full if kevd(r))
        comp_now = sum(Fnow((CUT - D(r['pub'])).days) for r in full) / len(full)
        m1 = sum(1 for r in full if D(r['pub']).month == qstart(q).month)
        shares = []
        for b in range(1, 5):
            qq = qname(i - b)
            allq = [r for r in C if quarter(r['pub']) == qq]
            shares.append(sum(1 for r in allq if (D(r['pub']) - qstart(qq)).days <= 39) / len(allq))
        left = (qdays(q) - 40) / qdays(q)
        rows.append(dict(quarter=q, cutoff=T.isoformat(), sample=n,
                         cur_obs=o0, cur_est=e0, cur_now=t0, prev_obs=o1, prev_est=e1, prev_now=t1,
                         pubs=len(full), pubs_first_month_x3=3 * m1, pubs_same_point=n0 / statistics.mean(shares),
                         listed_now=listed, listed_adjusted=listed / comp_now,
                         rule_pace=e0 + left * e1, rule_rate=e0 + max(3 * m1 - n0, 0) * e1 / n1))

    def lerr(a, b):
        return [math.log(r[a] / r[b]) for r in rows]

    def summ(a, b):
        e = lerr(a, b)
        return dict(total_estimate=sum(r[a] for r in rows), total_actual=sum(r[b] for r in rows),
                    ratio=sum(r[a] for r in rows) / sum(r[b] for r in rows),
                    mean_abs_log_error=sum(abs(x) for x in e) / len(e), log_error_sd=statistics.pstdev(e),
                    worst_low=min(math.exp(x) for x in e), worst_high=max(math.exp(x) for x in e))
    done = [r for r in rows if r['quarter'] <= '2026Q2']        # delay test needs later evidence to have arrived
    delay = dict(cutoffs=len(done),
                 current_quarter=dict(observed=sum(r['cur_obs'] for r in done), estimate=sum(r['cur_est'] for r in done), actual=sum(r['cur_now'] for r in done)),
                 previous_quarter=dict(observed=sum(r['prev_obs'] for r in done), estimate=sum(r['prev_est'] for r in done), actual=sum(r['prev_now'] for r in done)))
    for k in ('current_quarter', 'previous_quarter'):
        delay[k]['ratio'] = delay[k]['estimate'] / delay[k]['actual']
        delay[k]['unadjusted_ratio'] = delay[k]['observed'] / delay[k]['actual']
    return dict(rows=rows, delay=delay,
                publications=summ('pubs_first_month_x3', 'pubs'), publications_same_point=summ('pubs_same_point', 'pubs'),
                quarter_rule=summ('rule_pace', 'listed_adjusted'), quarter_rule_rate=summ('rule_rate', 'listed_adjusted'))


if __name__ == '__main__':
    B = build()
    write_json('estimates.json', B)
    P = B['P']
    print(f"Delay samples: {B['n_kev_delays']} CISA listings, {B['n_sensor_lags']} sensor-list entries")
    print('Share of CISA listings within 30 / 90 / 180 / 365 days:', ' / '.join(f"{100 * B['Fk'][k]:.0f}%" for k in ('30', '90', '180', '365')))
    print('Share of sensor listings in the same quarter / by the next / within three:', ' / '.join(f"{100 * B['Fm'][k]:.0f}%" for k in ('0', '1', '3')))
    print(f"October-December publications: {B['october']} in October -> {B['est_pub']} (range {B['ranges']['2026Q4:n'][0]:.0f}-{B['ranges']['2026Q4:n'][2]:.0f})")
    for q in QS[12:]:
        p = P[q]
        extra = f" | published so far: {p['est_any_pub']:.1f} attacked, {p['est_mass_pub']:.1f} mass" if 'est_any_pub' in p else ''
        print(f"{q}: published {p['n']:4d} | attacked {p['any']:3.0f} mass {p['mass']:2.0f} | estimate {p['est_any']:5.1f} attacked, {p['est_mass']:4.1f} mass{extra}")
    for k in ('2026Q3:any', '2026Q4:any', '2026Q4:mass', '2026:any', '2026:mass', '2026todate:any', '2026todate:mass'):
        print(f"range {k}: {B['ranges'][k][0]:.0f} to {B['ranges'][k][2]:.0f}")
    y5, y6 = B['year2025'], B['year2026']
    print(f"2025: {y5['n']} published, {y5['any']} attacked, {y5['mass']} mass | 2026 estimate: {y6['n']} published ({y6['n'] / y5['n']:.1f}x), "
          f"{y6['any']:.0f} attacked ({y6['any'] / y5['any']:.1f}x), {y6['mass']:.0f} mass ({y6['mass'] / y5['mass']:.1f}x)")
    bt = B['backtests']
    d = bt['delay']
    print(f"Back-test, delay adjustment ({d['cutoffs']} cutoffs): current quarter estimate {d['current_quarter']['estimate']:.0f} vs {d['current_quarter']['actual']} listed since "
          f"(unadjusted {d['current_quarter']['observed']}); previous quarter {d['previous_quarter']['estimate']:.0f} vs {d['previous_quarter']['actual']} (unadjusted {d['previous_quarter']['observed']})")
    for k in ('publications', 'publications_same_point', 'quarter_rule', 'quarter_rule_rate'):
        s = bt[k]
        print(f"Back-test, {k}: estimate {s['total_estimate']:.0f} vs actual {s['total_actual']:.0f} (ratio {s['ratio']:.2f}); typical miss {100 * (math.exp(s['mean_abs_log_error']) - 1):.0f}%; "
              f"worst {s['worst_low']:.2f}x to {s['worst_high']:.2f}x")
