"""Data and definitions shared by every chart and every number in the post.

Run nothing here directly: the chart scripts and numbers.py import it.
Every definition the post relies on (the class of vulnerability, "attacked", "mass exploitation",
the maker groups) is a few lines of code below, so it can be read and changed in one place.
"""
import csv, gzip, json, collections, datetime, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'
OUT = ROOT / 'output'
OUT.mkdir(exist_ok=True)

# The vulnerability records were downloaded on November 10, 2026. November 9 is the last full day.
SNAPSHOT = datetime.date(2026, 11, 9)

BOOLS = ('rce', 'pop2', 'kev', 'kev_rw', 'expl', 'zd', 'camp', 'cna')


def load_flaws():
    """One dict per vulnerability. See DATA_DICTIONARY.md for every column."""
    rows = []
    with gzip.open(DATA / 'flaws.csv.gz', 'rt', encoding='utf-8', newline='') as f:
        for r in csv.DictReader(f):
            if r['pub'][:10] > SNAPSHOT.isoformat():
                continue        # 12 records dated November 10, a partial day, are in the file but not in the study
            for k in BOOLS:
                r[k] = r[k] == '1'
            r['score'] = float(r['score']) if r['score'] else None
            r['victims'] = float(r['victims']) if r['victims'] else None
            r['pkp'] = int(r['pkp']) if r['pkp'] else 0
            r['ev_wide'] = r['ev_wide'].split('|') if r['ev_wide'] else []
            r['pv'] = r['pv'] or None
            r['kev_date'] = r['kev_date'] or None
            rows.append(r)
    return rows


def load_sensor_lists():
    """CIRCL's quarterly lists of the 100 most-sighted exploited vulnerabilities, honeypot era only.

    Returns {cve id: {period_start: count}}. Two kinds of list in the file are left out on purpose:
    the all-time lists, and the July-September 2024 list, which predates the Shadowserver honeypot feed
    (it began on October 24, 2024) and whose entries have as few as one sighting.
    """
    out = collections.defaultdict(dict)
    with open(DATA / 'sensor_lists.csv', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r['kind'] == 'quarter':
                out[r['id']][r['period_start']] = float(r['count'])
    return dict(out)


def load_panel():
    """The 86-vendor panel: revenue, ownership, staff and security programs, from filings and vendor pages."""
    with open(DATA / 'vendor_panel.csv', encoding='utf-8') as f:
        return {r['vendor']: r for r in csv.DictReader(f)}


R = load_flaws()
SENSOR = load_sensor_lists()
PANEL = load_panel()

# ----------------------------------------------------------------------------------------------- definitions

def quarter(d):
    """'2026-07-14' -> '2026Q3'"""
    return d[:4] + 'Q' + str((int(d[5:7]) - 1) // 3 + 1)


def opn(r):
    """Needs no login and no click from a user (CVSS: network vector, no privileges, no user interaction)."""
    return r['delivery'] == 'open'


def cls(r):
    """'The class' of Charts 1 and 2: no login, no click, in internet-facing enterprise software
    (edge devices such as firewalls and VPN gateways, and servers that normally face the internet)."""
    return opn(r) and r['role'] in ('edge', 'srv_exposed')


# Kinds of public evidence that an exploited vulnerability was attacked at scale.
# Left out on purpose: use by a commercial spyware vendor, a mention in a zero-day review, a MITRE ATT&CK
# reference and unclassified reports. Those show exploitation, not scale.
STRONG = {'ransomware flag in CISA catalog', 'ransomware advisory', 'botnet', 'government most-exploited list',
          'sensor or telemetry ranking', 'Rapid7 classification', 'named campaign with scale figure'}


def scale_evidence(r):
    """Why a vulnerability counts as mass-exploited. Empty list = it does not."""
    why = []
    if r['expl']:
        why += [t for t in r['ev_wide'] if t in STRONG]
    # A place among the 100 most-sighted exploited vulnerabilities in a honeypot-era quarter.
    # Honeypots cannot see attacks on client software (browsers, phones, desktop apps), where a place in the
    # list reflects mentions, so the sensor lists are not used for client software.
    if r['id'] in SENSOR and r['role'] != 'client_os':
        why.append('sensor top-100 list')
    if r['camp'] and r['victims']:
        why.append('campaign with a victim count')
    return why


def mass(r):
    """Mass exploitation: public evidence of attacks at scale."""
    return bool(scale_evidence(r))


def attacked(r):
    """Attacked at all: listed by CISA or documented as exploited in the sources, or mass-exploited."""
    return r['expl'] or mass(r)


def grp(r):
    """Maker group: hyperscale (Google, Apple, Meta, Amazon), microsoft, large, midmarket, oss, small, device."""
    return r['group']


GROUP_NAMES = {
    'hyperscale': ('Hyperscalers', 'Google, Apple, Meta, Amazon'),
    'microsoft': ('Microsoft', 'Windows, Exchange, SharePoint'),
    'large': ('Large vendors', 'Oracle, Cisco, Adobe, IBM'),
    'midmarket': ('Mid-market and smaller vendors', 'Ivanti, Citrix, Progress, GitLab'),
    'oss': ('Open-source projects', 'Apache, Linux, Mozilla, PHP'),
    'small': ('Plug-ins and small projects', 'WordPress, student code, unclassified'),
    'device': ('Device makers', 'D-Link, TP-Link, Tenda, QNAP'),
}


def bounty(r):
    """Bug-bounty status of the maker, where it is one of the 86 panel vendors."""
    if not r['pv']:
        return 'unmapped'
    return {'2.0': 'public paid', '1.0': 'private', '0.0': 'none', '': 'unverified'}[PANEL[r['pv']]['bounty']]


def D(s):
    return datetime.date.fromisoformat(s)


def write_json(name, obj):
    p = OUT / name
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    return p


def words(n):
    """Small whole numbers as words, for chart text."""
    return {0: 'none', 1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten',
            11: '11', 12: '12'}.get(n, f'{n:,}')
