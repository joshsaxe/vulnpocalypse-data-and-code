# Attacker types and volume signals per CVE from the research tables (untrusted text: run with python3 -I). Output out/actors_volume.json
import csv,re,json,collections,math,os
R='/home/claude/research/'; N=R+'research_notes/RCE flaw vendors attackers and volume/'; N0=R+'research_notes/RCE flaw exploitation determinants/'
CVE=re.compile(r'CVE-\d{4}-\d{4,}')
out=collections.defaultdict(lambda:dict(types=set(),sponsors=set(),actors=set(),zd_types=set(),wide_sources=set(),all_sources=set(),gov_years=set(),vol={}))
TYPES={'state','spyware_vendor','ransomware','botnet','criminal_other','hacktivist'}
# rows that record interest, capability or reconnaissance rather than use are left out
NOT_USE=re.compile(r'interest shown, not confirmed|per-CVE exploitation not detailed|use not reported|exploitation not observed',re.I)
skipped=0
for r in csv.DictReader(open(N+'actor_attribution.csv',encoding='utf-8')):
    m=CVE.fullmatch((r['cve'] or '').strip())
    if not m: continue
    if NOT_USE.search(r['source'] or ''): skipped+=1; continue
    t=(r['actor_type'] or '').strip().lower()
    if t not in TYPES: continue
    o=out[m.group(0)]; o['types'].add(t)
    sp=(r['state_sponsor'] or '').strip().upper()
    if t=='state' and sp: o['sponsors'].add(sp[:2])
    nm=(r['actor_name'] or '').strip()
    if nm and not re.search(r'^(unknown|unattributed|multiple|various|n/a|ransomware actors?|kev|cisa)',nm,re.I): o['actors'].add((t,re.sub(r'\s*\(.*?\)','',nm).strip().lower()[:40]))
    if (r['first_use_zero_day'] or '').strip().upper().startswith('Y'): o['zd_types'].add(t)
def cat_gov(s): return bool(re.search(r'routinely exploited|top 1[025]|top 10 most|top routinely',s))
for r in csv.DictReader(open(N0+'mass_vs_targeted_lists.csv',encoding='utf-8')):
    m=CVE.fullmatch((r['cve'] or '').strip())
    if not m: continue
    s=(r['source']+' | '+r['list_name']).lower()
    if re.search(r'impending threat|no exploitation known',s): continue
    o=out[m.group(0)]; src=re.sub(r'\s+',' ',r['source'].strip())[:60]
    o['all_sources'].add(src)
    if r['breadth'].strip().lower()=='wide':
        o['wide_sources'].add(src)
        if cat_gov(s): o['gov_years'].add(r['source_year'].strip()[:4] or src)
if os.path.exists(N+'volume_measures.csv'):
    for r in csv.DictReader(open(N+'volume_measures.csv',encoding='utf-8')):
        m=CVE.fullmatch((r['cve'] or '').strip())
        if not m: continue
        try: v=float(str(r['value']).replace(',',''))
        except Exception: continue
        k=(r['measure'] or '').strip()
        d=out[m.group(0)]['vol']
        if k=='rank_in_source': d[k]=min(d.get(k,1e9),v)
        elif k=='sensor_requests':
            d[k]=max(d.get(k,0),v); d['sensor_requests_sum']=d.get('sensor_requests_sum',0)+v; d['sensor_obs']=d.get('sensor_obs',0)+1
        else: d[k]=max(d.get(k,0),v)
J={k:dict(types=sorted(v['types']),sponsors=sorted(v['sponsors']),n_actors=len(v['actors']),zd_types=sorted(v['zd_types']),n_wide_sources=len(v['wide_sources']),n_sources=len(v['all_sources']),gov_years=len(v['gov_years']),vol=v['vol']) for k,v in out.items()}
json.dump(J,open(R+'rce/out/actors_volume.json','w'))
print('skipped interest-only rows',skipped); print('cves',len(J),'typed',sum(1 for v in J.values() if v['types']),'with vol',sum(1 for v in J.values() if v['vol']))
print('type combos',collections.Counter('+'.join(v['types']) for v in J.values() if v['types']).most_common(12))
