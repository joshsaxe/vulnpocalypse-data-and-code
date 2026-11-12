# Task 3 assembly: company attributes, update model, attacker types and volume measures attached to every flaw.
import sys,json,csv,re,collections,math,os
sys.path.insert(0,'/home/claude/research/rce/scripts')
from load import load,main
from feat import GROUP,xstrong
import vendattr,update
R='/home/claude/research/'; P=R+'rce/out/'; N=R+'research_notes/RCE flaw vendors attackers and volume/'
CVE=re.compile(r'CVE-\d{4}-\d{4,}',re.I)
def num(s):
    try: return float(str(s).replace(',','').strip())
    except Exception: return None
def campaigns():
    vict={}; types=collections.defaultdict(set)
    f=R+'research_notes/Vendor exploitation outcome drivers/mass_exploitation_campaigns.csv'
    for r in csv.DictReader(open(f,encoding='utf-8')):
        ids=[m.upper() for m in CVE.findall(r['cves'] or '')]
        c=num(r['compromised_count']); t=(r['actor_type'] or '').lower()
        for i in ids:
            if c: vict[i]=max(vict.get(i,0),c)
            if 'state' in t: types[i].add('state')
            if 'ransom' in t: types[i].add('ransomware')
            if 'botnet' in t: types[i].add('botnet')
    return vict,types
def circl():
    hp=collections.Counter(); hq=collections.Counter(); allt={}
    p=N+'circl_exploited_sightings.csv'
    if not os.path.exists(p): return hp,hq,allt
    for r in csv.DictReader(open(p,encoding='utf-8')):
        i=(r['id'] or '').strip().upper(); c=num(r['count'])
        if not i.startswith('CVE-') or c is None: continue
        span=(r['period_start'],r['period_end'])
        if span[0]<='2024-01-01' and span[1]>='2026-01-01': allt[i]=max(allt.get(i,0),c); continue   # all-time list kept separately
        hp[i]+=c; hq[i]+=1
    return hp,hq,allt
def level(nws,expl):
    if not expl: return 0
    return 1 if nws==0 else (2 if nws==1 else (3 if nws<=3 else 4))
def load3():
    rows=load(); AV=json.load(open(P+'actors_volume.json')); cv,ct=campaigns(); hp,hq,allt=circl()
    M=main(rows)
    vn=collections.Counter(); vi=collections.Counter()
    for r in M:
        v=(r['vendor'] or '').lower(); vn[v]+=1; vi[v]+= GROUP[r['role']]=='device'
    for r in rows:
        v=(r['vendor'] or '').lower()
        a=vendattr.attrs(r, (vi[v]/vn[v]) if vn[v]>=3 else None)
        r.update(tier=a['tier'],owner=a['owner'],rev=a['revenue'],bounty=a['bounty'],pledge=a['pledge'],cna=a['cna'],vdp=a['vdp_listed'],pv=a['pv'],anyprog=a['any_program'])
        r['upd'],r['upd_basis']=update.update_model(r)
        A=AV.get(r['id'],{})
        t=set(A.get('types',[]))|ct.get(r['id'],set())
        r['atk']=sorted(t); r['sponsors']=A.get('sponsors',[]); r['n_actors']=A.get('n_actors',0); r['zd_types']=A.get('zd_types',[])
        r['nws']=len(r['ev_wide']) if False else A.get('n_wide_sources',0)
        r['vol']=level(r['nws'],r['expl']) if r['wide'] or not r['expl'] else 1
        if r['wide'] and r['vol']<2: r['vol']=2
        vol=A.get('vol',{})
        r['victims']=max([x for x in (cv.get(r['id']),vol.get('victims_compromised')) if x] or [0]) or None
        r['sens']=vol.get('sensor_requests_sum'); r['sens_max']=vol.get('sensor_requests')
        r['hp']=hp.get(r['id'],0); r['hp_q']=hq.get(r['id'],0); r['hp_all']=allt.get(r['id'])
        r['group']=GROUP[r['role']]
    return rows,M
if __name__=='__main__':
    rows,M=load3()
    ex=[r for r in M if r['expl']]
    print('main',len(M),'expl',len(ex))
    print('vol levels',sorted(collections.Counter(r['vol'] for r in M).items()))
    print('tier',collections.Counter(r['tier'] for r in M).most_common())
    print('owner',collections.Counter(r['owner'] for r in M).most_common())
    print('upd',collections.Counter(r['upd'] for r in M).most_common(), collections.Counter(r['upd'] for r in ex).most_common())
    print('hp>0 main',sum(1 for r in M if r['hp']>0),'victims',sum(1 for r in ex if r['victims']),'sens',sum(1 for r in ex if r['sens']))
    print('typed',sum(1 for r in ex if r['atk']))
