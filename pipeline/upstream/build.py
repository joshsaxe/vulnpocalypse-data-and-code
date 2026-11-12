# Build the CVE-level dataset. Run with python3 -I (reads untrusted NVD/KEV-derived files).
import json,sys,csv,re,collections,datetime
sys.path.insert(0,'/home/claude/research/rce/scripts')
from rcedef import *; from roles2 import role2,keys,primary_vendor,norm
R='/home/claude/research/'
ext=json.load(open(R+'rce/out/ext_features.json'))
kevl=json.load(open('/home/claude/kev/data/kev.json'))['vulnerabilities']
kev={x['cveID']:x for x in kevl}
camp=set()
for row in csv.DictReader(open(R+'research_notes/Vendor exploitation outcome drivers/mass_exploitation_campaigns.csv',encoding='utf-8')):
    for m in re.findall(r'CVE-\d{4}-\d{4,}',row['cves']): camp.add(m)
D=lambda s: datetime.date.fromisoformat(s[:10]) if s else None
# ---- pass 1: counts per vendor / product over all CVEs; KEV cve -> pairs + pub
vend_n=collections.Counter(); prod_n=collections.Counter(); kev_pairs={}; kev_pub={}
recs=[]
for line in open(R+'rce/out/cves19.jsonl'):
    r=json.loads(line); vp=keys(r)
    pairs={(norm(v),p) for v,p in vp}; vs={v for v,p in pairs}
    for v in vs: vend_n[v]+=1
    for pr in pairs: prod_n[pr]+=1
    if r['id'] in kev: kev_pairs[r['id']]=pairs; kev_pub[r['id']]=r['pub']
    recs.append(r)
# older KEV CVEs (2017-2018) from Task-1 parse
for line in open(R+'out/cves.jsonl'):
    r=json.loads(line)
    if r['id'] in kev and r['id'] not in kev_pairs:
        pairs=set()
        for c in r.get('cpe') or []:
            p=c.split(':')
            if len(p)>=2: pairs.add((norm(p[-2].replace('_',' ')),p[-1].replace('_',' ')))
        kev_pairs[r['id']]=pairs; kev_pub[r['id']]=r.get('pub') or r['id'][4:8]+'-01-01'
for k,x in kev.items():
    if k not in kev_pairs:
        kev_pairs[k]={(norm(x['vendorProject'].lower()),'')}; kev_pub[k]=k[4:8]+'-07-01'
kv=collections.defaultdict(list); kp=collections.defaultdict(list)   # vendor -> [(pub, added)], pair -> [...]
for k,pairs in kev_pairs.items():
    pub=kev_pub[k][:10]; add=kev[k]['dateAdded']
    for v in {v for v,p in pairs}: kv[v].append((pub,add,k))
    for pr in pairs:
        if pr[1]: kp[pr].append((pub,add,k))
print('pass1 done',len(recs),flush=True)
out=open(R+'rce/out/rce.jsonl','w'); n=0; npop2=0
for r in recs:
    vec,ver=r['vec'],r['cv']; e=ext.get(r['id'],{})
    if not vec and e.get('adp_vec'): vec,ver=e['adp_vec'],3
    v=parse_vec(vec,ver); f,b=is_rce(r['desc'],r['cwe'],v)
    pop2 = v.get('av')=='N' and v.get('c')=='H' and v.get('i')=='H' and v.get('a')=='H'
    if not (f or pop2): continue
    vp=keys(r); pairs={(norm(a),p) for a,p in vp}; vs={a for a,p in pairs}
    pub=r['pub'][:10]; pd=D(pub); cut=(pd-datetime.timedelta(days=365)).isoformat()
    pv=primary_vendor(r)
    def prior(lst,strict):
        return sum(1 for (p,a,k) in lst if k!=r['id'] and ((a<pub) if strict else (p<cut)))
    pkv=max([prior(kv[a],False) for a in vs] or [0]); pkp=max([prior(kp[pr],False) for pr in pairs] or [0])
    pkv_s=max([prior(kv[a],True) for a in vs] or [0]); pkp_s=max([prior(kp[pr],True) for pr in pairs] or [0])
    k=kev.get(r['id'])
    msf_exploit = 'exploit' in (e.get('msf_types') or [])
    pocd=None
    if e.get('poc_first'):
        try: pocd=(D(e['poc_first'])-pd).days
        except Exception: pocd=None
    o=dict(id=r['id'],pub=pub,src=r['src'],rce=bool(f),basis=b,pop2=bool(pop2),score=r['score'],cv=ver if vec else 0,
           av=v.get('av'),pr=v.get('pr'),ui=v.get('ui'),ac=v.get('ac'),c=v.get('c'),i=v.get('i'),a=v.get('a'),
           delivery=delivery(v),wk=wk(r['cwe'],r['desc']),role=role2(r),vendor=pv,
           vend_n=max([vend_n[a] for a in vs] or [0]) if not pv else vend_n.get(pv,0),prod_n=max([prod_n[pr] for pr in pairs] or [0]),
           pkv=pkv,pkp=pkp,pkv_s=pkv_s,pkp_s=pkp_s,
           poc_n=e.get('poc_n',0),poc_days=pocd,poc_stars=e.get('poc_stars',0),msf=bool(e.get('msf_types')),msf_exploit=msf_exploit,nuclei=bool(e.get('nuclei')),
           xtag=('Exploit' in (r.get('tags') or [])),nref=r.get('nref',0),
           ssvc_auto=e.get('ssvc_auto'),ssvc_expl=e.get('ssvc_expl'),ssvc_ts=e.get('ssvc_ts'),epss=e.get('epss'),
           kev=bool(k),kev_date=k['dateAdded'] if k else None,kev_rw=(k['knownRansomwareCampaignUse']=='Known') if k else False,
           kev_name=k['vulnerabilityName'] if k else None,camp=r['id'] in camp,
           prod=(sorted(pairs,key=lambda pr:-prod_n[pr])[0][1] if pairs else ''),desc=r['desc'][:160])
    out.write(json.dumps(o)+'\n'); n+=1; npop2+=pop2
out.close(); print('written',n,'pop2',npop2)
json.dump({'vend_n':vend_n.most_common(3000)},open(R+'rce/out/vendor_counts.json','w'))
