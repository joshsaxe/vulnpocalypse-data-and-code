# Extract per-CVE features from external (untrusted) datasets. Run with python3 -I.
import json, os, sys, re, csv, collections
EXT, OUT = sys.argv[1], sys.argv[2]
CVE = re.compile(r'CVE-\d{4}-\d{4,}')
feat = collections.defaultdict(dict)
# ---- PoC-in-GitHub
n=0
for yr in sorted(os.listdir(os.path.join(EXT,'poc'))):
    yd=os.path.join(EXT,'poc',yr)
    if not (yr.isdigit() and os.path.isdir(yd)): continue
    for fn in os.listdir(yd):
        if not fn.endswith('.json'): continue
        try: d=json.load(open(os.path.join(yd,fn),encoding='utf-8'))
        except Exception: continue
        if not isinstance(d,list) or not d: continue
        dates=sorted(str(x.get('created_at',''))[:10] for x in d if x.get('created_at'))
        stars=0
        for x in d:
            try: stars=max(stars,int(x.get('stargazers_count') or 0))
            except Exception: pass
        cid=fn[:-5].upper()
        feat[cid]['poc_n']=len(d); feat[cid]['poc_first']=dates[0] if dates else None; feat[cid]['poc_stars']=stars
        n+=1
print('poc files',n,flush=True)
# ---- Metasploit
m=json.load(open(os.path.join(EXT,'msf','modules_metadata_base.json'),encoding='utf-8'))
nm=0
for name,mod in m.items():
    refs=[r for r in (mod.get('references') or []) if isinstance(r,str)]
    for r in refs:
        mm=CVE.search(r.upper())
        if not mm: continue
        cid=mm.group(0); f=feat[cid]
        t=mod.get('type'); f.setdefault('msf_types',[])
        if t not in f['msf_types']: f['msf_types'].append(t)
        rk=mod.get('rank'); 
        if isinstance(rk,int): f['msf_rank']=max(f.get('msf_rank',0),rk)
        dd=str(mod.get('disclosure_date') or '')[:10]; md=str(mod.get('mod_time') or '')[:10]
        if md: f['msf_mod']=min(f.get('msf_mod','9999'),md)
        nm+=1
print('msf refs',nm,flush=True)
# ---- Nuclei
nn=0
for line in open(os.path.join(EXT,'nuclei','cves.json'),encoding='utf-8'):
    line=line.strip()
    if not line: continue
    try: o=json.loads(line)
    except Exception: continue
    cid=str(o.get('ID','')).upper()
    if CVE.fullmatch(cid):
        feat[cid]['nuclei']=1; feat[cid]['nuclei_path']=str(o.get('file_path',''))[:40]; nn+=1
print('nuclei',nn,flush=True)
# ---- EPSS
ne=0
with open(os.path.join(EXT,'epss','cve-scores','cve-scores.csv'),encoding='utf-8') as f:
    for row in csv.reader(f):
        if len(row)<2 or not row[0].startswith('CVE-'): continue
        try: feat[row[0]]['epss']=float(row[1])
        except Exception: continue
        ne+=1
print('epss',ne,flush=True)
# ---- Vulnrichment (SSVC + ADP CVSS + KEV flag in ADP)
vr=os.path.join(EXT,'vulnrichment'); nv=0
for yr in sorted(os.listdir(vr)):
    if not (yr.isdigit() and int(yr)>=2019): continue
    for sub in os.listdir(os.path.join(vr,yr)):
        sd=os.path.join(vr,yr,sub)
        if not os.path.isdir(sd): continue
        for fn in os.listdir(sd):
            if not fn.endswith('.json'): continue
            try: d=json.load(open(os.path.join(sd,fn),encoding='utf-8'))
            except Exception: continue
            cid=fn[:-5].upper()
            for adp in (d.get('containers') or {}).get('adp') or []:
                if 'CISA' not in str(adp.get('title','')): continue
                for met in adp.get('metrics') or []:
                    o=met.get('other') or {}
                    if o.get('type')=='ssvc':
                        c=o.get('content') or {}
                        for opt in c.get('options') or []:
                            for k,v in opt.items():
                                kk={'Exploitation':'ssvc_expl','Automatable':'ssvc_auto','Technical Impact':'ssvc_impact'}.get(k)
                                if kk: feat[cid][kk]=str(v).lower()
                        feat[cid]['ssvc_ts']=str(c.get('timestamp',''))[:10]
                    elif o.get('type')=='kev':
                        feat[cid]['adp_kev']=str((o.get('content') or {}).get('dateAdded',''))[:10] or '1'
                    for key in ('cvssV3_1','cvssV3_0'):
                        if key in met and isinstance(met[key],dict) and met[key].get('vectorString'):
                            feat[cid]['adp_vec']=met[key]['vectorString']; feat[cid]['adp_score']=met[key].get('baseScore')
            nv+=1
    print('vulnrichment',yr,nv,flush=True)
json.dump(feat,open(OUT,'w'))
print('cves with any feature',len(feat))
c=collections.Counter()
for v in feat.values():
    for k in v: c[k]+=1
print(dict(c))
print('ssvc_expl',collections.Counter(v.get('ssvc_expl') for v in feat.values() if 'ssvc_expl' in v))
print('ssvc_auto',collections.Counter(v.get('ssvc_auto') for v in feat.values() if 'ssvc_auto' in v))
