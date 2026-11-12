# Parse selected pre-2019 CVE records (untrusted NVD files; run with python3 -I). Args: out_path id_list_json dir1 [dir2...]
import lzma, json, sys, os
out_path, ids_path = sys.argv[1], sys.argv[2]; dirs=sys.argv[3:]
IDS=set(json.load(open(ids_path)))
years={i[4:8] for i in IDS}
def best_cvss(m):
    for key in ('cvssMetricV31','cvssMetricV30'):
        arr = m.get(key) or []
        prim = [a for a in arr if a.get('type')=='Primary' and 'nvd' in (a.get('source') or '')]
        pick = prim or [a for a in arr if a.get('type')=='Primary'] or arr
        if pick:
            c = pick[0]['cvssData']; return c.get('vectorString'), c.get('baseScore'), 3
    arr = m.get('cvssMetricV40') or []
    if arr:
        c = arr[0]['cvssData']; return c.get('vectorString'), c.get('baseScore'), 4
    arr = m.get('cvssMetricV2') or []
    if arr:
        c = arr[0]['cvssData']; return c.get('vectorString'), c.get('baseScore'), 2
    return None, None, 0
n=0
with open(out_path,'w',encoding='utf-8') as out:
    for d0 in dirs:
        for fn in sorted(os.listdir(d0)):
            if not fn.endswith('.json.xz') or fn[4:8] not in years or int(fn[4:8])>=2019: continue
            with lzma.open(os.path.join(d0,fn),'rt',encoding='utf-8') as f: d=json.load(f)
            for it in d['cve_items']:
                if it['id'] not in IDS or it.get('vulnStatus')=='Rejected': continue
                vec,score,ver = best_cvss(it.get('metrics') or {})
                cwes = sorted({x['value'] for w in (it.get('weaknesses') or []) for x in w.get('description',[]) if x.get('value','').startswith('CWE-')})
                cpes=set()
                for conf in it.get('configurations') or []:
                    for node in conf.get('nodes') or []:
                        for cm in node.get('cpeMatch') or []:
                            if cm.get('vulnerable'):
                                p = cm.get('criteria','').split(':')
                                if len(p)>5: cpes.add(p[2]+':'+p[3]+':'+p[4])
                aff=set()
                for a in it.get('affected') or []:
                    for ad in a.get('affectedData') or []:
                        v=(ad.get('vendor') or '').strip(); p=(ad.get('product') or '').strip()
                        if v and v.lower()!='n/a': aff.add(v+'|'+p)
                desc = next((x['value'] for x in it.get('descriptions',[]) if x.get('lang')=='en'), '')
                refs = it.get('references') or []
                tags = sorted({t for r in refs for t in (r.get('tags') or [])})
                gh = sum('github.com' in (r.get('url') or '') for r in refs)
                rec = {'id':it['id'],'pub':it.get('published','')[:10],'src':it.get('sourceIdentifier'),'vec':vec,'score':score,'cv':ver,'cwe':cwes,
                       'cpe':sorted(cpes)[:25],'aff':sorted(aff)[:10],'desc':desc[:700],'nref':len(refs),'tags':tags,'gh':gh}
                out.write(json.dumps(rec,ensure_ascii=False)+'\n'); n+=1
print('written',n)
