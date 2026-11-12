# Combine exploitation-breadth evidence into per-CVE labels. Reads researcher CSVs (untrusted text): run with python3 -I.
import csv,re,json,collections,sys
R='/home/claude/research/'
N=R+'research_notes/RCE flaw exploitation determinants/'
CVE=re.compile(r'CVE-\d{4}-\d{4,}')
def cat(r):
    s=(r['source']+' | '+r['list_name']).lower()
    if re.search(r'impending threat|no exploitation known',s): return None
    if 'knownransomwarecampaignuse' in s: return 'ransomware flag in CISA catalog'
    if re.search(r'stopransomware|ransomware|black basta|lockbit|cl0p|akira|karakurt|extortion',s): return 'ransomware advisory'
    if re.search(r'botnet|mirai|androxgh0st|worm|gafgyt|quad7',s): return 'botnet'
    if re.search(r'routinely exploited|top 1[025]|top 10 most|top routinely|most used by prc|most frequently exploited by prc|vulnerabilities exploited in 2020|2020 cves section',s): return 'government most-exploited list'
    if 'rapid7' in s: return 'Rapid7 classification'
    if re.search(r'routinely targeted|sensor|greynoise|cloudflare|f5 labs|akamai|patchstack|wordfence|most exploited wordpress',s): return 'sensor or telemetry ranking'
    if re.search(r'project zero|0-days in-the-wild',s): return 'Project Zero zero-day list'
    if re.search(r'spying|surveillance|spyware|candiru|variston|dsirf|intellexa|nso',s): return 'spyware vendor'
    if 'earlier session campaign file' in s: return 'named campaign with scale figure'
    if 'att&ck' in s: return 'MITRE ATT&CK'
    if re.search(r'zero-day (year in )?review|zero-day year',s): return 'Google or Mandiant zero-day review'
    return 'other report'
lab=collections.defaultdict(lambda:dict(wide=set(),targeted=set(),unclear=set(),zd=False,zd_n=False))
for r in csv.DictReader(open(N+'mass_vs_targeted_lists.csv',encoding='utf-8')):
    c=cat(r)
    if c is None: continue
    m=CVE.fullmatch(r['cve'].strip())
    if not m: continue
    L=lab[m.group(0)]
    b=r['breadth'].strip().lower()
    L[b if b in('wide','targeted') else 'unclear'].add(c)
    z=r['zero_day'].strip().upper()[:1]
    if z=='Y': L['zd']=True
    if z=='N': L['zd_n']=True
out={k:dict(wide=sorted(v['wide']),targeted=sorted(v['targeted']),unclear=sorted(v['unclear']),zd=v['zd'],zd_n=v['zd_n']) for k,v in lab.items()}
json.dump(out,open(R+'rce/out/labels.json','w'))
print('cves',len(out),'with wide',sum(1 for v in out.values() if v['wide']),'zd',sum(v['zd'] for v in out.values()))
tc=collections.Counter(t for v in out.values() for t in v['wide']); print('wide types',tc.most_common())
only_flag=sum(1 for v in out.values() if v['wide']==['ransomware flag in CISA catalog']); print('wide only by KEV ransomware flag',only_flag)
