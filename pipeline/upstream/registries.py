# Vendor-level maturity signals from public registries (untrusted JSON: run with python3 -I). Output: out/registry_signals.json
import json,re,sys,collections
B='/home/claude/research/dl/ext/bounty/'
PLAT={'hackerone','bugcrowd','intigriti','yeswehack','github','google','gmail','outlook','hotmail','protonmail','proton','yahoo','zerocopter','immunefi','hackenproof','openbugbounty','synack','cobalt','federacy','huntr','mitre','cert','jpcert','zendesk','atlassian_net','freshdesk','typeform','forms','docs','medium','wordpress_com','notion','gitlab_com','bit','tinyurl','linkedin','twitter','facebook','support','security','www','mail','email'}
def nn(s):
    s=(s or '').lower()
    s=re.sub(r'\(.*?\)|bug bounty|bounty|program(me)?|vdp|responsible disclosure|vulnerability disclosure|public|private|managed','',s)
    s=re.sub(r'\b(inc|llc|ltd|corp|corporation|co|gmbh|ag|sa|se|bv|plc|limited|company|incorporated|foundation|project|the)\b','',s)
    return re.sub(r'[^a-z0-9]','',s)
def label(url_or_email):
    s=(url_or_email or '').lower().strip()
    if '@' in s: host=s.split('@')[-1]
    else:
        m=re.match(r'^[a-z]+://([^/]+)',s); host=m.group(1) if m else s.split('/')[0]
    parts=[p for p in host.split('.') if p]
    if len(parts)<2: return ''
    lab=parts[-2]
    if lab in ('com','co','org','net','ac','gov','edu') and len(parts)>=3: lab=parts[-3]
    return '' if lab in PLAT else re.sub(r'[^a-z0-9]','',lab)
sig=collections.defaultdict(lambda:dict(vdp=False,bounty=False,cna=False,cna_type=None,src=[]))
def add(key,**kw):
    if not key or len(key)<3: return
    s=sig[key]
    for k,v in kw.items():
        if k=='src': s['src'].append(v)
        elif v: s[k]=v if k=='cna_type' else True
for p in json.load(open(B+'program-list.json',encoding='utf-8')):
    b=str(p.get('offers_bounty','')).lower()=='yes'
    for key in {nn(p.get('program_name')),label(p.get('contact_email')),label(p.get('policy_url')) if 'hackerone' not in str(p.get('policy_url')) and 'bugcrowd' not in str(p.get('policy_url')) else ''}:
        add(key,vdp=True,bounty=b,src='disclose.io')
for p in json.load(open(B+'hackerone_data.json',encoding='utf-8')):
    b=str(p.get('offers_bounties')).lower()=='true'
    for key in {nn(p.get('name')),nn(p.get('handle')),label(p.get('website'))}: add(key,vdp=True,bounty=b,src='hackerone')
for p in json.load(open(B+'bugcrowd_data.json',encoding='utf-8')):
    try: b=float(p.get('max_payout') or 0)>0
    except Exception: b=False
    for key in {nn(p.get('name'))}: add(key,vdp=True,bounty=b,src='bugcrowd')
ncna=0
for c in json.load(open(B+'CNAsList.json',encoding='utf-8')):
    t=((c.get('CNA') or {}).get('type')) or []
    t=[str(x) for x in (t if isinstance(t,list) else [t])]
    keys={nn(c.get('organizationName')),nn(c.get('shortName'))}
    for ct in c.get('contact') or []:
        for e in ct.get('email') or []: keys.add(label(e.get('emailAddr')))
    for key in keys: add(key,cna=True,cna_type='/'.join(t)[:60],src='cna')
    ncna+=1
json.dump({k:dict(vdp=v['vdp'],bounty=v['bounty'],cna=v['cna'],cna_type=v['cna_type'],src=sorted(set(v['src']))) for k,v in sig.items()},open('/home/claude/research/rce/out/registry_signals.json','w'))
print('keys',len(sig),'cna orgs',ncna,'with bounty',sum(v['bounty'] for v in sig.values()),'cna keys',sum(v['cna'] for v in sig.values()))
for t in ['microsoft','fortinet','ivanti','paloaltonetworks','citrix','dlink','tplink','tenda','totolink','apache','mozilla','qnap','synology','zyxel','sonicwall','atlassian','jenkins','wordpress','drupal','netgear','progress','solarwinds','sophos','cisco','f5','juniper','vmware','zohocorp','manageengine','craftcms','roundcube','exim','php','samsung','huawei','hikvision','draytek','zimbra','connectwise','crushftp','veeam','gitlab','adobe','oracle','sap','google','apple']:
    v=sig.get(t); print(f"  {t:18s}",'-' if not v else f"vdp={int(v['vdp'])} bounty={int(v['bounty'])} cna={int(v['cna'])} {v['cna_type'] or ''} {sorted(set(v['src']))}")
