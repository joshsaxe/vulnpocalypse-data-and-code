# Feature construction shared by models and figures.
import math
GROUP={'edge':'ent_exposed','srv_exposed':'ent_exposed','srv_internal':'ent_internal','client_os':'client','iot':'device',
       'plugin':'tail','hobby':'tail','other_web':'tail','other':'tail','component':'tail','ics':'tail','cloud':'tail'}
GLAB={'ent_exposed':'Internet-facing enterprise systems','ent_internal':'Internal enterprise servers','client':'PCs, phones and browsers',
      'device':'Routers, cameras, small devices','tail':'Plug-ins, libraries, small projects, industrial'}
WK2={'memory':'memory','cmd':'injection','inject':'injection','deser':'injection','upload':'upload_auth','auth':'upload_auth','sqli':'upload_auth','other':'other'}
def xcode(r): return bool(r['poc_n'] or r['msf'] or r['nuclei'] or r['xtag'])
def xstrong(r): return bool(r['poc_n'] or r['msf'] or r['nuclei'])   # named exploit code: GitHub PoC, Metasploit, Nuclei
def feats(r):
    return dict(
        role=r['role'], group=GROUP[r['role']], delivery=r['delivery'], ac=r['ac'] or 'L',
        wk=r['wk'], wk2=WK2[r['wk']],
        poc=int(bool(r['poc_n'])), msf=int(bool(r['msf'])), nuclei=int(bool(r['nuclei'])), xtag=int(bool(r['xtag'])),
        pkp=int(r['pkp']>0), pkv=int(r['pkv']>0),
        lvend=math.log10(max(r['vend_n'],1)), lprod=math.log10(max(r['prod_n'],1)),
        score=(r['score'] if r['score'] is not None else 8.0), year=int(r['pub'][:4]), zd=int(bool(r.get('zd'))))
FAM={'product role':['role'],'access needed':['delivery','ac'],'exploit code':['poc','msf','nuclei','xtag'],
     'earlier exploited flaw in product/vendor':['pkp','pkv'],'weakness class':['wk'],'severity score':['score'],
     'vendor/product size':['lvend','lprod'],'year':['year'],'zero-day at discovery':['zd']}
