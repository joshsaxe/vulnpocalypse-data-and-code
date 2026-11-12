# Company attributes per flaw: tier, ownership, size, maturity signals, update model. Merges Task-1 panel, public registries and (when present) the research extension table.
import sys,re,csv,json,os,collections
sys.path.insert(0,'/home/claude/research/rce/scripts')
from panelmap import panel_vendor,PAN
from feat import GROUP
REG=json.load(open('/home/claude/research/rce/out/registry_signals.json'))
N='/home/claude/research/research_notes/RCE flaw vendors attackers and volume/'
def nn(s): return re.sub(r'[^a-z0-9]','',(s or '').lower())
EXT={}
if os.path.exists(N+'vendor_attributes_extension.csv'):
    for r in csv.DictReader(open(N+'vendor_attributes_extension.csv',encoding='utf-8')):
        EXT[nn(r['vendor'])]=r
    if 'dlink' in EXT: EXT.setdefault('dlink',EXT['dlink'])
HYPER={'Microsoft','Apple','Google','Amazon (AWS)'}
HYPER_V={'whatsapp','facebook','meta','android','chromium'}
LARGE_V=set("samsung huawei qualcomm siemens schneider-electric schneiderelectric nvidia intel amd lenovo hp mediatek arm redhat red hat sony lg panasonic canon ricoh xerox honeywell abb rockwellautomation mitsubishielectric mitsubishi bosch ericsson nokia zte hitachi fujitsu nec toshiba emerson ge philips medtronic hikvision dahua dahuasecurity asus tencent alibaba baidu bytedance xiaomi oppo vivo ibm oracle sap adobe cisco dell hpe vmware broadcom salesforce autodesk nvidia".split())|{'schneider electric','rockwell automation','mitsubishi electric','hewlett packard enterprise','red hat'}
OSS_V=set("apache mozilla jenkins drupal php exim roundcube linux gnu debian python nodejs wordpress joomla typo3 xwiki chamilo geoserver saltstack erlang xstream openssl openssh curl haxx git ffmpeg imagemagick gstreamer freerdp gpac qemu xen libreoffice thedocumentfoundation gimp vim sudo samba isc nginx squid-cache postgresql redis mariadb sqlite libpng libtiff zlib busybox dnsmasq eclipse golang rust-lang ruby-lang rubyonrails djangoproject laravel symfony spring nextcloud owncloud moodle mediawiki dokuwiki phpmyadmin webmin cacti nagios zabbix librenms pi-hole openwrt dd-wrt pfsense opnsense gitea gogs discourse mastodon matrix grafana prometheus kubernetes docker containerd helm istio hashicorp-none langflow langchain llamaindex ollama gradio mlflow anyscale ray openclaw litellm n8n dify comfyui open-webui cyberpanel control-webpanel craftcms vbulletin-none thinkphp dedecms".split())|{'the document foundation','squid-cache','pi-hole','control-webpanel','dd-wrt','open-webui','rust-lang','ruby-lang'}
OSS_V|=set("phpunit facade glpi-project dolibarr spip pluck-cms cmsmadesimple concretecms prestashop limesurvey umbraco textpattern bludit wbce emlog zephyrproject linuxfoundation contiki-ng rt-thread tianocore videolan pgadmin frappe observium fusionpbx vestacp ilias salesagility jorani seacms zzcms zzzcms publiccms wuzhicms jpress mingsoft eyoucms jizhicms 74cms shopxo crmeb feehi idreamsoft sem-cms taogogo xuxueli openrobotics mongo-express nazgul wazuh freetype openbsd gogs redis cacti webmin thinkphp laravel n8n metabase-none rocket.chat mattermost-none ossec opensearch elastic-none tomcat struts log4j".split())
HOBBY_V=set("rejetto filemanagerpro jmcnamara".split())
OSS_SRC={'security-advisories@github.com','security@huntr.dev','security@huntr.com','report@snyk.io','security@apache.org','security@golang.org','cve@kernel.org','security@php.net','security@mozilla.org','security@drupal.org','jenkinsci-cert@googlegroups.com','security@wordpress.org','security@nodejs.org','openssl-security@openssl.org','security@eclipse.org'}
# ownership at the time the flaw was published: (date the private-equity owner took control, owner class before that)
PE_SINCE={'Citrix':('2022-09-30','public'),'Sophos':('2020-03-02','public'),'Synacor (Zimbra)':('2021-04-01','public'),'Zendesk':('2022-11-22','public'),
          'ConnectWise':('2019-02-28','private'),'Veeam':('2020-03-01','private'),'Cleo':('2021-07-01','private')}
def rev(p):
    try: return float(p['revenue'])
    except Exception: return None
def own_class(s):
    s=(s or '').lower()
    if 'private-equity' in s or 'pe-owned' in s or 'private_equity' in s or 'sponsor-controlled' in s or 'lender-owned' in s: return 'pe'
    if 'open_source' in s or 'open-source' in s: return 'oss'
    if s.startswith('public') or 'subsidiary of cisco' in s or 'subsidiary (hpe' in s: return 'public'
    if 'state' in s: return 'state'
    if 'individual' in s or 'hobby' in s: return 'hobby'
    if s.strip()=='subsidiary': return 'subsidiary'
    if 'subsidiary' in s: return 'public' if 'public' in s else ('pe' if 'pe' in s or 'private equity' in s else 'private')
    if 'private' in s or 'founder' in s or 'venture' in s or 'individual' in s: return 'private'
    return 'unknown'
def attrs(r, vshare_iot=None):
    v=(r.get('vendor') or '').lower(); k=nn(v); role=r['role']; g=GROUP[role]; src=(r.get('src') or '').lower()
    pv=panel_vendor(r); p=PAN.get(pv) if pv else None; e=EXT.get(k)
    a=dict(pv=pv,revenue=None,owner='unknown',pe=None,bounty=None,pledge=None)
    reg=REG.get(k) or REG.get(nn(pv) if pv else '') or {}
    a['cna']=bool(reg.get('cna')); a['vdp_listed']=bool(reg.get('vdp')); a['bounty_listed']=bool(reg.get('bounty'))
    if p:
        a['revenue']=rev(p); a['owner']=own_class(p['ownership'])
        if a['owner']=='pe' and pv in PE_SINCE and (r.get('pub') or '9999')<PE_SINCE[pv][0]: a['owner']=PE_SINCE[pv][1]
        a['pe']=1 if a['owner']=='pe' else 0
        a['bounty']={'2.0':'public','1.0':'private','0.0':'none'}.get(p['bounty'])
        a['pledge']={'1.0':1,'0.0':0}.get(p['pledge'])
        a['tier']='hyperscale' if pv in HYPER else ('large' if (a['revenue'] or 0)>=5000 else 'midmarket')
    else:
        if e:
            a['owner']=own_class(e.get('owner_type'))
            if a['owner']=='subsidiary':
                lo=(e.get('legal_owner') or '').lower()
                a['owner']='public' if re.search(r'broadcom|ibm|daifuku|fortinet|foxconn|hon hai|cisco|hpe|oracle|nyse|nasdaq|listed',lo) else 'private'
            a['pe']=1 if a['owner']=='pe' else 0
            m=re.search(r'(\d[\d,]*\.?\d*)',(e.get('revenue_usd_m') or ''))
            a['revenue']=float(m.group(1).replace(',','')) if m else None
            a['vdp_ext']=(e.get('vdp') or '').strip().lower()=='yes'
            a['bounty']={'public_paid':'public','private_or_invite':'private','none_found':'none'}.get((e.get('bug_bounty') or '').strip())
        if v in HYPER_V: a['tier']='hyperscale'
        elif v in HOBBY_V: a['tier']='small'
        elif role in('plugin','hobby') or a['owner']=='hobby': a['tier']='small'
        elif v in OSS_V or src in OSS_SRC or role=='component' or (e and a['owner']=='oss'): a['tier']='oss'; a['owner']='oss' if a['owner']=='unknown' else a['owner']
        elif v in LARGE_V: a['tier']='large'; a['owner']='public' if a['owner']=='unknown' else a['owner']
        elif g=='device' or (vshare_iot or 0)>=0.6: a['tier']='device'
        elif role in('edge','srv_exposed','srv_internal','client_os','ics','cloud'): a['tier']='midmarket'
        else: a['tier']='small'
    if a['tier']=='midmarket' and g=='device': a['tier']='device'
    if a['bounty'] is None: a['bounty']='public' if a['bounty_listed'] else ('none' if p is None else None)
    if a.get('vdp_ext'): a['vdp_listed']=True
    a['any_program']= (a['bounty'] in('public','private')) or a['vdp_listed'] or a['cna']
    return a
TIERS=['hyperscale','large','midmarket','device','oss','small']
TLAB={'hyperscale':'Hyperscale platforms','large':'Large enterprise vendors','midmarket':'Mid-market software vendors','device':'Device makers','oss':'Open-source projects','small':'Plug-in authors and small projects'}
TSUB={'hyperscale':'Microsoft, Apple, Google, Amazon, Meta','large':'revenue above $5bn: Cisco, Oracle, SAP, Adobe, Fortinet, Samsung','midmarket':'Ivanti, Citrix, SonicWall, Progress, Zoho and smaller vendors','device':'D-Link, TP-Link, Tenda, Netgear, QNAP, DrayTek','oss':'Apache, Mozilla, Jenkins, Drupal, PHP and community code','small':'WordPress plug-ins, student projects, unclassified'}
