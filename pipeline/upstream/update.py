# How the fix reaches the customer, per flaw:
#  'vendor'     installed by the vendor by default (or vendor-operated service)
#  'optional'   offered automatically but someone must accept it, switch it on, or own the right model
#  'customer'   the customer downloads and installs it
#  'downstream' library: every product that embeds it must ship its own fix
# Product-family rules are read from research_notes/.../update_models_major_products.csv (62 families) and the vendor extension table; the rest follows product type.
import re,csv,os
N='/home/claude/research/research_notes/RCE flaw vendors attackers and volume/'
def nn(s): return re.sub(r'[^a-z0-9]','',(s or '').lower())
MAP={'auto_default':'vendor','vendor_operated':'vendor','optional':'optional','some_models':'optional','manual':'customer',
     'automatic_default':'vendor','automatic_optional':'optional','prompted':'optional'}
ALIAS={'paloalto':'paloaltonetworks','zohocorp':'zohomanageengine','zoho':'zohomanageengine','manageengine':'zohomanageengine','vmware':'vmwarebroadcom','broadcom':'vmwarebroadcom',
       'pulsesecure':'ivanti','ui':'ubiquiti','ubnt':'ubiquiti','tendacn':'tenda','ipswitch':'progress','dahuasecurity':'dahua','foxitsoftware':'foxit','dtsearch':'rarlab','7zip':'7zip',
       'netscaler':'citrix','mobileiron':'ivanti','googledevicemakers':'google','synacor':'synacor','hikvisiondigitaltechnology':'hikvision'}
SKIP=re.compile(r'mitigation|cloud-hosted|play system',re.I)
RULES=[]
p=N+'update_models_major_products.csv'
if os.path.exists(p):
    for r in csv.DictReader(open(p,encoding='utf-8')):
        code=MAP.get((r.get('update_code') or '').strip().lower())
        if not code or SKIP.search(r.get('product_family') or ''): continue
        vk=nn(r['vendor']); vk={'googledevicemakers':'google','wordpresspluginandthemevendors':'__plugin__'}.get(vk,vk)
        rx=(r.get('product_regex') or '').strip()
        try: rxc=re.compile(rx,re.I) if rx else None
        except re.error: rxc=None
        RULES.append((vk,rxc,code,(r.get('since') or '').strip()[:10],(r.get('verified') or 'N').strip()[:1].upper(),r.get('product_family') or ''))
# specific-first ordering: rules with a regex before whole-vendor rules; Pixel before Android
RULES.sort(key=lambda t:(t[1] is None, 0 if 'pixel' in t[5].lower() else 1))
VEND={}
p=N+'vendor_attributes_extension.csv'
if os.path.exists(p):
    for r in csv.DictReader(open(p,encoding='utf-8')):
        c=MAP.get((r.get('update_model') or '').strip().lower())
        if c: VEND[nn(r['vendor'])]=(c,'Y' if (r.get('verified') or '').strip().upper().startswith('Y') else 'N')
AUTO_CLIENT_V={'whatsapp','zoom','signal','telegram','opera','brave','vivaldi','valve','discord','slack','spotify','facebook','meta'}
APPLE_IOS=re.compile(r'iphone|ipad|\bios\b|safari|webkit|watchos|tvos|visionos')
def update_model(r):
    v=(r.get('vendor') or '').lower(); k=nn(v); k=ALIAS.get(k,k); role=r['role']; prod=(r.get('prod') or '').lower(); text=(prod+' | '+(r.get('desc') or '')).lower()
    if role=='cloud': return 'vendor','type'
    if role=='component': return 'downstream','type'
    if role=='plugin': return 'optional','table'
    if re.search(r'winrar',prod) or re.search(r'\bwinrar\b',text): return 'customer','table'
    if k=='apple' and role=='client_os': return 'vendor','recalled'
    if k=='microsoft': return ('vendor','table') if role=='client_os' else ('customer','table' if re.search(r'exchange|sharepoint',text) else 'type')
    if k=='google' and role=='client_os' and not re.search(r'android',text): return 'vendor','table'
    if k=='adobe':
        if re.search(r'acrobat|reader',prod): return 'vendor','recalled'
        return ('customer','type') if role!='client_os' else ('optional','type')
    for vk,rx,code,since,ver,fam in RULES:
        if vk!=k: continue
        if rx is None or rx.search(prod) or rx.search(text):
            if since and code in('vendor','optional') and r['pub']<since: return 'customer','table' if ver=='Y' else 'recalled'
            return code,('table' if ver=='Y' else 'recalled')
    if role=='client_os' and v in AUTO_CLIENT_V: return 'vendor','type'
    if k in VEND and role in('client_os','iot','edge','srv_exposed','srv_internal'):
        c,ver=VEND[k]
        if not (role!='client_os' and k in('samsung','huawei','mozilla','arm','qualcomm','mediatek')): return c,('table' if ver=='Y' else 'recalled')
    return 'customer','type'
ULAB={'vendor':'Vendor installs the fix by default','optional':'Offered automatically, but someone must accept it or switch it on','customer':'Customer downloads and installs the fix','downstream':'Library: every product that embeds it must ship a fix'}
