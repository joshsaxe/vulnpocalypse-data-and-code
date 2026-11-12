# Definitions shared by the Task-2 scripts: RCE population test, CVSS parsing, weakness classes.
import re
EXPL_RCE = re.compile(r"remote(ly)?[- ](code|command)[- ]execution|\bRCE\b|pre-?auth\w* (code|command) execution", re.I)
REMOTE   = re.compile(r"\bremote(ly)?\b|over (a|the) network|unauthenticated attacker|network[- ](adjacent|based) attacker", re.I)
EXEC = re.compile(r"""
 (execut\w*|run|runs|running|inject\w*|launch\w*|spawn\w*)\s+(of\s+)?(an?\s+|the\s+|any\s+)?
 (arbitrary|malicious|attacker[- ](controlled|supplied|provided|chosen)|unauthori[sz]ed|unintended|remote|their\s+own|crafted|external|untrusted|user[- ]supplied|injected)?\s*
 ((os|operating[- ]system|system[- ]level|system|shell|native|php|python|java|groovy|ruby|perl|lua|server[- ]side|binary|machine|unsigned|privileged|root|bash|powershell|sh)\s+)?
 (code|commands?|programs?|executables?|binaries|payloads?|shell\s?code)\b
 |\b(code|command)\s+(execution|injection)\b
 |\barbitrary\s+(code|commands?)\b
 |\bos\s+command
 |exploit\s+(heap|stack|object)\s+corruption
 |\b(web\s?shell|reverse\s+shell)\b
 |result\s+in\s+takeover\s+of
""", re.I|re.X)
XSS = re.compile(r"cross[- ]?site[- ]scripting|\bXSS\b|web script|html injection|arbitrary (java)?script|in (the|a) (context of (the|a) )?(victim|user|admin\w*)'?s? (web )?browser|script code in|stored .{0,30}script|javascript code", re.I)
SQLI = re.compile(r"sql injection|sql command|sql quer|sql statement|\bsqli\b", re.I)
LOCAL = re.compile(r"\b(an app|a (malicious |sandboxed |local )?app(lication)?|local (user|attacker|privilege)|locally authenticated|physical access|physically (present|proximate)|a local\b|malicious (dll|library))", re.I)
RCE_CWE = {'CWE-77','CWE-78','CWE-88','CWE-94','CWE-95','CWE-96','CWE-98','CWE-502','CWE-434','CWE-917','CWE-1336','CWE-470'}
CMD={'CWE-77','CWE-78','CWE-88'}
CODE={'CWE-94','CWE-95','CWE-96','CWE-98','CWE-502','CWE-917','CWE-1336','CWE-470','CWE-913','CWE-74','CWE-116','CWE-20'}  # 74/116/20 only as weak fallbacks (see wk())
DESER={'CWE-502'}
INJ={'CWE-94','CWE-95','CWE-96','CWE-98','CWE-917','CWE-1336','CWE-470','CWE-913'}
UPL={'CWE-434','CWE-22','CWE-23','CWE-35','CWE-36','CWE-73','CWE-59','CWE-24','CWE-29'}
MEM={'CWE-119','CWE-120','CWE-121','CWE-122','CWE-125','CWE-787','CWE-416','CWE-415','CWE-190','CWE-191','CWE-476','CWE-843','CWE-824','CWE-908','CWE-131','CWE-129','CWE-680','CWE-788','CWE-805','CWE-823','CWE-362','CWE-704','CWE-763','CWE-786','CWE-822','CWE-825','CWE-1284','CWE-126','CWE-124','CWE-134'}
AUTH={'CWE-287','CWE-306','CWE-862','CWE-863','CWE-284','CWE-285','CWE-269','CWE-798','CWE-522','CWE-288','CWE-290','CWE-294','CWE-295','CWE-345','CWE-346','CWE-347','CWE-352','CWE-639','CWE-1188','CWE-732','CWE-276','CWE-266'}
D_MEM = re.compile(r"buffer overflow|out[- ]of[- ]bounds|use[- ]after[- ]free|memory corruption|heap[- ](based|corruption|overflow)|stack[- ](based|overflow)|type confusion|integer (over|under)flow|double free|uninitiali[sz]ed|memory safety|overflow", re.I)
D_CMD = re.compile(r"command injection|os command|inject\w* (arbitrary )?(os |shell |system )?commands?|shell metacharacters|arbitrary (os |shell |system )?commands?", re.I)
D_DES = re.compile(r"deseriali[sz]", re.I)
D_UPL = re.compile(r"file upload|upload\w* (of )?(arbitrary|malicious|dangerous|php|a web ?shell)|unrestricted upload|path traversal|directory traversal|arbitrary file (write|creation|overwrite)", re.I)
D_INJ = re.compile(r"code injection|template injection|\bssti\b|expression language|\bognl\b|\bjndi\b|\beval\b|inject\w* (arbitrary )?(php |python |java )?code|prototype pollution|file inclusion", re.I)
D_AUTH= re.compile(r"authentication bypass|bypass(es|ing)? authentication|missing authentication|improper access control|hard-?coded|default (credentials|password)", re.I)

def parse_vec(vec, ver):
    if not vec: return {}
    parts={}
    for p in vec.split('/'):
        if ':' in p:
            k,v=p.split(':',1); parts[k]=v
    if ver in (3,4):
        ui=parts.get('UI'); 
        if ui is not None and ui!='N': ui='R'
        if ver==4:
            c,i,a=parts.get('VC'),parts.get('VI'),parts.get('VA')
            ac='H' if (parts.get('AC')=='H' or parts.get('AT')=='P') else parts.get('AC')
        else:
            c,i,a=parts.get('C'),parts.get('I'),parts.get('A'); ac=parts.get('AC')
        return dict(av=parts.get('AV'),pr=parts.get('PR'),ui=ui,ac=ac,c=c,i=i,a=a,s=parts.get('S'))
    if ver==2:
        pr={'N':'N','S':'L','M':'H'}.get(parts.get('Au'))
        m={'C':'H','P':'L','N':'N'}
        return dict(av=parts.get('AV'),pr=pr,ui=None,ac={'L':'L','M':'L','H':'H'}.get(parts.get('AC')),c=m.get(parts.get('C')),i=m.get(parts.get('I')),a=m.get(parts.get('A')),s=None)
    return {}

MEMW={'CWE-119','CWE-120','CWE-121','CWE-122','CWE-787','CWE-416','CWE-415','CWE-190','CWE-191','CWE-843','CWE-824','CWE-131','CWE-129','CWE-680','CWE-788','CWE-823','CWE-763','CWE-786','CWE-822','CWE-825','CWE-124','CWE-134'}
D_MEMW = re.compile(r"buffer overflow|out[- ]of[- ]bounds write|use[- ]after[- ]free|memory corruption|heap[- ](based|corruption|overflow)|stack[- ](based|overflow)|type confusion|double free|write[- ]what[- ]where", re.I)
def is_rce(desc, cwes, v):
    """Return (flag, basis). Same rule for every CVE; uses only the NVD record.
    basis: explicit (says remote code/command execution) | phrase (says code or commands can be executed)
           | file (code execution when a user opens attacker-supplied content; local vector)
           | cwe (command injection / code injection / deserialization / dangerous upload class, scored full compromise)
           | memory (remotely reachable memory-corruption write, scored full compromise)"""
    cw=set(cwes or [])
    explicit=bool(EXPL_RCE.search(desc))
    ex=bool(EXEC.search(desc))
    if ex and not explicit:
        xss = bool(XSS.search(desc)) or ('CWE-79' in cw and not (cw & RCE_CWE))
        sqli= bool(SQLI.search(desc)) and not re.search(r"arbitrary (os |system |shell )?commands?\b(?! in the database)|arbitrary code|code execution", desc, re.I)
        if xss or (sqli and 'CWE-89' in cw and not (cw & RCE_CWE)): ex=False
    av,pr,ui=v.get('av'),v.get('pr'),v.get('ui')
    full = v.get('c')=='H' and v.get('i')=='H'
    cwe_rce = bool(cw & RCE_CWE) and 'CWE-79' not in cw and full
    mem = (bool(cw & MEMW) or bool(D_MEMW.search(desc))) and full and v.get('a')=='H'
    local_words=bool(LOCAL.search(desc))
    if av in ('N','A'):
        if not (explicit or ex or cwe_rce or mem): return False,None
        if local_words and not explicit and not REMOTE.search(desc): return False,None
        return True, ('explicit' if explicit else 'phrase' if ex else 'cwe' if cwe_rce else 'memory')
    if av=='L':
        if explicit: return True,'explicit'
        if ui=='R' and pr=='N' and not local_words and ex: return True,'file'
        return False,None
    if av=='P': return False,None
    if explicit or (ex and REMOTE.search(desc) and not local_words): return True,('explicit' if explicit else 'phrase')
    return False,None

def wk(cwes, desc):
    cw=set(cwes or [])
    if cw & CMD: return 'cmd'
    if cw & DESER: return 'deser'
    if cw & INJ: return 'inject'
    if cw & MEM: return 'memory'
    if cw & UPL: return 'upload'
    if 'CWE-89' in cw: return 'sqli'
    if cw & AUTH: return 'auth'
    if D_CMD.search(desc): return 'cmd'
    if D_DES.search(desc): return 'deser'
    if D_MEM.search(desc): return 'memory'
    if D_UPL.search(desc): return 'upload'
    if D_INJ.search(desc): return 'inject'
    if SQLI.search(desc): return 'sqli'
    if D_AUTH.search(desc): return 'auth'
    return 'other'

def delivery(v):
    av,pr,ui=v.get('av'),v.get('pr'),v.get('ui')
    if av is None: return 'unknown'
    if ui=='R': return 'user'
    if pr in ('L','H'): return 'creds'
    if av in ('N','A') and pr=='N': return 'open'
    return 'unknown'
