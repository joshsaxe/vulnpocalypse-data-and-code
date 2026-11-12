import json,datetime
P='/home/claude/research/rce/out/'
def load(path=P+'rce.jsonl'):
    rows=[json.loads(l) for l in open(path)]
    lab=json.load(open(P+'labels.json'))
    for r in rows:
        L=lab.get(r['id'])
        r['ev_wide']=L['wide'] if L else []
        r['ev_other']=(L['targeted']+L['unclear']) if L else []
        r['zd']=bool(L and L['zd'])
        r['listed']=bool(L)
        r['expl']=bool(r['kev'] or L)                 # any documented exploitation
        r['wide']=bool(r['expl'] and r['ev_wide'])
        r['bucket']='wide' if r['wide'] else ('minimal' if r['expl'] else 'never')
        # stricter breadth label: ignores a lone ransomware flag in the CISA catalog
        strong=[t for t in r['ev_wide'] if t!='ransomware flag in CISA catalog']
        r['wide_strict']=bool(r['expl'] and strong)
    return rows
def main(rows, lo='2019-01-01', hi='2025-12-31', pop='rce'):
    return [r for r in rows if r[pop] and lo<=r['pub']<=hi]
