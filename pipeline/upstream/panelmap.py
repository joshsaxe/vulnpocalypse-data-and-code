# Map each RCE flaw to a Task-1 panel vendor (86 vendors) where possible; attach panel attributes.
import sys,re,csv,json
sys.path.insert(0,'/home/claude/research/scripts'); sys.path.insert(0,'/home/claude/research/rce/scripts')
import panel
PAN={r['vendor']:r for r in csv.DictReader(open('/home/claude/research/out/vendor_panel.csv'))}
_idx=[]
for name,(grp,cpes,affrx,cnas,kevn) in panel.V.items():
    _idx.append((name,grp,set(c.replace('_',' ') for c in cpes),re.compile(affrx),set(s.lower() for s in cnas)))
def panel_vendor(r):
    v=(r.get('vendor') or '').lower(); src=(r.get('src') or '').lower()
    for name,grp,cpes,rx,cnas in _idx:
        if v and (v in cpes or rx.search(v)): return name
    for name,grp,cpes,rx,cnas in _idx:
        if src in cnas: return name
    return None
