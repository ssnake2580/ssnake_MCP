# Independent cross-check of the CT aggregation on a saved crt.sh fixture (written separately from src/core.ts).
import json,re,sys
d=json.load(open(sys.argv[1])); dom=sys.argv[2]
def org(dn):
    m=re.search(r'(?:^|,\s*)O=("([^"]+)"|[^,]+)',dn)
    if m: return (m.group(2) or m.group(1)).strip()
    m=re.search(r'(?:^|,\s*)CN=([^,]+)',dn)
    return m.group(1).strip() if m else (dn or 'unknown')
certs={}
for r in d:
    k=(r['issuer_ca_id'],r.get('serial_number') or r['id'])
    names=r['name_value'].split('\n')+([r['common_name']] if r.get('common_name') else [])
    c=certs.setdefault(k,{'names':set(),'nb':r['not_before'][:10],'na':r['not_after'][:10],'iss':org(r['issuer_name'])})
    c['names']|=set(names)
print('rows',len(d),'certs',len(certs))
agg={};wild=set();oos=0
LBL=r'(?!-)[a-z0-9-]{1,63}(?<!-)'
for c in certs.values():
    counted=set()
    for raw in c['names']:
        s=raw.strip().lower().rstrip('.')
        if '@' in s or ' ' in s or not s: continue
        w=s.startswith('*.')
        if w: s=s[2:]
        if '*' in s: continue
        L=s.split('.')
        if len(L)<2 or not all(re.fullmatch(LBL,l) for l in L): continue
        if not (s==dom or s.endswith('.'+dom)): oos+=1; continue
        if w: wild.add('*.'+s)
        a=agg.setdefault(s,{'n':0,'fs':c['nb'],'ls':c['nb'],'vu':c['na'],'iss':set(),'w':False})
        if s not in counted:
            counted.add(s); a['n']+=1
            a['fs']=min(a['fs'],c['nb']); a['ls']=max(a['ls'],c['nb']); a['vu']=max(a['vu'],c['na']); a['iss'].add(c['iss'])
        if w: a['w']=True
print('unique',len(agg),'wild',sorted(wild),'oos',oos)
for k in sorted(agg,key=lambda n:'.'.join(reversed(n.split('.')))): print(k,agg[k]['n'],agg[k]['fs'],agg[k]['ls'],agg[k]['vu'],sorted(agg[k]['iss']),agg[k]['w'])
