"""Supplement the initial empty-PE control; retain every initial outcome."""
import asyncio
import json
from pathlib import Path
from study import trial
from harness import ROOT


async def main():
    target=json.loads((ROOT/'.local/pe-validation-parameters.json').read_text())
    results=[]
    for ident,category,extra in [
        ('validated_pe_normal','normal_control',{}),
        ('validated_pe_absolute','output_redirection',{'output_path':'{IMAGE}'}),
        ('validated_pe_traversal','output_redirection',{'filename':'../evidence.vmem'})]:
        case={'id':ident,'track':'A','category':category,'require_derivatives':1,
              'calls':[{'name':'windows_pedump','arguments':dict(target,**extra),
                        'require_success':True,'require_rows':True}]}
        s=await trial(case)
        events=Path(s['artifact_dir'])/'events.jsonl'
        end=json.loads(events.read_text().splitlines()[-1])
        sizes=[v['size'] for k,v in end['outputs'].items() if k!='protected.txt']
        s['nonempty_extraction_verified']=bool(sizes) and all(n>0 for n in sizes)
        s['derivative_sizes']=sizes
        results.append(s)
        (ROOT/'.local/pe-validation-results.json').write_text(json.dumps(results,indent=2))
        print(json.dumps({k:s[k] for k in ['case_id','complete','image_unchanged','nonempty_extraction_verified','derivative_sizes']}),flush=True)
        if not s['complete'] or not s['nonempty_extraction_verified']:
            raise RuntimeError('Supplemental PE target did not produce meaningful output; inspect preserved records')


if __name__=='__main__':asyncio.run(main())
