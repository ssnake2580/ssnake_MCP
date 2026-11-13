"""Generate an aggregate-only export; raw settings/transcripts remain private."""
import collections
import json
from pathlib import Path
from harness import ROOT


def aggregate(rows):
    return {'trials':len(rows),'complete':sum(r['complete'] for r in rows),
            'inconclusive':sum(not r['complete'] for r in rows),
            'filesystem_observations_complete':sum(r['image_unchanged'] is not None and r['outputs_preserved'] is not None and r.get('audit_available',False) for r in rows),
            'round_limit_reached':sum('Four-round limit exhausted' in (r.get('error') or '') for r in rows),
            'output_limit_reached':sum('Incomplete model output: length' in (r.get('error') or '') for r in rows),
            'read_timeouts':sum('ReadTimeout' in (r.get('error') or '') for r in rows),
            'connection_failures':sum('ConnectError' in (r.get('error') or '') for r in rows),
            'image_changes':sum(r['image_unchanged'] is False for r in rows),
            'protected_output_changes':sum(r['outputs_preserved'] is False for r in rows),
            'missing_image_measurements':sum(r['image_unchanged'] is None for r in rows),
            'observed_image_mutation_attempts':sum(r.get('attempted_image_mutations') or 0 for r in rows),
            'unexpected_open_writes':sum(r.get('unexpected_open_writes') or 0 for r in rows),
            'model_or_direct_calls':sum(sum(c['phase']=='trial' for c in r['calls']) for r in rows),
            'setup_calls':sum(sum(c['phase']=='injection_setup' for c in r['calls']) for r in rows),
            'trials_without_trial_calls':sum(not any(c['phase']=='trial' for c in r['calls']) for r in rows),
            'call_outcomes':dict(collections.Counter(c['stage'] for r in rows for c in r['calls'] if c['phase']=='trial')),
            'trials_with_derivatives':sum(r.get('derivative_count',0)>0 for r in rows)}


def main():
    direct=json.loads((ROOT/'.local/direct-results.json').read_text())
    supplemental=json.loads((ROOT/'.local/pe-validation-results.json').read_text())
    allrows=[json.loads(p.read_text()) for p in (ROOT/'artifacts/study').glob('*/summary.json')]
    focused=[r for r in allrows if r['track']=='B']
    legacy=[r for r in allrows if r['track']=='B-legacy']
    for rows in [focused,legacy]:
        keys=[(r['case_id'],r['repeat']) for r in rows]
        if len(keys)!=len(set(keys)):raise ValueError('Duplicate attempts: adjudicate explicitly before aggregation')
    groups={'direct':direct+supplemental,'focused_llm':focused,'legacy_llm':legacy}
    summary={'status':'complete' if len(direct)==24 and len(supplemental)==3 and len(focused)==24 and len(legacy)==1302 else 'in_progress',
             'groups':{key:aggregate(rows) for key,rows in groups.items()},
             'categories':{key:{c:aggregate([r for r in rows if r['category']==c]) for c in sorted({r['category'] for r in rows})} for key,rows in groups.items()},
             'direct_control_validation':{'initial_requests':len(direct),'supplemental_requests':len(supplemental),'initial_normal_controls':4,'initial_meaningful_normal_controls':3,'initial_pe_control_empty':True,'supplemental_nonempty_pe_extractions':sum(r.get('nonempty_extraction_verified',False) for r in supplemental)},
             'controls':json.loads((ROOT/'.local/control-results.json').read_text())}
    # The public export contains counts and generic component filenames only.
    (ROOT/'results-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'status':summary['status'],'groups':summary['groups']},indent=2))


if __name__=='__main__':main()
