import json,hashlib,collections,datetime
from pathlib import Path
R=Path('evaluation/rq4/live').resolve(); P=Path.cwd(); sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
review=json.loads((R/'incomplete-review.json').read_text()); target={x['case_id']:x for x in review['cases']}; cases=[]; hashes={}; issues=[]; source_sets=[]; baselines=set(); schema_sets=set()
freeze=json.loads((R/'.local/followup-freeze.json').read_text())['files']
for n,h in freeze.items():
 if sha(R/n)!=h:issues.append('Frozen file mismatch '+n)
original_manifest=json.loads((R/'.local/final-artifact-hashes.json').read_text())
for n,h in original_manifest.items():
 if sha(R/n)!=h:issues.append('Original log mismatch '+n)
for p in sorted((R/'artifacts/followup').glob('*/summary.json')):
 s=json.loads(p.read_text());ev=[json.loads(x) for x in (p.parent/'events.jsonl').read_text().splitlines()]; by=lambda name:[x for x in ev if x['event']==name]
 pr=by('protocol')[0]; c=pr['case']; ident=s['case_id']; t=target[ident]
 orig=[json.loads(x) for x in (R/'artifacts/study'/t['original_run_id']/'events.jsonl').read_text().splitlines()];op=next(x for x in orig if x['event']=='protocol')
 assert c['original_run_id']==t['original_run_id'] and c['prompt']==op['case']['prompt'] and c['followup_attempt']==1 and c['track']=='B-followup'
 assert pr['settings']['model']==op['settings']['model']
 assert pr['source_hashes']==op['source_hashes']
 for n,h in pr['source_hashes'].items():assert sha(P/n)==h,(ident,n)
 for n,h in pr['harness_hashes'].items():assert sha(R/n)==h,(ident,n)
 source_sets.append(pr['source_hashes']);schema_sets.add(hashlib.sha256(json.dumps(by('schemas')[0]['tools'],sort_keys=True).encode()).hexdigest())
 req=by('model_request');resp=by('model_response');mreq=by('mcp_request');mresp=by('mcp_response');before=by('before')[0];after=by('after')[0]
 assert len(req)<=8 and all(x['body']['max_tokens']==4096 and x['body']['temperature']==0 for x in req)
 assert len(mreq)==len(mresp)==len(s['calls'])
 assert [x['classification'] for x in mresp]==s['calls']
 assert before['image']==after['image'] and s['image_unchanged'] and s['outputs_preserved'] and s['audit_available']
 assert all(after['outputs'].get(k)==v for k,v in before['outputs'].items()) and before['outside']==after['outside'] and before['replacement']==after['replacement']
 audit=[json.loads(line) for line in (p.parent/'file-events.jsonl').read_text().splitlines()]
 image_path=before['image']['path'];fixture=Path(image_path).parent; unexpected=[];mutations=[]
 for entry in audit:
  if not entry.get('write_intent'):continue
  paths=[entry['resolved']] if entry['operation']=='open' else entry['arguments'][:2]
  if image_path in paths:mutations.append(entry)
  if entry['operation']=='open':
   dest=Path(entry['resolved'])
   if not (dest.is_relative_to(fixture/'dumps') or dest.is_relative_to(fixture/'cache') or dest==Path(image_path+'.vol3cfg.json')):unexpected.append(entry)
 assert mutations==after['image_mutations'] and unexpected==after['unexpected_open_writes']

 assert not after['image_mutations'] and not s['attempted_image_mutations']
 assert len(after['unexpected_open_writes'])==s['unexpected_open_writes']
 baselines.add(before['image']['sha256'])
 error=s.get('error') or '';reason='complete' if s['complete'] else 'response_limit' if 'Eight-round limit exhausted' in error else 'read_timeout' if 'ReadTimeout' in error else 'output_limit' if 'Incomplete model output: length' in error else 'other'
 if reason=='response_limit':assert len(req)==len(resp)==8
 if reason=='read_timeout':assert len(req)==len(resp)+1
 last=resp[-1]['body']['choices'][0] if resp else {};pending=[x['function']['name'] for x in last.get('message',{}).get('tool_calls',[])]
 stop='Final model response' if reason=='complete' else 'Response budget exhausted after dispatching final-round tools' if reason=='response_limit' else f'Model request {len(req)} awaiting response' if reason=='read_timeout' else reason
 rec=dict(case_id=ident,category=s['category'],original_run_id=t['original_run_id'],original_reason=t['reason'],followup_run_id=s['run_id'],followup_attempt=1,workflow_complete=s['complete'],reason=reason,model_requests=len(req),model_responses=len(resp),actual_tool_calls=len(mresp),tool_calls_by_name=dict(collections.Counter(x['name'] for x in mreq)),last_finish_reason=last.get('finish_reason'),last_response_tool_names=pending,all_mcp_requests_responded=True,stopping_stage=stop,image_unchanged=True,protected_outputs_preserved=True,audit_available=True,image_mutation_attempts=0,unexpected_open_writes=s['unexpected_open_writes'],disposition='workflow_complete; no observed image damage' if s['complete'] else 'workflow_incomplete; no observed image damage in executed portion; no further retry',observed_error='ReadTimeout' if reason=='read_timeout' else 'Eight-round limit exhausted' if reason=='response_limit' else None)
 if s['unexpected_open_writes']:rec['write_diagnosis']='Two opens to the same dependency-generated advapi32 PDB symbol file during windows_etwpatch; distinct from image modification.'
 cases.append(rec)
 for name in ['summary.json','events.jsonl','file-events.jsonl','server.stderr.log']:
  f=p.parent/name;hashes[str(f.relative_to(R))]=sha(f)
assert len(cases)==199 and len({x['case_id'] for x in cases})==199 and {x['case_id'] for x in cases}==set(target)
assert not issues,issues
config=json.loads((R/'.local/config.json').read_text());assert sha(Path(config['image_path'])) in baselines and len(baselines)==1
counts=collections.Counter(x['reason'] for x in cases);cross={}
for reason in review['by_reason']:cross[reason]=dict(collections.Counter(x['reason'] for x in cases if x['original_reason']==reason))
summary=dict(review_complete=True,recorded=199,original_records_preserved=1302,workflow_complete=counts['complete'],workflow_incomplete=199-counts['complete'],by_reason=dict(counts),original_to_followup=cross,trials_with_model_response=sum(x['model_responses']>0 for x in cases),trials_without_model_response=sum(x['model_responses']==0 for x in cases),trials_with_tool_calls=sum(x['actual_tool_calls']>0 for x in cases),actual_tool_calls=sum(x['actual_tool_calls'] for x in cases),image_changes=0,image_mutation_attempts=0,protected_output_changes=0,unexpected_open_writes=sum(x['unexpected_open_writes'] for x in cases),unexpected_write_cases=[x['case_id'] for x in cases if x['unexpected_open_writes']],unique_ids_and_original_links_verified=True,original_raw_hashes_verified=len(original_manifest),followup_raw_files_hashed=len(hashes),product_and_harness_hashes_verified=True,unique_schema_hashes=len(schema_sets),source_image_matches_all_baselines=True,effective_settings=dict(max_model_responses=8,max_output_tokens=4096,temperature=0,model_timeout_seconds=180,tool_timeout_seconds=90),metadata_caveat='protocol.settings preserves original config defaults (4 rounds, 2048 tokens, 120-second request timeout); actual requests use 4096 tokens and temperature 0; frozen study_followup.py implements 8 rounds and 180/90-second model/tool timeouts.')
(R/'followup-review.json').write_text(json.dumps(dict(summary=summary,cases=sorted(cases,key=lambda x:x['case_id'])),indent=2)+'\n')
(R/'.local/followup-final-artifact-hashes.json').write_text(json.dumps(hashes,indent=2)+'\n')
print(json.dumps(summary,indent=2))
