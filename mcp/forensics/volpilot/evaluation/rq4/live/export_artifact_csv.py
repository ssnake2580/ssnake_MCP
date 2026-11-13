"""Export public RQ4 tables from retained measurements; never exports model outputs.
Run with uv run --no-sync --offline python evaluation/rq4/live/export_artifact_csv.py
from VolPilot. Private artifacts are needed to regenerate, not to read the CSVs.
"""
import collections
import csv
import json
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'public-csv'
PRIVATE_HOST = urllib.parse.urlparse(json.loads((ROOT/'.local/config.json').read_text())['base_url']).hostname


def write(name, rows):
    assert rows
    for row in rows:
        for value in row.values():
            text = str(value)
            assert '/Users/' not in text and (not PRIVATE_HOST or PRIVATE_HOST not in text), (name, row.get('case_id'))
            assert not text.lstrip().startswith(('=', '+', '@')), 'Unsafe spreadsheet cell'
    with (OUT / name).open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)


def reason(summary):
    error = summary.get('error') or ''
    if summary['complete']:
        return 'complete'
    for marker, result in [('round limit exhausted', 'response_limit'),
                           ('Incomplete model output: length', 'output_limit'),
                           ('ReadTimeout', 'read_timeout'), ('ConnectError', 'connection_failure')]:
        if marker in error:
            return result
    raise ValueError(error)


def main():
    OUT.mkdir(exist_ok=True)
    corpus = list(csv.DictReader((ROOT.parent/'index.csv').open(encoding='utf-8-sig', newline='')))
    catalog = {r['id']: r for r in corpus}
    assert len(catalog) == len(corpus) == 1302
    review = json.loads((ROOT/'followup-review.json').read_text())
    follow = {r['case_id']: r for r in review['cases']}
    rows = []
    for directory, track in [('study', 'B-legacy'), ('followup', 'B-followup')]:
        for p in sorted((ROOT/'artifacts'/directory).glob('*/summary.json')):
            s = json.loads(p.read_text())
            if s['track'] != track:
                continue
            events = [json.loads(line) for line in (p.parent/'events.jsonl').read_text().splitlines()]
            get = lambda name: [e for e in events if e['event'] == name]
            protocol = get('protocol')[0]
            case = protocol['case']
            ident = s['case_id']
            assert ident in catalog and catalog[ident]['prompt'] in case['prompt']
            req, resp = get('model_request'), get('model_response')
            calls = get('mcp_response')
            assert len(calls) == len(get('mcp_request')) == len(s['calls'])
            status = reason(s)
            namecounts = collections.Counter(c['classification']['name'] for c in calls)
            before, after = get('before')[0], get('after')[0]
            is_follow = track == 'B-followup'
            record = dict(stratum='followup' if is_follow else 'original', case_id=ident,
                run_id=s['run_id'], original_run_id=case.get('original_run_id',s['run_id']),
                category=s['category'], prompt=catalog[ident]['prompt'],
                presented_prompt_template=case['prompt'],
                workflow_complete=s['complete'], outcome=status,
                model_requests=len(req), model_responses=len(resp),
                actual_tool_calls=len(calls), tool_calls_by_name=json.dumps(dict(sorted(namecounts.items())), sort_keys=True),
                all_mcp_requests_responded=True, max_model_responses=8 if is_follow else 4,
                max_output_tokens=4096 if is_follow else 2048, temperature=0,
                model_timeout_seconds=180, tool_timeout_seconds=90,
                image_unchanged=s['image_unchanged'], protected_outputs_preserved=s['outputs_preserved'],
                image_sha256_before=before['image']['sha256'], image_sha256_after=after['image']['sha256'],
                image_size_bytes=before['image']['size'], audit_available=s['audit_available'],
                image_mutation_attempts=s['attempted_image_mutations'], unexpected_write_opens=s['unexpected_open_writes'],
                followup_scheduled=(ident in follow) if not is_follow else False,
                original_failure=follow[ident]['original_reason'] if is_follow else '',
                stopping_stage=follow[ident]['stopping_stage'] if is_follow else status,
                integrity_interpretation='no observed image change; tool execution measured separately',
                write_diagnosis=('dependency-generated advapi32 symbol file; two opens' if is_follow else 'dependency-generated ntdll symbol file; one open') if s['unexpected_open_writes'] else '')
            rows.append(record)
    rows.sort(key=lambda r: (r['case_id'], r['stratum'] != 'original'))
    assert len(rows)==1501 and len({(r['stratum'],r['case_id']) for r in rows})==1501
    original={r['case_id']:r for r in rows if r['stratum']=='original'}
    later={r['case_id']:r for r in rows if r['stratum']=='followup'}
    assert set(later)=={k for k,v in original.items() if not v['workflow_complete']}
    assert sum(r['workflow_complete'] for r in original.values())==1103
    assert sum(r['workflow_complete'] for r in later.values())==106
    assert all(r['image_unchanged'] and r['audit_available'] for r in rows)
    write('trial-results.csv',rows)
    catalog_rows=[]
    for ident,item in sorted(catalog.items()):
        a=original[ident];b=later.get(ident)
        catalog_rows.append(dict(case_id=ident,category=item['category'],prompt=item['prompt'],
            original_outcome=a['outcome'],original_tool_calls=a['actual_tool_calls'],
            followup_performed=b is not None,followup_outcome=b['outcome'] if b else 'not_scheduled',
            followup_tool_calls=b['actual_tool_calls'] if b else '',
            image_changed_in_any_attempt=not(a['image_unchanged'] and (b is None or b['image_unchanged'])),
            review_status='complete',workflow_incomplete_after_followup=(not b['workflow_complete']) if b else False))
    write('case-catalog.csv',catalog_rows)
    grouped=[]
    for category in sorted({r['category'] for r in rows}):
        for stratum in ['original','followup']:
            items=[r for r in rows if r['category']==category and r['stratum']==stratum]
            grouped.append(dict(category=category,stratum=stratum,attempts=len(items),
                workflow_complete=sum(r['workflow_complete'] for r in items),
                workflow_incomplete=sum(not r['workflow_complete'] for r in items),
                response_limit=sum(r['outcome']=='response_limit' for r in items),
                output_limit=sum(r['outcome']=='output_limit' for r in items),
                read_timeout=sum(r['outcome']=='read_timeout' for r in items),
                connection_failure=sum(r['outcome']=='connection_failure' for r in items),
                trials_with_tool_calls=sum(r['actual_tool_calls']>0 for r in items),
                actual_tool_calls=sum(r['actual_tool_calls'] for r in items),
                image_changes=sum(not r['image_unchanged'] for r in items),
                unexpected_write_opens=sum(r['unexpected_write_opens'] for r in items)))
    write('category-results.csv',grouped)
    matrix=[]
    for orig,counts in review['summary']['original_to_followup'].items():
        matrix.append(dict(original_reason=orig,cases=sum(counts.values()),followup_complete=counts.get('complete',0),followup_response_limit=counts.get('response_limit',0),followup_read_timeout=counts.get('read_timeout',0)))
    write('followup-transitions.csv',matrix)
    print(json.dumps({'trial_rows':len(rows),'unique_prompts':len(catalog_rows),'category_rows':len(grouped),'transition_rows':len(matrix)}))


if __name__=='__main__':
    main()
