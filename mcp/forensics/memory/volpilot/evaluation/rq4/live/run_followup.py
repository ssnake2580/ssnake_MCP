"""One separately recorded follow-up per incomplete original ID; no silent retries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
from harness import ROOT, digest


def health(config, inference=False):
    body = {'model': config['model'], 'messages': [{'role': 'user', 'content': 'Reply OK.'}],
            'temperature': 0, 'max_tokens': 8} if inference else None
    headers = {'Content-Type': 'application/json'}
    key = os.environ.get(config.get('api_key_env', 'RQ4_MODEL_API_KEY'))
    if key:
        headers['Authorization'] = 'Bearer ' + key
    request = urllib.request.Request(config['base_url'].rstrip('/') +
        ('/chat/completions' if inference else '/models'),
        data=json.dumps(body).encode() if body else None, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    if inference and data['choices'][0].get('finish_reason') != 'stop':
        raise RuntimeError('Startup inference probe did not complete')


def main():
    freeze = json.loads((ROOT/'.local/followup-freeze.json').read_text())
    for name, expected in freeze['files'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError('Frozen follow-up input changed: ' + name)
    reviews = json.loads((ROOT/'incomplete-review.json').read_text())['cases']
    config = json.loads((ROOT/'.local/config.json').read_text())
    health(config, inference=True)
    node = shutil.which('node') or str(Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node')
    env = dict(os.environ, PROMPTFOO_CONFIG_DIR=str(ROOT/'.local/promptfoo-followup'),
               PROMPTFOO_DISABLE_TELEMETRY='1', PROMPTFOO_DISABLE_UPDATE='1', PROMPTFOO_CACHE_ENABLED='false')
    for review in reviews:
        records = [json.loads(p.read_text()) for p in (ROOT/'artifacts/followup').glob('*/summary.json')]
        ids = [r['case_id'] for r in records]
        if len(ids) != len(set(ids)):
            raise RuntimeError('Duplicate follow-up ID')
        if review['case_id'] in ids:
            continue
        health(config)
        original = ROOT/'artifacts/study'/review['original_run_id']/'events.jsonl'
        protocol = next(json.loads(line) for line in original.read_text().splitlines()
                        if json.loads(line)['event'] == 'protocol')
        case = dict(protocol['case'], track='B-followup', original_run_id=review['original_run_id'],
                    original_failure=review['reason'], followup_attempt=1)
        evaluation = {'providers': [{'id': 'file://'+str(ROOT/'followup_provider.cjs')}],
            'prompts': ['{{case_json}}'], 'tests': [{'description': case['id'],
            'vars': {'case_json': json.dumps(case, ensure_ascii=False), 'repeat': 1}}],
            'evaluateOptions': {'maxConcurrency': 1}}
        cfg = ROOT/'.local/promptfooconfig.followup.json'
        cfg.write_text(json.dumps(evaluation, ensure_ascii=False, indent=2))
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        output = ROOT/'artifacts'/f'followup-{case["id"]}-{stamp}.json'
        print(f'Starting {case["id"]}; recorded {len(records)}/199', flush=True)
        with output.with_suffix('.log').open('w') as log:
            subprocess.run([node, str(ROOT/'node_modules/promptfoo/dist/src/entrypoint.js'), 'eval',
                '-c', str(cfg), '--no-cache', '--no-share', '--no-table', '--max-concurrency', '1',
                '-o', str(output)], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        records = [json.loads(p.read_text()) for p in (ROOT/'artifacts/followup').glob('*/summary.json')]
        current = [r for r in records if r['case_id'] == case['id']]
        if len(current) != 1:
            raise RuntimeError('Missing or duplicate follow-up result')
        result = current[0]
        progress = {'recorded': len(records), 'planned': 199,
            'complete': sum(r['complete'] for r in records),
            'inconclusive': sum(not r['complete'] for r in records), 'last_case': case['id']}
        (ROOT/'.local/followup-progress.json').write_text(json.dumps(progress, indent=2))
        print(json.dumps(progress), flush=True)
        if result['image_unchanged'] is not True or result['outputs_preserved'] is not True or not result.get('audit_available') or result.get('attempted_image_mutations') or result.get('unexpected_open_writes'):
            raise RuntimeError('Follow-up observation anomaly; investigate before resuming')
        if not result['complete'] and not any(message in (result.get('error') or '') for message in
                ['Eight-round limit exhausted', 'Incomplete model output: length']):
            raise RuntimeError('Follow-up execution/transport error; investigate before resuming')
        fixture = Path(result['artifact_dir'])/'fixture'
        if fixture.exists() and fixture.parent.parent == ROOT/'artifacts/followup':
            shutil.rmtree(fixture)
    print('All follow-up IDs recorded; adjudicate remaining incompletes before paper revision.', flush=True)


if __name__ == '__main__':
    main()
