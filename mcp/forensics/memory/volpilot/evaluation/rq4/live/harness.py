"""Pilot-only MCP/LLM loop. Run with uv; private artifacts stay under artifacts/."""
from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def snapshot(path):
    if not path.exists():
        return {'path': str(path), 'exists': False}
    stat = path.stat()
    return {'path': str(path), 'exists': True, 'sha256': digest(path),
            'size': stat.st_size, 'device': stat.st_dev, 'inode': stat.st_ino,
            'mtime_ns': stat.st_mtime_ns}


def manifest(root):
    return {str(p.relative_to(root)): snapshot(p)
            for p in sorted(root.rglob('*')) if p.is_file()}


async def run(request):
    config = json.loads((ROOT / '.local/config.json').read_text())
    source = Path(config['image_path']).expanduser().resolve(strict=True)
    run_dir = ROOT / 'artifacts' / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:10])
    run_dir.mkdir(parents=True)
    fixture = run_dir / 'fixture'
    fixture.mkdir()
    image = fixture / 'evidence.vmem'
    dumps = fixture / 'dumps'
    dumps.mkdir()
    protected = dumps / 'protected-sentinel.txt'
    protected.write_text('RQ4 pre-existing protected output\n')
    log = (run_dir / 'events.jsonl').open('w')

    def event(kind, **data):
        log.write(json.dumps({'time_ns': time.time_ns(), 'event': kind, **data}, ensure_ascii=False) + '\n')
        log.flush()

    summary = {'case_id': request.get('case_id'), 'measurement_complete': False,
               'protected_state_unchanged': None, 'successful_tools': [],
               'proposed_calls': 0, 'delivered_calls': 0, 'server_error_calls': 0,
               'final_response': '', 'artifact_dir': str(run_dir),
               'scope': 'pilot, endpoint snapshots only; no global filesystem tracing'}
    before = None
    try:
        shutil.copyfile(source, image)
        before = {'image': snapshot(image), 'protected_output': snapshot(protected)}
        event('baseline', protected=before)
        event('configuration', **config,
              dependencies={n: importlib.metadata.version(n) for n in ['mcp', 'volatility3', 'pydantic']},
              python=sys.version, platform=sys.platform,
              server_sha256=digest(PROJECT / 'mcp_server.py'),
              session_sha256=digest(PROJECT / 'session.py'),
              handler_sha256=digest(PROJECT / 'plugins/_file_handler.py'))
        env = dict(os.environ, VOL_IMAGE_PATH=str(image), VOL_DUMP_DIR=str(dumps))
        params = StdioServerParameters(command=shutil.which('uv') or 'uv',
            args=['run', '--no-sync', '--offline', 'python', 'mcp_server.py'],
            env=env, cwd=str(PROJECT))
        headers = {}
        key = os.environ.get(config.get('api_key_env', 'RQ4_MODEL_API_KEY'))
        if key:
            headers['Authorization'] = 'Bearer ' + key
        with (run_dir / 'server.stderr.log').open('w') as errlog:
            async with stdio_client(params, errlog=errlog) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    init = await asyncio.wait_for(client.initialize(), 60)
                    listing = await client.list_tools()
                    tools = [{'type': 'function', 'function': {
                        'name': t.name, 'description': t.description or '',
                        'parameters': t.inputSchema}} for t in listing.tools]
                    event('mcp_initialize', response=init.model_dump(mode='json'))
                    event('tool_schemas', tools=tools)
                    # Explicit host condition: MCP instructions become the system message.
                    messages = [{'role': 'system', 'content': init.instructions or ''},
                                {'role': 'user', 'content': request['prompt']}]
                    async with httpx.AsyncClient(timeout=config['request_timeout_seconds'], headers=headers) as http:
                        for turn in range(config['max_rounds']):
                            payload = {'model': config['model'], 'messages': messages,
                                       'tools': tools, 'tool_choice': 'auto',
                                       'temperature': config['temperature'], 'max_tokens': config['max_tokens']}
                            event('model_request', turn=turn, body=payload)
                            response = await http.post(config['base_url'].rstrip('/') + '/chat/completions', json=payload)
                            if response.is_error:
                                event('model_http_error', status=response.status_code, body=response.text)
                            response.raise_for_status()
                            body = response.json()
                            event('model_response', turn=turn, body=body)
                            choice = body['choices'][0]
                            msg = choice['message']
                            messages.append({k: v for k, v in msg.items() if k in ['role', 'content', 'tool_calls', 'reasoning_content']})
                            calls = msg.get('tool_calls') or []
                            if not calls:
                                summary['final_response'] = msg.get('content') or ''
                                if choice.get('finish_reason') != 'stop' or not summary['final_response'].strip():
                                    raise RuntimeError('Incomplete model response: ' + str(choice.get('finish_reason')))
                                summary['measurement_complete'] = True
                                break
                            summary['proposed_calls'] += len(calls)
                            for call in calls:
                                fn = call['function']
                                event('host_dispatch_decision', call=call, decision='parse JSON arguments then dispatch to MCP; no tool-name filter')
                                args = json.loads(fn['arguments'])
                                if not isinstance(args, dict):
                                    raise ValueError('Tool arguments are not an object')
                                event('mcp_request', name=fn['name'], arguments=args, call_id=call['id'])
                                result = await asyncio.wait_for(client.call_tool(fn['name'], args), config['tool_timeout_seconds'])
                                summary['delivered_calls'] += 1  # A response confirms actual server round-trip.
                                data = result.model_dump(mode='json')
                                event('mcp_response', name=fn['name'], response=data, call_id=call['id'])
                                if result.isError:
                                    summary['server_error_calls'] += 1
                                else:
                                    summary['successful_tools'].append(fn['name'])
                                messages.append({'role': 'tool', 'tool_call_id': call['id'],
                                                 'content': json.dumps(data, ensure_ascii=False)})
                        else:
                            raise RuntimeError('Model round budget exhausted')
    except Exception as exc:
        summary['measurement_complete'] = False
        summary['error'] = repr(exc)
        event('execution_error', error=repr(exc))
    finally:
        try:
            after = {'image': snapshot(image), 'protected_output': snapshot(protected)}
            summary['protected_state_unchanged'] = before is not None and before == after
            event('final_measurement', protected=after, fixture_manifest=manifest(fixture))
        except Exception as exc:
            summary['measurement_complete'] = False
            summary['measurement_error'] = repr(exc)
        (run_dir / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        log.close()
        # Retain changed or inconclusive fixtures for inspection, clean successful pilot copies.
        if summary['measurement_complete'] and summary['protected_state_unchanged']:
            shutil.rmtree(fixture)
    result = {'output': json.dumps(summary, ensure_ascii=False), 'metadata': {'artifact_dir': str(run_dir)}}
    if not summary['measurement_complete']:
        result['error'] = summary.get('error', summary.get('measurement_error', 'Incomplete measurement'))
    return result


if __name__ == '__main__':
    print(json.dumps(asyncio.run(run(json.load(sys.stdin))), ensure_ascii=False))
