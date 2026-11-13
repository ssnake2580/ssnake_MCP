"""Separate measurement and file-handler component controls; no original evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from harness import ROOT, PROJECT, snapshot, digest


def main():
    results={'measurement_controls':[],'component_tests':[]}
    with tempfile.TemporaryDirectory(prefix='rq4-controls-') as directory:
        base=Path(directory)
        for action in ['modify','delete','rename','restore']:
            d=base/action;d.mkdir();image=d/'control.raw';image.write_bytes(b'baseline bytes')
            before=snapshot(image)
            env=dict(os.environ,VOL_IMAGE_PATH=str(image),RQ4_AUDIT_LOG=str(d/'audit.jsonl'))
            subprocess.run(['uv','run','--no-sync','--offline','python',str(ROOT/'audit_server.py'),'--control',action],env=env,cwd=PROJECT,check=True)
            after=snapshot(image)
            logs=[json.loads(x) for x in (d/'audit.jsonl').read_text().splitlines()]
            detected=any(x.get('write_intent') for x in logs)
            byte_match=after.get('sha256')==before['sha256']
            assert detected and ((action=='restore' and byte_match) or (action!='restore' and before!=after))
            results['measurement_controls'].append({'action':action,'snapshot_changed':before!=after,'bytes_match':byte_match,'audit_detected':detected})
        os.environ['XDG_CACHE_HOME']=str(base/'cache')
        sys.path.insert(0,str(PROJECT))
        from plugins._file_handler import make_file_handler
        cases=[('traversal','../outside.txt'),('parent_traversal','../../evidence.raw'),
               ('absolute',str(base/'evidence.raw')),('nested','sub/file.bin'),
               ('nul','bad\0name'),('dotdot','..'),('windows_relative','..\\outside.txt'),
               ('windows_drive','C:\\evidence.raw'),('windows_unc','\\\\server\\share\\evidence.raw'),
               ('collision','existing.bin')]
        for ident,name in cases:
            d=base/ident;d.mkdir();out=d/'dumps';out.mkdir()
            existing=out/'existing.bin';existing.write_bytes(b'protected')
            outside=d/'outside.txt';outside.write_bytes(b'outside protected')
            image=base/'evidence.raw';image.write_bytes(b'evidence protected')
            before=[snapshot(p) for p in [existing,outside,image]]
            handler=make_file_handler(str(out));error=None
            try:
                h=handler(name);h.write(b'authorized derivative');h.close()
            except (ValueError,TypeError,OSError) as exc:error=type(exc).__name__
            after=[snapshot(p) for p in [existing,outside,image]]
            unchanged=before==after
            assert unchanged
            created=[p.name for p in out.iterdir() if p!=existing]
            if ident=='collision':assert created==['existing-1.bin']
            results['component_tests'].append({'id':ident,'error_type':error,'protected_unchanged':unchanged,'created_files':created})
    (ROOT/'.local/control-results.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
