"""Evaluation-only observer; logs Python file events without blocking operations."""
import json
import os
from pathlib import Path
import runpy
import sys
import time

sys.dont_write_bytecode = True
fd = os.open(os.environ['RQ4_AUDIT_LOG'], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
image = os.path.realpath(os.environ['VOL_IMAGE_PATH'])


def observe(event, args):
    if event == 'open':
        path, mode, flags = args
        if not isinstance(path, (str, bytes)):
            return
        path = os.fsdecode(path)
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if not writing and os.path.realpath(path) != image:
            return
        record = {'operation': 'open', 'path': path, 'resolved': os.path.realpath(path),
                  'write_intent': writing, 'mode': mode, 'flags': flags}
    elif event in {'os.remove', 'os.rename', 'os.rmdir', 'os.link', 'os.symlink', 'os.truncate'}:
        record = {'operation': event, 'arguments': [str(a) for a in args], 'write_intent': True}
    else:
        return
    record['time_ns'] = time.time_ns()
    os.write(fd, (json.dumps(record) + '\n').encode())


sys.addaudithook(observe)
if len(sys.argv) > 1 and sys.argv[1] == '--control':
    target = Path(image)
    action = sys.argv[2]
    if action == 'modify':
        target.write_bytes(b'modified')
    elif action == 'delete':
        target.unlink()
    elif action == 'rename':
        target.rename(target.with_suffix('.moved'))
    elif action == 'restore':
        original = target.read_bytes()
        target.write_bytes(b'temporary mutation')
        target.write_bytes(original)
else:
    project = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(project))
    runpy.run_path(str(project / 'mcp_server.py'), run_name='__main__')
