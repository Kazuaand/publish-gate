"""Export committed blobs without trusting archive attributes or working files."""
import subprocess
from pathlib import PurePosixPath


def export_head(tree, destination):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(tree), *args])
    head = git('rev-parse', '--verify', 'HEAD').decode().strip()
    prefix = git('rev-parse', '--show-prefix').decode().strip()
    listing = git('ls-tree', '-rz', '--full-tree', head)
    for entry in listing.split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, oid = header.split()
        name = name.decode('utf-8')
        if not name.startswith(prefix):
            continue
        relative = PurePosixPath(name[len(prefix):])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe-git-path')
        if any(part in {'node_modules', 'dist', '.git', '.venv', '__pycache__'} for part in relative.parts):
            continue
        if kind != b'blob' or mode not in {b'100644', b'100755'}:
            raise ValueError('unsupported-git-entry')
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(git('cat-file', 'blob', oid.decode()))
    return head
