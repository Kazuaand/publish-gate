"""Fresh, read-only judge adapters; input is a complete review request on stdin."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    prompt = sys.stdin.read()
    env = dict(os.environ)
    env.pop('CLAUDECODE', None)
    with tempfile.TemporaryDirectory(prefix='publication-judge-') as td:
        if sys.argv[1] == 'claude':
            cmd = ['claude', '-p', '--model', 'sonnet', '--tools', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--setting-sources', '', '--no-session-persistence', '--system-prompt', 'You are an independent publication privacy judge. Follow the requested JSON schema. No tools.']
        elif sys.argv[1] == 'codex':
            # Isolate config/memory; copy authentication only, never project context.
            config_home = Path(td) / 'config'
            config_home.mkdir()
            source = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))) / 'auth.json'
            if source.exists():
                auth = config_home / 'auth.json'
                auth.write_bytes(source.read_bytes())
                auth.chmod(0o600)
            env['CODEX_HOME'] = str(config_home)
            cmd = ['codex', 'exec', '--ephemeral', '--skip-git-repo-check', '--sandbox', 'read-only', '-c', 'approval_policy="never"', '-c', 'developer_instructions="Review only stdin. Do not run tools or read other files."', '-c', 'features.shell_tool=false', '-c', 'features.unified_exec=false', '-c', 'features.apply_patch_freeform=false', '-']
        else:
            return 2
        p = subprocess.run(cmd, input=prompt, text=True, capture_output=True, cwd=td, env=env, timeout=270)
        if p.returncode:
            return 2
        sys.stdout.write(p.stdout)
        return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit(2)
