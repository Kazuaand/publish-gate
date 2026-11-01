"""Fresh, read-only judge adapters; input is a complete review request on stdin."""
import base64
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from collections import deque
from diagnostics import redact, diagnostic
from image_support import frames, MAX_BYTES


def run_cli(cmd, *, input, cwd, env, timeout, **unused):
    """Stream masked stderr so an outer deadline cannot discard diagnostics."""
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, cwd=cwd, env=env) as process:
        tail = deque(maxlen=20)
        stderr_pipe = process.stderr
        def forward():
            for line in stderr_pipe:
                tail.append(line)
                sys.stderr.write(redact(line) + '\n')
                if diagnostic(subprocess.CompletedProcess([], 0, '', line), None, '', 0)['failure_class'] == 'usage-limit':
                    sys.stderr.write('usage-limit\n')
                sys.stderr.flush()
        reader = threading.Thread(target=forward, daemon=True)
        reader.start()
        # communicate must not consume stderr concurrently with the forwarding thread.
        stderr_pipe = process.stderr
        process.stderr = None
        try:
            stdout, _ = process.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            reader.join(timeout=1)
            raise subprocess.TimeoutExpired(cmd, timeout, stderr=''.join(tail))
        finally:
            process.stderr = stderr_pipe
        reader.join()
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, ''.join(tail))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('judge', choices=['claude', 'codex'])
    parser.add_argument('--image', action='append', default=[])
    args = parser.parse_args()
    prompt = sys.stdin.read()
    env = dict(os.environ)
    env.pop('CLAUDECODE', None)
    with tempfile.TemporaryDirectory(prefix='publication-judge-') as td:
        attachments = []
        for number, path in enumerate(args.image):
            data = Path(path).read_bytes()
            if len(data) > MAX_BYTES:
                return 2
            for index, frame in enumerate(frames(data)):
                target = Path(td) / f'image-{number}-frame-{index}.png'
                frame.save(target, format='PNG')
                attachments.append((f"image_items[{number}]", index, target))
        if args.judge == 'claude':
            cmd = ['claude', '-p', '--model', 'sonnet', '--tools', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--safe-mode', '--no-session-persistence', '--system-prompt', 'You are an independent publication privacy judge. Follow the requested JSON schema. No tools.']
            if attachments:
                cmd += ['--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose']
                content = [{'type': 'text', 'text': prompt}]
                for name, index, path in attachments:
                    content += [{'type': 'text', 'text': f'Image {name}, frame {index}'}, {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/png', 'data': base64.b64encode(path.read_bytes()).decode()}}]
                prompt = json.dumps({'type': 'user', 'message': {'role': 'user', 'content': content}}) + '\n'
        elif args.judge == 'codex':
            # Isolate config/memory; copy authentication only, never project context.
            config_home = Path(td) / 'config'
            config_home.mkdir()
            source = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))) / 'auth.json'
            if source.exists():
                auth = config_home / 'auth.json'
                auth.write_bytes(source.read_bytes())
                auth.chmod(0o600)
            env['CODEX_HOME'] = str(config_home)
            cmd = ['codex', 'exec', '--ephemeral', '--skip-git-repo-check', '--sandbox', 'read-only', '-c', 'approval_policy="never"', '-c', 'developer_instructions="Review stdin and attached images. Do not run tools or read other files."', '-c', 'features.shell_tool=false', '-c', 'features.unified_exec=false', '-c', 'features.apply_patch_freeform=false', '-']
            for name, index, path in attachments:
                cmd[-1:-1] = ['--image', str(path)]
            if attachments:
                prompt += '\nAttachment order: ' + json.dumps([(name, index) for name, index, _ in attachments])
        else:
            return 2
        p = run_cli(cmd, input=prompt, text=True, capture_output=True, cwd=td, env=env, timeout=float(os.environ.get('PUBLISH_GATE_JUDGE_TIMEOUT', '600')) * 0.8)
        sys.stderr.write(redact(getattr(p, 'stderr', '')))
        failure = diagnostic(p, None, 'non-zero exit', 0)['failure_class']
        if failure == 'usage-limit':
            sys.stderr.write('\nusage-limit\n')
        if p.returncode:
            sys.stderr.write(redact(p.stdout))
            return p.returncode
        output = p.stdout
        if args.judge == 'claude' and attachments:
            results = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
            results = [item for item in results if item.get('type') == 'result']
            if len(results) != 1 or results[0].get('is_error'):
                sys.stderr.write('\njudge-schema-mismatch\n' + redact(p.stdout))
                return 2
            output = results[0]['result']
        sys.stdout.write(output)
        return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired as error:
        sys.stderr.write('judge-timeout\n' + redact(error.stderr))
        sys.exit(2)
    except json.JSONDecodeError:
        sys.stderr.write('judge-json-parse')
        sys.exit(2)
    except (KeyError, TypeError):
        sys.stderr.write('judge-schema-mismatch')
        sys.exit(2)
    except Exception as error:
        sys.stderr.write(type(error).__name__)
        sys.exit(2)
