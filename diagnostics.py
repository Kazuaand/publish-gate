"""Conservative diagnostic redaction, never persisted raw process output."""
import re
import subprocess
from detector_patterns import PATTERNS


def redact(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    text = str(value or '')
    for pattern in PATTERNS.values():
        text = re.sub(pattern, '[REDACTED]', text)
    text = re.sub(r'(?i)(?:authorization|token|secret|password|key)\s*[:=]\s*\S+', '[REDACTED]', text)
    text = re.sub(r'[A-Za-z0-9_+/=.-]{20,}', '[REDACTED]', text)
    return '\n'.join(text.splitlines()[-20:])[-4000:]


def diagnostic(process, error, failure_class, elapsed):
    stderr = getattr(process, 'stderr', '') or getattr(error, 'stderr', '') or ''
    stdout = getattr(process, 'stdout', '') or getattr(error, 'stdout', '') or ''
    combined = str(stderr) + str(stdout)
    if isinstance(error, subprocess.TimeoutExpired) or 'judge-timeout' in combined:
        failure_class = 'timeout'
    elif re.search(r'(?i)(usage.?limit|rate.?limit|limit.{0,40}(reached|exceeded)|hit.{0,20}limit|quota.{0,30}(exhaust|exceed))', combined):
        failure_class = 'usage-limit'
    elif 'judge-json-parse' in combined:
        failure_class = 'JSON parse'
    elif 'judge-schema-mismatch' in combined:
        failure_class = 'schema mismatch'
    return {'exit_code': getattr(process, 'returncode', None), 'failure_class': failure_class,
            'elapsed_seconds': round(elapsed, 3), 'stderr_tail': redact(stderr)}
