"""Built-in detector expressions and denylist category names."""
PREFIX = r'(?<![A-Za-z0-9_-])'
PATTERNS = {
    'openai-project': PREFIX + r'sk-proj-[A-Za-z0-9_-]{16,}',
    'anthropic': PREFIX + r'sk-ant-[A-Za-z0-9_-]{16,}',
    'github-fine': PREFIX + r'github_pat_[A-Za-z0-9_]{16,}',
    'github-classic': PREFIX + r'gh[pousr]_[A-Za-z0-9]{20,}',
    'telegram': r'\b\d{8,12}:[A-Za-z0-9_-]{35}\b',
    'bearer': r'\bBearer\s+[A-Za-z0-9._~+/=-]{8,}',
    'url-credentials': r'https?://[^\s/:<>]+:[^\s/@<>]+@',
    'bcrypt': r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}',
    'aws-access': r'\bAKIA[A-Z0-9]{16}\b',
    'basic': r'\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}',
    'private-key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'slack': PREFIX + r'xox[baprs]-[A-Za-z0-9-]{12,}',
    'generic-key': PREFIX + r'sk-(?!proj-|ant-)[A-Za-z0-9_-]{20,}',
    'label-value': r'(?i)(?:password|passwd|api[_ -]?key|access[_ -]?token|client[_ -]?secret|パスワード|認証情報|ユーザー名)\s*(?:[:=：]|\n|\bis\b|\bare\b)\s*[^\s<>]+',
    'label-value-gap': r'(?i)\b(?:password|passwd|token|api[_ -]?key|access[_ -]?token|client[_ -]?secret)\s+for\s+[^\r\n:;=]{1,80}?\s*(?:[:=]|\bis\b)\s*[^\s<>]+',
    'capability-url': r'https?://[^\s<>"\']+(?:[?&#](?:token|key|secret|signature|sig|invite|auth)=|/(?:invite|join|reset-password)/)[^\s<>"\']+',
    'private-ip': r'(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2})(?![\d.])',
    'private-ipv6': r'(?i)(?<!\w)(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]+',
    'home-path': r'(?:/(?:Users|home)/[^\s/<>]+|[A-Z]:\\Users\\[^\s\\]+|~' + r'/[^\s<>]+)',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'phone': r'(?<!\w)(?:\+\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -])\d{2,4}[ -]\d{3,4}(?!\w)',
    'credential-html': r'(?i)(?:type\s*=\s*["\']password|class\s*=\s*["\'][^"\']*\bcred(?:ential)?s?\b)',
    'confi' + 'dential-name': r'(?i)(?:confi' + r'dential|do.not' + r'.share|社外共有' + r'厳禁)',
}
CATEGORIES = {'real-name', 'company', 'client', 'handle', 'tool', 'person', 'address', 'organization', 'account', 'host', 'path', 'email', 'phone', 'secret', 'internal', 'other'}

