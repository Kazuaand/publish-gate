"""Fake positive controls are assembled at runtime, never live credentials."""
from pathlib import Path
import tempfile
import re
from publish_gate import analyzer_load, scan, deny_rules, external, digest, judges


def selftest():
    repeated = 'A' * 40
    samples = {
        'openai-project': 'sk-' + 'proj-' + repeated,
        'anthropic': 'sk-' + 'ant-' + repeated,
        'github-fine': 'github_' + 'pat_' + repeated,
        'github-classic': 'gh' + 'p_' + repeated,
        'telegram': ''.join(str(n) for n in range(1, 10)) + ':' + 'A' * 35,
        'bearer': 'Bear' + 'er ' + repeated,
        'url-credentials': 'https://' + 'demo:fake-value@' + 'example.invalid/',
        'bcrypt': '$2' + 'y$12$' + 'A' * 53,
        'aws-access': 'AK' + 'IA' + 'A' * 16,
        'basic': 'Ba' + 'sic ' + 'QUFBQUFBQUFB',
        'private-key': '-----BE' + 'GIN PRIVATE KEY-----',
        'slack': 'xo' + 'xb-' + repeated,
        'generic-key': 's' + 'k-' + repeated,
        'label-value': 'pass' + 'word:\nnot-a-real-credential',
        'capability-url': 'https://example.invalid/' + '?token=' + repeated,
        'private-ip': '.'.join(['192', '168', '20', '30']),
        'private-ipv6': ':'.join(['fd12', '', '1234']),
        'home-path': '/' + 'home/' + 'example/file',
        'email': 'example' + '@' + 'example.invalid',
        'phone': '-'.join(['202', '555', '0142']),
        'credential-html': '<input type=' + '"password">',
        'confi' + 'dential-name': 'do-' + 'not-share',
    }
    with tempfile.TemporaryDirectory(prefix='publication-selftest-') as td:
        root = Path(td)
        tree = root / 'tree'
        tree.mkdir()
        deny = root / 'deny'
        name = '架空' + '太郎'
        address = '架空県' + '架空市'
        deny.write_text('person\t' + name + '\naddress\t' + address + '\n')
        paths = ['~' + '/' + '.claude/' + 'references/rules/x.md',
                 '~' + '/' + '.claude/' + 'rules/ROUTING.md',
                 '/'.join(['', 'Users', 'someone', 'goals', 'x'])]
        with deny.open('a') as stream:
            for value in paths:
                stream.write('path\t' + re.escape(value) + '\t# generated fake control\n')
        rules = deny_rules(deny)
        (tree / 'paths.txt').write_text('\n'.join(paths))
        analyzer = analyzer_load()
        for rule, sample in samples.items():
            (tree / (rule + '.txt')).write_text('Fixture: ' + sample)
        (tree / 'html.txt').write_text('<p>pass<b>' + 'word</b>: <span>fake-value</span></p>')
        (tree / 'html-block.txt').write_text('<dt>Pass' + 'word</dt><dd>fake-value</dd>')
        (tree / 'prose.txt').write_text('The pass' + 'word is fake-value.')
        (tree / 'short.txt').write_text('pass' + 'word: xy')
        (tree / 'japanese.txt').write_text(name + '\n' + address)
        first, second, _ = scan(tree, rules, analyzer)
        for rule in samples:
            assert any(f['file'] == rule + '.txt' and f['rule_id'] == rule for f in first), rule
        assert any(f['file'] == 'html.txt' and f['rule_id'] == 'label-value' for f in first)
        for name in ('html-block.txt', 'prose.txt', 'short.txt'):
            assert any(f['file'] == name and f['rule_id'] == 'label-value' for f in first), name
        assert {f['line'] for f in second if f['file'] == 'japanese.txt'} == {1, 2}
        assert {f['line'] for f in second if f['file'] == 'paths.txt'} == {1, 2, 3}
        ext, versions = external(tree, root)
        assert not any(f['rule_id'].endswith('-error') for f in ext), 'external-tools'
        clean = root / 'clean'
        clean.mkdir()
        (clean / 'readme.txt').write_text('A small utility for checking text.\n')
        a, b, _ = scan(clean, rules, analyzer)
        c, _ = external(clean, root)
        assert not a and not b and not c, 'clean-fixture'
        h = digest(clean)
        (clean / 'readme.txt').write_text('Changed content.\n')
        assert digest(clean) != h
        bad, _ = judges({}, [], ['false', 'true'], root, root / 'bad.json')
        assert len(bad) == 2, 'fail-closed-judges'
    print('PASS: 13 key shapes; 9 additional patterns; HTML rerun; 2 Japanese and 3 three-field path denylist controls; clean stages 1-2; tree hash; judge failure controls')
    print('External tools: ' + str(versions))
    return 0
