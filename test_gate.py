"""Control-flow regression tests; selftest exercises installed detectors separately."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import publish_gate as gate


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree = self.root / 'tree'
        self.tree.mkdir()
        self.source = self.tree / 'guide.txt'
        self.source.write_text('Clean text.')
        self.deny = self.root / 'deny'
        self.deny.write_text('person\tForbiddenExample\n')
        self.args = argparse.Namespace(tree=str(self.tree), denylist=str(self.deny), out=str(self.root / 'result.json'), judge_cmd=['review-one', 'review-two'], max_rounds=2, fix_cmd='repair')

    def test_deny_formats(self):
        self.deny.write_text('# person\nAlpha\ncompany\tBeta\npath\tGamma\t# fake note\n')
        rules = gate.deny_rules(self.deny)
        self.assertEqual([r[1] for r in rules], ['person', 'company', 'path'])
        for rule, value in zip(rules, ['Alpha', 'Beta', 'Gamma']):
            self.assertIsNotNone(rule[2].search(value))

    def test_review_gate(self):
        item = type('Entity', (), {'entity_type': 'PERSON', 'start': 0, 'end': 5})()
        analyzer = type('Analyzer', (), {'analyze': lambda *a, **k: [item]})()
        for verdicts, expected in [(['PASS', None], 'FAIL'), (['PASS', 'FAIL'], 'FAIL'), (['PASS', 'PASS'], 'PASS')]:
            def respond(argv, cwd, stdin=None, **kwargs):
                payload = json.loads(stdin.split('\n')[-1])
                verdict = verdicts[0 if argv[0] == 'review-one' else 1]
                items = [] if verdict is None else [
                    {'id': i['id'], 'verdict': verdict, 'reason': 'False positive in generic prose.'}
                    for i in payload['review_items']]
                return type('Response', (), {'returncode': 0, 'stdout': json.dumps(
                    {'verdict': 'PASS', 'findings': [], 'review_items': items})})()
            with patch.object(gate, 'analyzer_load', return_value=analyzer), patch.object(gate, 'external', return_value=([], {})), patch.object(gate, 'run', side_effect=respond):
                evidence, _ = gate.check(self.args)
            self.assertTrue(evidence['review_items'])
            self.assertEqual(evidence['stages']['4']['result'], expected)

    def test_presidio_classes(self):
        kinds = sorted(gate.PRESIDIO_DROP | gate.PRESIDIO_REVIEW | {'EMAIL_ADDRESS', 'FUTURE_IDENTIFIER'})
        entities = [type('Entity', (), {'entity_type': kind, 'start': 0, 'end': 5})() for kind in kinds]
        analyzer = type('Analyzer', (), {'analyze': lambda *a, **k: entities})()
        reviews = []
        hard, _, _ = gate.scan(self.tree, gate.deny_rules(self.deny), analyzer, reviews)
        self.assertEqual({x['rule_id'] for x in hard}, {'presidio-email_address', 'presidio-future_identifier'})
        self.assertEqual({x['entity'] for x in reviews}, gate.PRESIDIO_REVIEW)
        self.assertEqual([x['id'] for x in reviews], list(range(1, len(reviews) + 1)))

    def test_review_id_mismatch(self):
        evidence = [{'id': 1, 'file': 'guide.txt', 'line': 1, 'entity': 'PERSON', 'text': 'Clean'}]
        for ids in ([1, 1], [1, 2], [2], [True]):
            response = {'verdict': 'PASS', 'findings': [], 'review_items': [
                {'id': n, 'verdict': 'PASS', 'reason': 'False positive.'} for n in ids]}
            result = type('Response', (), {'returncode': 0, 'stdout': json.dumps(response)})()
            with patch.object(gate, 'run', return_value=result):
                findings, _ = gate.judges({'guide.txt': 'Clean'}, [], self.args.judge_cmd, self.root, self.root / 'j.json', evidence)
            self.assertTrue(findings)

    def test_repeated_review_spans(self):
        self.source.write_text('Example Person; author: Example Person.')
        def analyze(*args, **kwargs):
            import re
            return [type('Entity', (), {'entity_type': 'PERSON', 'start': m.start(), 'end': m.end()})()
                    for m in re.finditer('Example Person', kwargs['text'])]
        analyzer = type('Analyzer', (), {'analyze': analyze})()
        reviews = []
        gate.scan(self.tree, gate.deny_rules(self.deny), analyzer, reviews)
        self.assertEqual(len(reviews), 2)
        self.assertEqual([x['id'] for x in reviews], [1, 2])

    def test_output_collision(self):
        self.args.out = str(self.deny)
        before = self.deny.read_bytes()
        with self.assertRaises(ValueError):
            gate.check(self.args)
        self.assertEqual(before, self.deny.read_bytes())
        linked = self.root / 'hardlink.json'
        os.link(self.deny, linked)
        self.args.out = str(linked)
        with self.assertRaises(ValueError):
            gate.check(self.args)
        self.deny.rename(self.root / 'result.judge-1.json')
        self.args.denylist = str(self.root / 'result.judge-1.json')
        self.args.out = str(self.root / 'result.json')
        with self.assertRaises(ValueError):
            gate.check(self.args)

    def test_nested_runtime_directory_scanned(self):
        path = self.tree / 'nested' / '.venv'
        path.mkdir(parents=True)
        (path / 'value.txt').write_text('ForbiddenExample')
        _, second, _ = gate.scan(self.tree, gate.deny_rules(self.deny))
        self.assertEqual(gate.stage(second)["count"], 1)

    def test_judge_invalid_and_value_not_persisted(self):
        response = type('Response', (), {'returncode': 0, 'stdout': '{"verdict":"FAIL","findings":[{"file":"guide.txt","line":1,"reason":"do-not-persist-this-value"}]}'})()
        with patch.object(gate, 'run', return_value=response):
            findings, paths = gate.judges({'guide.txt':'Clean text.'}, [], self.args.judge_cmd, self.root, self.root / 'result.json')
        self.assertEqual(len(findings), 2)
        for path in paths:
            self.assertNotIn('do-not-persist', Path(path).read_text())

    @patch.object(gate, 'judges', return_value=([], []))
    @patch.object(gate, 'external', return_value=([], {'mock': 'test'}))
    @patch.object(gate, 'analyzer_load', return_value=None)
    def test_loop_repair_and_limit(self, *_):
        self.source.write_text('ForbiddenExample')
        def repair(*args, **kwargs):
            self.source.write_text('Clean text.')
            return type('Response', (), {'returncode': 0})()
        with patch.object(gate, 'run', side_effect=repair):
            self.assertEqual(gate.loop(self.args), 0)
        self.source.write_text('ForbiddenExample')
        self.args.max_rounds = 1
        with patch.object(gate, 'run') as command:
            self.assertEqual(gate.loop(self.args), 1)
            command.assert_not_called()

    @patch.object(gate, 'judges', return_value=([], []))
    @patch.object(gate, 'external', return_value=([], {}))
    @patch.object(gate, 'analyzer_load', return_value=None)
    def test_fail_on_tree_mutation(self, *_):
        def mutate(*args):
            self.source.write_text('Changed')
            return [], []
        with patch.object(gate, 'judges', side_effect=mutate):
            evidence, _ = gate.check(self.args)
        self.assertEqual(evidence['result'], 'FAIL')
        self.assertIn('tree-changed', [x['rule_id'] for x in evidence['stages']['4']['findings']])

if __name__ == '__main__':
    unittest.main()
