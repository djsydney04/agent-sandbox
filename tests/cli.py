"""CLI regressions using a disposable Docker protocol double, not a live engine."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BINARY = Path(__file__).resolve().parent.parent / 'target/debug/sandbox'


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'config').mkdir()
        (self.root / 'workspace').mkdir()
        (self.root / 'config/network.json').write_text(json.dumps({
            'allow': ['api.openai.com'], 'deny': [], 'ports': [443], 'private_allow': []}))
        (self.root / 'config/codex.toml').write_text('')
        fingerprint = subprocess.check_output([
            str(BINARY), '--root', str(self.root), 'allow', 'fingerprint'], text=True).strip()
        self.env = dict(os.environ, TEST_ROOT=str(self.root), TEST_FINGERPRINT=fingerprint)
        mock = self.root / 'docker'
        mock.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
a = sys.argv[1:]
with (root / 'calls').open('a') as f:
    f.write(json.dumps(a) + '\\n')
if 'config' in a:
    print(json.dumps({'services': {'agent': {
        'network_mode': 'service:gateway', 'cap_drop': ['ALL'], 'user': '0:0',
        'security_opt': ['no-new-privileges:true'],
        'volumes': [{'type': 'bind', 'source': str(root / 'workspace'), 'target': '/workspace'}]
    }}}))
elif 'cat' in a:
    print(os.environ['TEST_FINGERPRINT'] if (root / 'restarted').exists() else 'old')
elif 'restart' in a:
    (root / 'restarted').touch()
    print('Compose restart progress')
elif 'up' in a:
    print('Compose startup progress')
elif 'ps' in a and '-q' in a:
    print('gateway-id' if os.environ.get('TEST_RUNNING', '1') == '1' else '')
elif 'run' in a:
    print('{"type":"thread.started"}')
''')
        mock.chmod(0o755)
        self.env['SANDBOX_DOCKER'] = str(mock)

    def run_cli(self, *args):
        return subprocess.run([str(BINARY), '--root', str(self.root), *args],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]

    def test_policy_reload_preserves_json_stdout(self):
        result = self.run_cli('run', '--json', 'test')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                         [{'type': 'thread.started'}])
        self.assertIn('Applying policy', result.stderr)
        self.assertTrue((self.root / 'restarted').exists())

    def test_doctor_never_mutates_running_or_stopped_runtime(self):
        for running in ('1', '0'):
            with self.subTest(running=running):
                self.env['TEST_RUNNING'] = running
                result = self.run_cli('doctor')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('pending' if running == '1' else 'stopped', result.stdout)
                for call in self.calls():
                    self.assertFalse(set(call) & {'up', 'restart', 'run', 'build', 'down'})

    def test_policy_directory_symlink_into_workspace_is_rejected(self):
        (self.root / 'config').rename(self.root / 'workspace/policy')
        (self.root / 'config').symlink_to(self.root / 'workspace/policy', target_is_directory=True)
        self.assert_workspace_rejected()

    def test_policy_file_symlink_into_workspace_is_rejected(self):
        policy = self.root / 'config/network.json'
        policy.rename(self.root / 'workspace/network.json')
        policy.symlink_to(self.root / 'workspace/network.json')
        self.assert_workspace_rejected()

    def assert_workspace_rejected(self):
        result = self.run_cli('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('policy files', result.stderr)
        self.assertFalse(any('up' in call or 'run' in call for call in self.calls()))


if __name__ == '__main__':
    unittest.main()
