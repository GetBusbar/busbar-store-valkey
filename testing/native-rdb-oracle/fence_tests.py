#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Targeted live native fence/capture witnesses; only disposable sources."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--exporter', type=Path, required=True)
parser.add_argument('--module', type=Path, required=True)
parser.add_argument('--scratch-root', type=Path, required=True)
parser.add_argument('--peer', type=Path, required=True)
parser.add_argument('--cli', type=Path, default=Path('/opt/homebrew/bin/valkey-cli'))
options = parser.parse_args()
sys.argv = [__file__, '--module', str(options.module), '--scratch-root', str(options.scratch_root)]
import tests as native

PASSWORD = 'probe-fixture-only'
OWNER = list(b'legacy.valkey.v1')
PERMISSIONS = ['-@all', '+get', '+info', '+role', '+acl|users', '+acl|getuser', '+client|list',
               '+client|setinfo', '+select', '+hello', '+ping', '+sync', '+replconf', '+module|list']


def connection(directory):
    return {'socket': str(directory / 'writer.sock'), 'database': 0, 'username': 'inspector',
            'password': PASSWORD, 'timeout_ms': 15000,
            'cli': {'path': str(options.cli), 'sha256': list(hashlib.sha256(options.cli.read_bytes()).digest())},
            'peer': {'path': str(options.peer), 'sha256': list(hashlib.sha256(options.peer.read_bytes()).digest())}}


def setup(admin, old_on=False):
    native.send(admin, 'SET', 'busbar:schema', '9')
    native.send(admin, 'SET', 'busbar:captured', 'native-source-value')
    native.send(admin, 'ACL', 'SETUSER', 'old', 'on' if old_on else 'off', '>old-fixture-only', '~*', '+@all')
    native.send(admin, 'ACL', 'SETUSER', 'inspector', 'on', '>' + PASSWORD, '~*', *PERMISSIONS)
    native.send(admin, 'ACL', 'SETUSER', 'default', 'off')


def invoke(mode, envelope, *args):
    return subprocess.run([str(options.exporter), mode, *map(str, args)],
                          input=json.dumps(envelope).encode(), capture_output=True, timeout=25)


def probe(anchor, archive=None):
    return {'version': 1, 'source_owner': OWNER, 'source_physical': 9,
            'archive_sha256': archive or [1] * 32, 'native_anchor_sha256': anchor,
            'old_writers': ['old'], 'sender_attestation_sha256': [2] * 32,
            'backend_attestation_sha256': [3] * 32, 'challenge': [4] * 32}


class LiveFenceWitnesses(unittest.TestCase):
    def test_readonly_probe_passes_and_enabled_old_writer_refuses(self):
        for old_on in (False, True):
            with self.subTest(old_on=old_on), tempfile.TemporaryDirectory(prefix='fence-users-', dir=options.scratch_root) as work:
                directory = Path(work)
                with native.fixture(directory) as admin:
                    setup(admin, old_on)
                    admin.close()
                    config = connection(directory)
                    observed = invoke('--inspect-source', {'connection': config, 'old_writers': ['old']})
                    if old_on:
                        self.assertNotEqual(observed.returncode, 0)
                        self.assertEqual(observed.stdout, b'')
                    else:
                        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
                        identity = json.loads(observed.stdout)
                        verified = invoke('--verify-fence', {'connection': config, 'probe': probe(identity['native_anchor_sha256'])})
                        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
                        reply = json.loads(verified.stdout)
                        self.assertEqual(reply['native_anchor_sha256'], identity['native_anchor_sha256'])
                        self.assertEqual(reply['enforcement_policy_sha256'], identity['enforcement_policy_sha256'])

    def test_authenticated_queued_old_transaction_refuses(self):
        with tempfile.TemporaryDirectory(prefix='fence-queued-', dir=options.scratch_root) as work:
            directory = Path(work)
            with native.fixture(directory) as admin:
                setup(admin, True)
                with socket.socket(socket.AF_UNIX) as old:
                    old.settimeout(5)
                    old.connect(str(directory / 'writer.sock'))
                    native.send(old, 'AUTH', 'old', 'old-fixture-only')
                    native.send(old, 'MULTI')
                    native.send(old, 'SET', 'busbar:queued', 'must-not-run')
                    native.send(admin, 'ACL', 'SETUSER', 'old', 'off')
                    admin.close()
                    observed = invoke('--inspect-source', {'connection': connection(directory), 'old_writers': ['old']})
                    self.assertNotEqual(observed.returncode, 0)
                    self.assertEqual(observed.stdout, b'')

    def test_official_capture_binds_origin_and_fresh_recheck(self):
        with tempfile.TemporaryDirectory(prefix='fence-capture-', dir=options.scratch_root) as work:
            directory = Path(work)
            with native.fixture(directory) as admin:
                setup(admin)
                admin.close()
                config = connection(directory)
                captured = invoke('--capture-live', {'connection': config, 'old_writers': ['old']},
                                  '--source-output', directory / 'captured.rdb', '--schema', 9,
                                  '--output', directory / 'captured.archive', '--scratch-root', options.scratch_root,
                                  '--supervisor', Path(__file__).parent / 'extract.py', '--module', options.module,
                                  '--server', native.options.server, '--max-source-bytes', 1048576,
                                  '--max-native-bytes', 1048576, '--archive-bytes', 1048576,
                                  '--max-rows', 100, '--index-bytes', 65536, '--deadline', 15)
                self.assertEqual(captured.returncode, 0, captured.stderr.decode())
                report = json.loads(captured.stdout)
                self.assertFalse(report['snapshot_only'])
                anchor = list(bytes.fromhex(report['native_anchor_sha256']))
                verified = invoke('--verify-fence', {'connection': config,
                                  'probe': probe(anchor, list(bytes.fromhex(report['archive_sha256'])))})
                self.assertEqual(verified.returncode, 0, verified.stderr.decode())
                self.assertEqual(hashlib.sha256((directory / 'captured.rdb').read_bytes()).hexdigest(), report['source_rdb_sha256'])


if __name__ == '__main__':
    unittest.main(argv=[__file__])
