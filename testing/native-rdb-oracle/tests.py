#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Two targeted witnesses against the actual official engine and exporter.

These are newly generated native 9.1.3 physical-format fixtures, never alleged
published busbar release fixtures. Existing signed source fixtures are untouched.
"""
import argparse
from contextlib import contextmanager
from pathlib import Path
import socket
import os
import struct
import subprocess
import tempfile
import time
import unittest

import extract

parser = argparse.ArgumentParser()
parser.add_argument('--module', type=Path, required=True)
parser.add_argument('--server', default='/opt/homebrew/bin/valkey-server')
parser.add_argument('--retain-source', type=Path)
parser.add_argument('--scratch-root', type=Path, required=True)
options, extra = parser.parse_known_args()
options.scratch_root.mkdir(parents=True, exist_ok=True)


def send(connection, *args):
    encoded = [a if isinstance(a, bytes) else str(a).encode() for a in args]
    connection.sendall(f'*{len(args)}\r\n'.encode() + b''.join(
        f'${len(a)}\r\n'.encode() + a + b'\r\n' for a in encoded))
    def reply():
        line = bytearray()
        while not line.endswith(b'\r\n'):
            part = connection.recv(1)
            if not part:
                raise RuntimeError('fixture engine disconnected')
            line.extend(part)
        if line[:1] == b'*':
            return [reply() for _ in range(int(line[1:-2]))]
        if line[:1] not in (b'+', b':'):
            raise RuntimeError('fixture command refused')
        return line
    return reply()


@contextmanager
def fixture(directory):
    sock = directory / 'writer.sock'
    args = [options.server, '--port', '0', '--unixsocket', str(sock), '--unixsocketperm', '700',
            '--dir', str(directory), '--dbfilename', 'source.rdb', '--save', '', '--appendonly', 'no',
            '--daemonize', 'no', '--logfile', str(directory / 'writer.log'), '--hide-user-data-from-log', 'yes']
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        stop = time.monotonic() + 5
        while not sock.exists():
            if process.poll() is not None or time.monotonic() >= stop:
                raise RuntimeError('fixture writer startup failed')
            time.sleep(0.01)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(sock))
            yield connection
    finally:
        extract.terminate(process)


def cells(path):
    with path.open('rb') as stream:
        header = stream.read(80)
        databases = struct.unpack_from('<I', header, 76)[0]
        stream.read(8 * databases)
        while stream.read(8) == b'BBVPAGE1':
            size, count = struct.unpack('<QQ', stream.read(16))
            page = bytearray(stream.read(size))
            try:
                at = 0
                for _ in range(count):
                    db, kind, expiry, kn, pn, vn = struct.unpack_from('<IBqQQQ', page, at)
                    at += 37
                    key = bytes(page[at:at + kn]); at += kn
                    position = bytes(page[at:at + pn]); at += pn
                    value = bytes(page[at:at + vn]); at += vn
                    yield db, kind, expiry, key, position, value
            finally:
                page[:] = b'\0' * len(page)


class FrozenExportWitnesses(unittest.TestCase):
    def test_expired_keys_binary_fields_and_other_database_survive_offline_load(self):
        with tempfile.TemporaryDirectory(prefix='witness-expired-', dir=options.scratch_root) as directory:
            directory = Path(directory)
            expiry = int(time.time() * 1000) + 1500
            with fixture(directory) as connection:
                send(connection, 'SET', 'busbar:schema', '9')
                send(connection, 'SET', 'busbar:expired', b'\0\xffexpired')
                send(connection, 'PEXPIREAT', 'busbar:expired', expiry)
                send(connection, 'HSET', b'busbar:hash\xff', b'field\0\xff', b'value\xff\0')
                send(connection, 'PEXPIREAT', b'busbar:hash\xff', expiry)
                send(connection, 'SELECT', 1)
                send(connection, 'SET', b'otherdb\xff', b'binary\0value')
                send(connection, 'SAVE')
            time.sleep(max(0, (expiry - int(time.time() * 1000)) / 1000 + 0.05))
            source = directory / 'source.rdb'
            digest = extract.digest_file(source)
            output = directory / 'export.frames'
            receipt = extract.extract(source, digest, output, options.module, options.server,
                                      databases=16, page_bytes=256, page_items=2, deadline=10, scratch=options.scratch_root)
            values = list(cells(output))
            self.assertIn((0, 1, expiry, b'busbar:expired', b'', b'\0\xffexpired'), values)
            self.assertIn((0, 2, expiry, b'busbar:hash\xff', b'field\0\xff', b'value\xff\0'), values)
            self.assertIn((1, 1, -1, b'otherdb\xff', b'', b'binary\0value'), values)
            self.assertEqual(receipt['keys_by_database'][:2], [3, 1])
            self.assertGreater(receipt['pages'], 1)
            self.assertEqual(extract.digest_file(source), digest)
            if options.retain_source:
                os.link(source, options.retain_source)
                os.chmod(options.retain_source, 0o400)

    def test_expired_hash_field_expiry_is_rejected_without_publishing(self):
        with tempfile.TemporaryDirectory(prefix='witness-hfe-', dir=options.scratch_root) as directory:
            directory = Path(directory)
            expiry = int(time.time() * 1000) + 1500
            with fixture(directory) as connection:
                send(connection, 'HSET', 'busbar:volatile-hash', 'field', 'value')
                send(connection, 'HPEXPIREAT', 'busbar:volatile-hash', expiry, 'FIELDS', 1, 'field')
                send(connection, 'SAVE')
            time.sleep(max(0, (expiry - int(time.time() * 1000)) / 1000 + 0.05))
            source = directory / 'source.rdb'
            digest = extract.digest_file(source)
            output = directory / 'rejected.frames'
            with self.assertRaisesRegex(extract.UnsupportedFrozenSource, 'hash field expiry'):
                extract.extract(source, digest, output, options.module, options.server, deadline=10, scratch=options.scratch_root)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + '.json').exists())
            self.assertEqual(extract.digest_file(source), digest)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *extra])
