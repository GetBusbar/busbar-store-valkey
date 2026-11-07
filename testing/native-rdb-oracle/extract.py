#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Offline official-engine extraction. Never connects to a source server.

Requires a caller-supplied RDB SHA256 and a private copied RDB. The only engine
accepted by this first bridge is official Valkey 9.1.3. Its upstream loader reads
Valkey 8 RDB11 and Valkey 9 RDB80. No RDB parsing is implemented here.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time


class UnsupportedFrozenSource(Exception):
    """Missing native capability or source feature that cannot be preserved."""


def digest_file(path, stop=None):
    digest = hashlib.sha256()
    with open(path, 'rb', buffering=0) as source:
        buffer = bytearray(1024 * 1024)
        try:
            while count := source.readinto(buffer):
                if stop is not None and time.monotonic() >= stop:
                    raise UnsupportedFrozenSource('offline extraction deadline exceeded')
                digest.update(memoryview(buffer)[:count])
        finally:
            buffer[:] = b'\0' * len(buffer)
    return digest.hexdigest()


def command(connection, *arguments):
    # Only fixed control commands go through this supervisor. Native payload
    # cells are streamed by the module, never through Python RESP conversions.
    pieces = [f'*{len(arguments)}\r\n'.encode()]
    for arg in arguments:
        arg = str(arg).encode()
        pieces.extend([f'${len(arg)}\r\n'.encode(), arg, b'\r\n'])
    connection.sendall(b''.join(pieces))
    line = bytearray()
    while not line.endswith(b'\r\n'):
        part = connection.recv(1)
        if not part or len(line) >= 4096:
            raise UnsupportedFrozenSource('invalid offline engine control reply')
        line.extend(part)
    if line[:1] == b'-':
        # Module errors are fixed, content-free strings. Do not forward engine
        # diagnostics, which can otherwise contain source names or values.
        if b'UnsupportedFrozenSource' in line:
            raise UnsupportedFrozenSource('native guards failed or unsupported hash field expiry')
        raise UnsupportedFrozenSource('offline engine refused extraction')
    if line != b'+OK\r\n' and line != b'+PONG\r\n':
        raise UnsupportedFrozenSource('unexpected offline engine control reply')


def validate_export(path, expected_digest, page_bytes, page_items, databases, max_bytes, stop=None):
    """Check complete framing/coverage without allocating native values."""
    total = path.stat().st_size
    if total > max_bytes:
        raise UnsupportedFrozenSource('export exceeds total byte limit')
    with path.open('rb', buffering=0) as stream:
        header = stream.read(80)
        if len(header) != 80 or header[:8] != b'BBVEXP01' or header[8:72] != expected_digest.encode():
            raise UnsupportedFrozenSource('wrong frozen export identity')
        version, db_count = struct.unpack_from('<II', header, 72)
        if version != 0x00090103 or db_count != databases:
            raise UnsupportedFrozenSource('unsupported frozen export engine or database count')
        raw_counts = stream.read(8 * databases)
        if len(raw_counts) != 8 * databases:
            raise UnsupportedFrozenSource('truncated frozen export coverage')
        counts = struct.unpack(f'<{databases}Q', raw_counts)
        observed = [0] * databases
        rows = pages = 0
        while True:
            if stop is not None and time.monotonic() >= stop:
                raise UnsupportedFrozenSource('offline extraction deadline exceeded')
            tag = stream.read(8)
            if tag == b'BBVEND01':
                tail = stream.read(80)
                if len(tail) != 80 or tail[16:] != expected_digest.encode() or stream.read(1):
                    raise UnsupportedFrozenSource('invalid frozen export completion')
                final_rows, final_pages = struct.unpack_from('<QQ', tail)
                if (final_rows, final_pages) != (rows, pages) or tuple(observed) != counts:
                    raise UnsupportedFrozenSource('frozen export coverage mismatch')
                return {'rows': rows, 'pages': pages, 'keys_by_database': list(counts)}
            if tag != b'BBVPAGE1':
                raise UnsupportedFrozenSource('incomplete frozen export')
            raw = stream.read(16)
            if len(raw) != 16:
                raise UnsupportedFrozenSource('truncated frozen export page')
            size, items = struct.unpack('<QQ', raw)
            if not 0 < size <= page_bytes or not 0 < items <= page_items:
                raise UnsupportedFrozenSource('frozen export page exceeds budget')
            payload = bytearray(size)
            try:
                view = memoryview(payload)
                at = 0
                while at < size:
                    read = stream.readinto(view[at:])
                    if not read:
                        raise UnsupportedFrozenSource('truncated frozen export cells')
                    at += read
                at = 0
                for _ in range(items):
                    if size - at < 37:
                        raise UnsupportedFrozenSource('truncated frozen export cell')
                    db, kind, expiry, key_len, pos_len, val_len = struct.unpack_from('<IBqQQQ', payload, at)
                    if db >= databases or kind > 5 or expiry < -1:
                        raise UnsupportedFrozenSource('unsupported frozen export cell')
                    length = 37 + key_len + pos_len + val_len
                    if length > size - at:
                        raise UnsupportedFrozenSource('truncated frozen export binary data')
                    if kind == 0:
                        observed[db] += 1
                    at += length
                if at != size:
                    raise UnsupportedFrozenSource('trailing frozen export bytes')
            finally:
                payload[:] = b'\0' * len(payload)
            rows += items
            pages += 1


def validate_load_log(path):
    # The official loader can discard malformed empty keys or invalid negative
    # expiry. Its own counters must prove that no such lossy path was taken.
    # Never reproduce its diagnostics in an error or receipt.
    if path.stat().st_size > 1024 * 1024:
        raise UnsupportedFrozenSource('official loader diagnostics exceed budget')
    messages = [line for line in path.read_bytes().splitlines() if b'Done loading RDB, keys loaded:' in line]
    if len(messages) != 1:
        raise UnsupportedFrozenSource('official loader coverage counters missing')
    message = messages[0]
    loaded = re.search(rb'keys loaded: ([0-9]+)', message)
    expired = re.search(rb'keys expired: ([0-9]+)', message)
    fields = re.search(rb'all fields expired hashes: ([0-9]+)', message)
    empty = re.search(rb'empty keys skipped: ([0-9]+)', message)
    if not loaded or not expired or not fields or int(expired[1]) or int(fields[1]) or (empty and int(empty[1])):
        raise UnsupportedFrozenSource('official loader dropped unsupported physical records')
    return int(loaded[1])


def terminate(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def extract(source, source_sha256, output, module, server, *, databases=16,
            page_bytes=1024 * 1024, page_items=1000, max_bytes=1024 * 1024 * 1024,
            max_source_bytes=1024 * 1024 * 1024, deadline=60, scratch=None):
    if len(source_sha256) != 64 or any(c not in '0123456789abcdef' for c in source_sha256):
        raise UnsupportedFrozenSource('expected lowercase source SHA256 is required')
    if not 1 <= databases <= 1024 or not 64 <= page_bytes <= 64 * 1024 * 1024 or not 1 <= page_items <= 1000000:
        raise UnsupportedFrozenSource('invalid offline extraction limits')
    if not 0 < deadline <= 86400 or not 0 < max_bytes < 2**63 or not 0 < max_source_bytes < 2**63:
        raise UnsupportedFrozenSource('invalid offline extraction limits')
    source, output, module = Path(source).absolute(), Path(output).absolute(), Path(module).absolute()
    receipt = output.with_name(output.name + '.json')
    if output.exists() or receipt.exists():
        raise UnsupportedFrozenSource('output or receipt already exists')
    server = Path(shutil.which(str(server)) or str(server)).absolute()
    version = subprocess.run([str(server), '--version'], check=True, capture_output=True, timeout=5).stdout
    if not version.startswith(b'Valkey server v=9.1.3 '):
        raise UnsupportedFrozenSource('this bridge requires Valkey 9.1.3')
    server_digest, module_digest = digest_file(server), digest_file(module)
    if scratch is None:
        raise UnsupportedFrozenSource('an explicit private scratch root is required')
    scratch = Path(scratch).absolute()
    scratch.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    stop = started + deadline
    process = None
    # Every disposable file stays beneath the task's explicit scratch root.
    with tempfile.TemporaryDirectory(prefix='frozen-export-', dir=scratch) as work:
        work = Path(work)
        os.chmod(work, 0o700)
        dump = work / 'snapshot.rdb'
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb', buffering=0) as src, dump.open('xb', buffering=0) as dst:
            initial = os.fstat(src.fileno())
            if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_source_bytes:
                raise UnsupportedFrozenSource('source is not a bounded regular RDB artifact')
            digest = hashlib.sha256()
            copied = 0
            buffer = bytearray(1024 * 1024)
            try:
                while count := src.readinto(buffer):
                    copied += count
                    if copied > max_source_bytes or time.monotonic() >= stop:
                        raise UnsupportedFrozenSource('source copy exceeds extraction limits')
                    view = memoryview(buffer)[:count]
                    digest.update(view)
                    written = 0
                    while written < count:
                        n = dst.write(view[written:])
                        if not n:
                            raise UnsupportedFrozenSource('source copy failed')
                        written += n
                os.fsync(dst.fileno())
            finally:
                buffer[:] = b'\0' * len(buffer)
            after = os.fstat(src.fileno())
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(initial, f) != getattr(after, f) for f in fields) or digest.hexdigest() != source_sha256:
                raise UnsupportedFrozenSource('source changed or SHA256 does not match')
        os.chmod(dump, 0o400)
        exported = work / 'native.frames'
        sock = work / 'engine.sock'
        log = work / 'engine.log'
        args = [str(server), '--port', '0', '--unixsocket', str(sock), '--unixsocketperm', '700',
                '--dir', str(work), '--dbfilename', dump.name, '--databases', str(databases),
                '--replicaof', '127.0.0.1', '0', '--replica-read-only', 'yes',
                '--replica-serve-stale-data', 'yes', '--save', '', '--appendonly', 'no',
                '--maxmemory', '0', '--maxmemory-policy', 'noeviction', '--daemonize', 'no',
                '--hide-user-data-from-log', 'yes', '--logfile', str(log),
                '--user', 'default', 'on', 'nopass', '-@all', '+ping', '+bbexport.run',
                '--loadmodule', str(module), str(exported), source_sha256, str(page_bytes),
                str(page_items), str(max_bytes), str(databases), str(int(deadline * 1000))]
        try:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            while not sock.exists():
                if process.poll() is not None or time.monotonic() >= stop:
                    raise UnsupportedFrozenSource('official engine failed to load bounded source')
                time.sleep(0.01)
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(max(0.001, stop - time.monotonic()))
                connection.connect(str(sock))
                command(connection, 'PING')
                command(connection, 'BBEXPORT.RUN')
            terminate(process)
            if time.monotonic() >= stop:
                raise UnsupportedFrozenSource('offline extraction deadline exceeded')
            if digest_file(dump, stop) != source_sha256:
                raise UnsupportedFrozenSource('private snapshot changed during extraction')
            loaded_keys = validate_load_log(log)
            coverage = validate_export(exported, source_sha256, page_bytes, page_items, databases, max_bytes, stop)
            if sum(coverage['keys_by_database']) != loaded_keys:
                raise UnsupportedFrozenSource('official loader/export coverage mismatch')
            exported_digest = digest_file(exported, stop)
            result = {'format': 'busbar-valkey-frozen-export/1', 'source_sha256': source_sha256,
                      'export_sha256': exported_digest, 'engine_version': '9.1.3',
                      'engine_sha256': server_digest, 'module_sha256': module_digest,
                      'loaded_native_keys': loaded_keys,
                      'unsupported_source_features': ['hash-field-expiry', 'module-values', 'streams'],
                      **coverage}
            # A completed read-only export and its receipt are published only
            # after native guards, source identity, framing and coverage pass.
            os.chmod(exported, 0o400)
            staged_receipt = work / 'receipt.json'
            with staged_receipt.open('x') as target:
                json.dump(result, target, sort_keys=True, indent=2)
                target.write('\n')
                target.flush()
                os.fsync(target.fileno())
            os.chmod(staged_receipt, 0o400)
            os.link(staged_receipt, receipt)
            try:
                os.link(exported, output)
            except BaseException:
                receipt.unlink()
                raise
            return result
        except (OSError, subprocess.SubprocessError) as error:
            raise UnsupportedFrozenSource('offline engine I/O, startup or deadline failure') from error
        finally:
            terminate(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--server', default='valkey-server')
    parser.add_argument('--scratch-root', dest='scratch', type=Path, required=True)
    parser.add_argument('--databases', type=int, default=16)
    parser.add_argument('--page-bytes', type=int, default=1024 * 1024)
    parser.add_argument('--page-items', type=int, default=1000)
    parser.add_argument('--max-bytes', type=int, required=True)
    parser.add_argument('--max-source-bytes', type=int, required=True)
    parser.add_argument('--deadline', type=float, default=60)
    args = parser.parse_args()
    try:
        result = extract(**vars(args))
    except UnsupportedFrozenSource as error:
        parser.exit(1, f'UnsupportedFrozenSource: {error}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
