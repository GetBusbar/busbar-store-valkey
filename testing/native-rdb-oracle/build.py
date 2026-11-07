#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the offline module; no Cargo/plugin runtime dependencies are added."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--peer-output', type=Path)
args = parser.parse_args()
header = root / 'vendor' / 'valkeymodule.h'
if hashlib.sha256(header.read_bytes()).hexdigest() != '1006fc046f0836322ab95178f75e0362fba2bf37b6595329207b6bff02b60793':
    parser.error('vendored official Valkey 9.1.3 header checksum mismatch')
flags = ['-dynamiclib', '-undefined', 'dynamic_lookup'] if sys.platform == 'darwin' else ['-shared']
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC', *flags,
                '-o', str(args.output), str(root / 'export.c')], check=True)

if args.peer_output:
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-o', str(args.peer_output), str(root / 'peer.c')], check=True)
