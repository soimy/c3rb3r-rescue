#!/usr/bin/env python3
"""Inspect the Git INDEX before commit/push; never print detected secret values.

Optional --master-file checks raw/hex/base64 representations of the real 48-byte
material and its IV/key portions. This is a guard, not a complete secret scanner.
"""
import argparse
import base64
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ALLOWED_ROOTS = {'scripts', 'tests', 'docs', 'profiles', 'skills'}
ALLOWED_FILES = {'.gitignore', 'README.md', 'requirements.txt', 'AGENTS.md'}
SUFFIXES = {'.py', '.md', '.txt', '.json', '.yaml'}


def inspect_blob(path, data, mode, secrets=()):
    p = PurePosixPath(path)
    errors = []
    if p.parts[0] not in ALLOWED_ROOTS and path not in ALLOWED_FILES:
        errors.append('path outside publication allowlist')
    if path not in ALLOWED_FILES and p.suffix not in SUFFIXES:
        errors.append('unapproved file type')
    if mode not in ('100644', '100755'):
        errors.append('not a regular Git blob')
    if len(data) > 1024**2 or b'\x00' in data:
        errors.append('binary or oversized content')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        errors.append('not UTF-8 text')
        text = ''
    for expression, message in (
        (r'gh[pousr]_[A-Za-z0-9]{20,}', 'GitHub credential pattern'),
        (r'glpat-[A-Za-z0-9_-]{16,}', 'GitLab credential pattern'),
        (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 'private key PEM'),
        (r'[/]Users[/][^/\s]+[/]', 'personal absolute path'),
        (r'(?<![\d.])192\.168\.\d{1,3}\.\d{1,3}(?![\d.])', 'incident private IP'),
    ):
        if re.search(expression, text):
            errors.append(message)
    if any(secret in data for secret in secrets):
        errors.append('known incident key material')
    return errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path('.'))
    p.add_argument('--master-file', type=Path)
    a = p.parse_args()
    secrets = []
    if a.master_file:
        raw = a.master_file.read_bytes()
        if len(raw) != 48:
            raise ValueError('Expected a 48-byte private master file')
        for value in (raw, raw[:16], raw[16:]):
            secrets.extend((value, value.hex().encode(), value.hex().upper().encode(), base64.b64encode(value)))
    records = subprocess.check_output(['git', '-C', str(a.repo), 'ls-files', '--stage', '-z']).split(b'\0')
    failures, count = [], 0
    for record in records:
        if not record:
            continue
        prefix, path_bytes = record.split(b'\t', 1)
        mode, oid, stage = prefix.decode().split()
        path = path_bytes.decode()
        data = subprocess.check_output(['git', '-C', str(a.repo), 'cat-file', 'blob', oid])
        errors = inspect_blob(path, data, mode, secrets)
        if stage != '0':
            errors.append('unresolved index stage')
        if errors:
            failures.append({'path': path, 'issues': errors})
        count += 1
    if not count:
        failures.append({'issues': ['empty Git index']})
    print(json.dumps({'checked_blobs': count, 'failures': failures}, ensure_ascii=True))
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
