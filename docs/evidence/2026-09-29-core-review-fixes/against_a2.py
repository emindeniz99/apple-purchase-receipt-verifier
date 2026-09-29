#!/usr/bin/env python3
"""Evidence only (2026-09-29): the rebuilt module's corpus rows against
lane A2's rows from 05b4ad9, row by row.

    against_a2.py <a2-rows-dir> <new-rows-dir>

Both directories hold module-<corpus>.jsonl as the trap host's `calls`
mode writes them ({"id", "out"} or {"id", "trap"}). Prints, per corpus,
how many rows are identical, differ only in the message, or differ in the
verdict (verified, reason, endpoint status), and lists every row that
differs with both answers' verdict and message.
"""

import json
import sys

CORPORA = ['cases', 'hostile', 'algorithms', 'substrate', 'fuzz']


def rows(path):
    out = {}
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            row = json.loads(line)
            out[row['id']] = row
    return out


def verdict(row):
    """(verdict, message) of one row."""
    if 'trap' in row:
        return ('trap', row['trap'])
    try:
        answer = json.loads(row['out'])
    except (json.JSONDecodeError, TypeError):
        return ('text', row.get('out'))
    if isinstance(answer, dict) and 'status' in answer and 'verified' not in answer:
        return (f"status {answer['status']}", '')
    if isinstance(answer, dict):
        if answer.get('verified'):
            return ('verified', '')
        return (answer.get('reason'), answer.get('message'))
    return ('other', str(answer))


def main():
    old_dir, new_dir = sys.argv[1], sys.argv[2]
    total = {'identical': 0, 'message': 0, 'verdict': 0, 'missing': 0}
    for corpus in CORPORA:
        old = rows(f'{old_dir}/module-{corpus}.jsonl')
        new = rows(f'{new_dir}/module-{corpus}.jsonl')
        counts = {'identical': 0, 'message': 0, 'verdict': 0, 'missing': 0}
        listed = []
        for key, row in old.items():
            if key not in new:
                counts['missing'] += 1
                continue
            if row == new[key]:
                counts['identical'] += 1
                continue
            (old_verdict, old_message), (new_verdict, new_message) = verdict(row), verdict(new[key])
            kind = 'verdict' if old_verdict != new_verdict else 'message'
            counts[kind] += 1
            listed.append((kind, key, old_verdict, old_message, new_verdict, new_message))
        print(f'== {corpus}: {len(old)} rows: ' + ', '.join(f'{v} {k}' for k, v in counts.items()))
        for kind, key, old_verdict, old_message, new_verdict, new_message in sorted(listed):
            print(f'  {kind:7} {key}')
            print(f'          05b4ad9: {old_verdict}: {old_message}')
            print(f'          now:     {new_verdict}: {new_message}')
        for k, v in counts.items():
            total[k] += v
    print('== all: ' + ', '.join(f'{v} {k}' for k, v in total.items()))


if __name__ == '__main__':
    main()
