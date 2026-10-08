"""Versioned CSV content identity, independent of platform newline/CSV quoting.

Row order, duplicate rows, values and column names remain significant. Column order
is canonicalized; embedded newlines become LF. No whitespace or labels are trimmed.
This identifies input content; it does not promise bit-identical model training.
"""
import csv
import hashlib
import json
from pathlib import Path

METHOD = 'etis-csv-content-v1'


def dataset_identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.reader(stream)
        columns = next(reader, None)
        if not columns or len(set(columns)) != len(columns):
            raise ValueError('Dataset requires unique nonempty CSV column names')
        if any(not name for name in columns):
            raise ValueError('Dataset column names must be nonempty')
        indices = sorted(range(len(columns)), key=lambda i: columns[i])

        def update(value):
            digest.update(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
            digest.update(b'\n')

        update([METHOD, [columns[i] for i in indices]])
        for row in reader:
            if len(row) != len(columns):
                raise ValueError('Dataset CSV row has the wrong column count')
            update([row[i].replace('\r\n', '\n').replace('\r', '\n') for i in indices])
    return {'dataset_sha256': digest.hexdigest(),
            'dataset_fingerprint_method': METHOD,
            'dataset_file_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
