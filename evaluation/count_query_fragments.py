"""Count query/fragment coverage by label in existing PhreshPhish pools, offline.

Exports aggregate counts only; never accesses HTML or destination URLs.
"""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'evaluation/reports/2026-10-v4/query-shortcut/query-fragment-counts.json'


def counts(frame):
    frame = frame[frame.source.eq('phreshphish')]
    result = {}
    for label, name in [(0, 'benign'), (1, 'phishing')]:
        values = frame.loc[frame.label_binary.eq(label), 'url']
        item = dict(total=len(values), with_query=0, without_query=0,
                    with_fragment=0, without_fragment=0, with_both=0, parse_failures=0)
        for value in values:
            value = str(value)
            try:
                parsed = urlsplit(value if '://' in value else 'http://' + value)
            except ValueError:
                item['parse_failures'] += 1
                continue
            query, fragment = bool(parsed.query), bool(parsed.fragment)
            item['with_query' if query else 'without_query'] += 1
            item['with_fragment' if fragment else 'without_fragment'] += 1
            item['with_both'] += int(query and fragment)
        assert item['with_query'] + item['without_query'] + item['parse_failures'] == item['total']
        assert item['with_fragment'] + item['without_fragment'] + item['parse_failures'] == item['total']
        result[name] = item
    return result


def main():
    cache_path = ROOT / 'evaluation/local-results/v4/prepared.joblib'
    data = joblib.load(cache_path)
    deployment = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    assert data['data_sha256'] == deployment['data_sha256']
    assert data['protocol_sha256'] == deployment['protocol_sha256']
    result = {
        'scope': 'PhreshPhish rows only, in existing filtered fitting/calibration pools and the complete official test split',
        'definitions': {
            'with_query': 'Nonempty urllib.parse.urlsplit query; an empty ? is not counted.',
            'with_fragment': 'Nonempty urllib.parse.urlsplit fragment; an empty # is not counted.',
            'with_both': 'Nonempty query and nonempty fragment on the same URL.',
            'selected_combined_model': 'Only PhreshPhish rows from the selected combined model pools; ETIS rows excluded.',
            'phreshphish_only_model': 'PhreshPhish-only model pools, whose filtering differs from the combined setting.',
            'train_calibration': 'Fitting and calibration pools combined; not the unfiltered upstream official training split.',
        },
        'data_sha256': data['data_sha256'],
        'protocol_sha256': data['protocol_sha256'],
        'prepared_cache_sha256': hashlib.sha256(cache_path.read_bytes()).hexdigest(),
        'pools': {},
    }
    for setting, key in [('combined', 'selected_combined_model'), ('phreshphish', 'phreshphish_only_model')]:
        fit, cal = data['pools'][setting]
        assert not fit.loc[fit.source.eq('phreshphish'), 'official_split'].ne('train').any()
        assert not cal.loc[cal.source.eq('phreshphish'), 'official_split'].ne('train').any()
        assert set(fit.row_id).isdisjoint(cal.row_id)
        result['pools'][key] = {'fit': counts(fit), 'calibration': counts(cal),
                                'train_calibration': counts(pd.concat([fit, cal], ignore_index=True))}
    test = data['tests']['phreshphish_test']
    assert test.source.eq('phreshphish').all() and test.official_split.eq('test').all()
    assert len(test) == 168060 and test.row_id.is_unique
    result['test'] = counts(test)
    OUTPUT.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
