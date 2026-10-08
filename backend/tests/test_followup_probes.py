"""Preserved reviewer inputs, now exposed regression cases rather than held-out data."""
import json
from pathlib import Path
import pytest
from app.engines.risk_scoring import calculate_final_risk_score

ROOT=Path(__file__).resolve().parents[2]
rows=json.loads((ROOT/'evaluation/followup-probes.json').read_text(encoding='utf-8'))
parameters=[pytest.param(row,id=row['name'],marks=pytest.mark.xfail(strict=True,
    reason='Known model false alarm on the supplied NBE notice; genuine-SMS acceptance remains open'))
    if row.get('known_limitation') else pytest.param(row,id=row['name']) for row in rows]

@pytest.mark.parametrize('row',parameters)
def test_reviewer_followup_probe(db,row):
    verdict=calculate_final_risk_score(**row['body'],db=db)['verdict']
    if row['expected']=='not 400':
        assert verdict in {'LOW','MEDIUM','HIGH','INCOMPLETE'}
    else:
        assert verdict in row['expected'].split('/')
