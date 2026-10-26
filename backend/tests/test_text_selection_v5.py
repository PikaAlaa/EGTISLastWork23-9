"""Guard equal-source weighting and the frozen loss/latency/tie order."""
import pytest
from evaluation.select_text_v5 import choose_candidate, loss_components, percentile95


def held(tp, fn, fp, tn):
    return {'held_source': {'confusion': dict(tp=tp, fn=fn, fp=fp, tn=tn),
                            'phishing_n': tp+fn, 'legitimate_n': fp+tn}}


def test_unequal_sources_are_equally_weighted_and_medium_counts_as_alarm():
    loso = {'small': held(1, 1, 1, 9), 'large': held(7, 3, 2, 0)}
    comp = loss_components(loso, dict(n=12, incomplete_n=0, medium_or_high_n=3), ['small', 'large'])
    assert comp == pytest.approx(dict(source_mean_fnr=.4, source_mean_fpr=.55,
                                    everyday_medium_or_high_rate=.25))


def test_incomplete_probe_replay_cannot_select():
    with pytest.raises(ValueError, match='complete probes'):
        loss_components({'s': held(1, 1, 1, 1)}, dict(n=12, incomplete_n=1), ['s'])


def candidate(loss, f1, passes=True):
    return dict(mean_primary_loss=loss, mean_validation_macro_f1=f1, latency_gate_passes=passes)


RULE = dict(tie_tolerance=.000001, max_p95_cpu_ms=300, simplicity_order=['simple', 'complex'])


def test_latency_rejection_precedes_loss_and_f1():
    models = {'slow': candidate(.01, 1., False), 'simple': candidate(.2, .8), 'complex': candidate(.3, 1.)}
    winner, detail = choose_candidate(models, RULE)
    assert winner == 'simple'
    assert detail['eligible'] == ['simple', 'complex']


def test_loss_tolerance_then_validation_f1_then_simplicity():
    models = {'simple': candidate(.2, .8), 'complex': candidate(.2000005, .9)}
    assert choose_candidate(models, RULE)[0] == 'complex'
    models['simple']['mean_validation_macro_f1'] = .9
    assert choose_candidate(models, RULE)[0] == 'simple'
    models['complex']['mean_primary_loss'] = .200002
    models['complex']['mean_validation_macro_f1'] = 1.
    assert choose_candidate(models, RULE)[0] == 'simple'


def test_no_latency_eligible_candidate_fails_closed():
    with pytest.raises(ValueError, match='No candidate'):
        choose_candidate({'simple': candidate(.1, 1., False)}, RULE)


def test_p95_uses_linear_interpolation_including_tail():
    assert percentile95(list(range(1, 228))) == pytest.approx(215.7)
