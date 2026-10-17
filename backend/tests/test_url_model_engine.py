"""The deployed lexical model accepts URL strings and performs no resolution."""
from app.engines.url_model import ARTIFACT, score_url
import pytest


def test_deployed_host_model_is_packaged_and_scores_string_only():
    assert ARTIFACT.is_file()
    result = score_url("https://example.com/account/verify")
    assert 0.0 <= result["probability"] <= 1.0
    assert 0.0 <= result["threshold"] <= 1.0
    assert len(result["version"]) == 16


@pytest.mark.parametrize('value', ['https://example.com/', 'http://login.example.com/account?id=42', 'https://192.0.2.1/login'])
def test_research_dictionary_schema_matches_frozen_evaluator(value):
    pytest.importorskip('pyarrow')
    from app.core.url_utils import parse_url
    from app.engines.url_features import phresh_features
    from evaluation.phreshphish_utils import hand_features
    from evaluation.run_url_v3 import ext
    extractor = ext()
    for full in [False, True]:
        assert phresh_features(value, parse_url(value).host, extractor, full) == hand_features(value, parse_url(value).host, extractor, full)
