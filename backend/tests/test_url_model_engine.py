"""The deployed lexical model accepts URL strings and performs no resolution."""
from app.engines.url_model import ARTIFACT, score_url


def test_deployed_host_model_is_packaged_and_scores_string_only():
    assert ARTIFACT.is_file()
    result = score_url("https://example.com/account/verify")
    assert 0.0 <= result["probability"] <= 1.0
    assert 0.0 <= result["threshold"] <= 1.0
    assert len(result["version"]) == 16
