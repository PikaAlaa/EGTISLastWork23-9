"""Package the selected frozen sklearn/LightGBM pipeline; never fit or tune.

The legacy deployed_char.joblib filename remains the runtime's compatibility
path; model_name and the deployment receipt identify the actual architecture.
Transformer predictions cannot be deployed by this command.
"""
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from evaluation.transformer_contract import MODELS, read_json, require, sha, write_json


def main():
    import importlib.metadata
    import joblib
    from evaluation.run_text_review import probe_results
    out = ROOT / 'evaluation/reports/2026-10-v5'
    work = ROOT / 'evaluation/local-results/text-transformers'
    comparison = read_json(out / 'comparison.json')
    winner = comparison['selected_model']
    require(winner not in MODELS, 'Transformer winner: trained weights and runtime integration are unavailable; do not deploy')
    require(winner != 'bilstm', 'This packager is for pipeline artifacts only')
    candidate = comparison['models'][winner]
    require(candidate['latency_gate_passes'] and comparison['final_test_run'] is False, 'Selection gate failed')
    require(comparison['amendment_sha256'] == sha(out / 'latency_amendment.md'), 'Amendment mismatch')
    rule = ROOT.joinpath(*re.split(r'[\\/]', comparison['rule_path']))
    require(sha(rule) == comparison['rule_md_sha256'], 'Frozen rule mismatch')
    source = ROOT / 'release-artifacts/evaluation/reports/2026-10-v3/models' / (winner + '.joblib')
    run = candidate['runs'][0]
    require(sha(source) == run['model_sha256'], 'Selected source weights mismatch')
    artifact = joblib.load(source)
    artifact.update(model_name=winner, low_threshold=.2,
                    high_threshold=run['validation']['threshold_at_recall_95'],
                    selection_rule_sha256=comparison['rule_json_sha256'])
    target = ROOT / 'ml/models/deployed_char.joblib'
    before = read_json(work / 'deployed_before.json')
    require(sha(target) == before['artifact_sha256'], 'Current deployment changed since before replay')
    staged = work / 'selected_pipeline.joblib'
    joblib.dump(artifact, staged)
    packaged = joblib.load(staged)
    after = probe_results(packaged['pipeline'], packaged['high_threshold'],
                         [p['text'] for p in read_json(ROOT / 'colab-bundle/payload/probes.json')])
    after.pop('cpu_p95_ms', None)
    require(after['rows'] == run['everyday']['rows'], 'Packaged artifact does not reproduce candidate probes')
    # Backup stays ignored; original research/September artifacts are untouched.
    (work / 'previous_deployed_char.joblib').write_bytes(target.read_bytes())
    (work / 'previous_deployment_model.json').write_bytes((ROOT / 'ml/models/deployment_model.json').read_bytes())
    target.write_bytes(staged.read_bytes())
    deployment = dict(selected=winner, artifact_path=target.relative_to(ROOT).as_posix(),
                      artifact_sha256=sha(target), source_artifact_path=source.relative_to(ROOT).as_posix(),
                      source_artifact_sha256=sha(source), previous_artifact_sha256=before['artifact_sha256'],
                      deployed_at_utc=datetime.now(timezone.utc).isoformat(),
                      runtime_backend='char (legacy name for the probability-pipeline adapter)',
                      model_name=winner, low_threshold=.2, high_threshold=artifact['high_threshold'],
                      selection_rule_path=rule.relative_to(ROOT).as_posix(), selection_rule_sha256=comparison['rule_md_sha256'],
                      selection_rule_json_sha256=comparison['rule_json_sha256'],
                      latency_amendment_sha256=comparison['amendment_sha256'],
                      comparison_path=(out / 'comparison.json').relative_to(ROOT).as_posix(),
                      comparison_sha256=sha(out / 'comparison.json'), report=(out / 'REPORT.md').relative_to(ROOT).as_posix(),
                      data_sha256=comparison['data_sha256'], frozen_split_sha256=comparison['frozen_split_sha256'],
                      primary_loss=candidate['mean_primary_loss'], primary_loss_components=candidate['mean_primary_loss_components'],
                      cpu_p95_ms=candidate['local_latency']['p95_ms'], cpu_gate_limit_ms=300,
                      latency_libraries=candidate['local_latency']['libraries'],
                      libraries={n: importlib.metadata.version(n) for n in ('numpy', 'scikit-learn', 'joblib', 'lightgbm')},
                      preprocessing='normalize_arabic_text; 150-word windows, stride 75; maximum probability',
                      model_weights_fitted=False, thresholds_retuned=False, final_test_run=False,
                      genuine_egyptian_sms_test_count=0,
                      status='experimental; selected on exposed development evidence',
                      limitations=comparison['limitations'])
    write_json(ROOT / 'ml/models/deployment_model.json', deployment)
    write_json(out / 'deployment.json', dict(**deployment, before_probes=before['everyday'], after_probes=after))
    print('DEPLOYED', winner, deployment['artifact_sha256'])
    print('BEFORE', before['everyday']['high_n'], before['everyday']['medium_or_high_n'])
    print('AFTER', after['high_n'], after['medium_or_high_n'])


if __name__ == '__main__':
    main()
