"""Save the comparison rules before model fitting or test predictions."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from datetime import datetime,timezone
from evaluation.phreshphish_utils import OUT,write,sha,STRICT_ALIASES,AMBIGUOUS_FAMILIES

def main():
    if (OUT/'protocol.json').exists():raise ValueError('Protocol already frozen; do not overwrite it')
    write('protocol.json',{'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'frozen_before_training_and_test_predictions':True,
      'data_sha256':sha(ROOT/'data/phreshphish-lock.json') if (ROOT/'data/phreshphish-lock.json').exists() else None,
      'dataset_revision':'eabec4b7a66324b79cc8a0ad856d1731dc26fe1a',
      'settings':{'etis':'Existing cleaned ETIS training rows, both classes.',
        'phreshphish':'Only official PhreshPhish training rows, both classes.',
        'combined':'ETIS training phishing plus official PhreshPhish training benign and phishing; no ETIS training benign.'},
      'representations':['host_only (primary)','full_url (diagnostic comparison with genuine benign paths)'],
      'models':{'char_logistic':'char 3–5 TF-IDF, min_df=2, max_features=50000, sublinear_tf, float32; balanced LR C=4 max_iter=2000',
        'char_calibrated_svm':'same TF-IDF; balanced LinearSVC, sigmoid calibration with 2 group-disjoint folds inside fitting partition',
        'lightgbm':'handmade URL/host features; 250 trees, learning_rate=.05, 31 leaves, balanced classes, 2 CPU threads'},
      'split':'Preserve official PhreshPhish train/test designation. Never move official test rows into training or calibration. Within each eligible training pool, stable SHA-256 registered-domain buckets <80 fit, >=80 calibrate, seed namespace etis-phresh-42.',
      'leakage_control':'Exclude all official PhreshPhish test and frozen ETIS validation registered domains from every fitting/calibration pool. Input-domain metadata only is used for this exclusion. Remove training-pool domains with both labels, preserving earlier Task 2 rule; deduplicate exact same-label URL strings within each setting. No evaluation rows removed or reallocated.',
      'etis_evaluation':'Existing cleaned 8,889-row grouped validation cohort; ETIS sealed final test remains untouched. Additional calibration partition is taken from ETIS training, making this an independent comparison rather than reuse of the earlier validation thresholds.',
      'thresholds':'Select thresholds on each setting calibration rows only for FPR <=1% and <=0.1%; report achieved evaluation recall AND FPR. Also report retrospective evaluation ROC recall at those caps, explicitly non-deployable.',
      'precision':'TPR*pi/(TPR*pi+FPR*(1-pi)), pi=.01 and .001; hypothetical class-prior adjustment, not observed deployment precision. Undefined for absent classes or no positive alerts.',
      'subgroups':'Arabic if normalized lang is ar, ara or arabic; exact registry names/domains or predeclared aliases for Egyptian-brand target. Global family-only targets are ambiguous and counted separately, not asserted Egyptian.',
      'brand_registry_sha256':sha(ROOT/'backend/app/core/egyptian_brands.py'),'strict_target_aliases':STRICT_ALIASES,
      'ambiguous_global_families':sorted(AMBIGUOUS_FAMILIES),
      'invalid_input_policy':'Retain all official test rows in denominators. Unparseable URL hosts abstain (no alert), counting as FN for phishing or TN for benign; report coverage. No 2048-character runtime length cap in research feature extraction; count long URLs separately.',
      'model_promotion':'No automatic deployment or tuning based on PhreshPhish test results. No hyperparameter search.',
      'source_caveats':['Card test total 168060 versus 91260+76876=168136, difference 76; use measured counts.','Benign-URL source not stated on dataset card.','CC BY 4.0 plus card request for anti-phishing research use only.','Geographic/language subgroups do not provide authentic Egyptian SMS evidence.']})
    print('Protocol frozen before training/test predictions')

if __name__=='__main__':main()
