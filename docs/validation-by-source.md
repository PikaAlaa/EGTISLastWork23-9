# Validation composition and candidate comparison

**Development only: these results do not establish everyday Egyptian SMS accuracy.**
The validation set is dominated by the translated-email source. Its labels and
language tags are not proof of representative bank notifications or dialect coverage.
The known invented everyday-message probes still produce false alarms.
Collect representative consented messages and reserve independent groups before final testing.

Content fingerprint: `13b0539d9f3cd730b31ebea3f319a76b0e065f1b2d4d1ca53bc88e0d043bf81c`
Method: `etis-csv-content-v1`. All three candidates match it.
This identifies CSV content across platforms; model training may still vary by runtime.

Selected: **char** using validation only. Final test: **not run**.
Thresholds use pooled validation, not thresholds retuned separately for each source.

## Pooled validation

| Model | Group | N | Phishing | Legitimate | Precision | Recall | F1 | FP / legitimate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| char | all | 282 | 93 | 189 | 1.000 | 0.989 | 0.995 | 0 / 189 |
| bilstm | all | 282 | 93 | 189 | 0.968 | 0.978 | 0.973 | 3 / 189 |
| lightgbm | all | 282 | 93 | 189 | 0.962 | 0.817 | 0.884 | 3 / 189 |

## By source

| Model | Group | N | Phishing | Legitimate | Precision | Recall | F1 | FP / legitimate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| char | kaggle_arabic_phishing_fully_dataset | 179 | 32 | 147 | 1.000 | 1.000 | 1.000 | 0 / 147 |
| char | kaggle_dialectal_arabic_sms | 55 | 40 | 15 | 1.000 | 1.000 | 1.000 | 0 / 15 |
| char | salloum_gaber_bilingual_corpus | 48 | 21 | 27 | 1.000 | 0.952 | 0.976 | 0 / 27 |
| bilstm | kaggle_arabic_phishing_fully_dataset | 179 | 32 | 147 | 0.914 | 1.000 | 0.955 | 3 / 147 |
| bilstm | kaggle_dialectal_arabic_sms | 55 | 40 | 15 | 1.000 | 1.000 | 1.000 | 0 / 15 |
| bilstm | salloum_gaber_bilingual_corpus | 48 | 21 | 27 | 1.000 | 0.905 | 0.950 | 0 / 27 |
| lightgbm | kaggle_arabic_phishing_fully_dataset | 179 | 32 | 147 | 0.941 | 1.000 | 0.970 | 2 / 147 |
| lightgbm | kaggle_dialectal_arabic_sms | 55 | 40 | 15 | 0.966 | 0.700 | 0.812 | 1 / 15 |
| lightgbm | salloum_gaber_bilingual_corpus | 48 | 21 | 27 | 1.000 | 0.762 | 0.865 | 0 / 27 |

## By language

| Model | Group | N | Phishing | Legitimate | Precision | Recall | F1 | FP / legitimate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| char | ar | 227 | 53 | 174 | 1.000 | 0.981 | 0.990 | 0 / 174 |
| char | mixed | 55 | 40 | 15 | 1.000 | 1.000 | 1.000 | 0 / 15 |
| bilstm | ar | 227 | 53 | 174 | 0.944 | 0.962 | 0.953 | 3 / 174 |
| bilstm | mixed | 55 | 40 | 15 | 1.000 | 1.000 | 1.000 | 0 / 15 |
| lightgbm | ar | 227 | 53 | 174 | 0.960 | 0.906 | 0.932 | 2 / 174 |
| lightgbm | mixed | 55 | 40 | 15 | 0.966 | 0.700 | 0.812 | 1 / 15 |

## By content type

| Model | Group | N | Phishing | Legitimate | Precision | Recall | F1 | FP / legitimate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| char | text | 282 | 93 | 189 | 1.000 | 0.989 | 0.995 | 0 / 189 |
| bilstm | text | 282 | 93 | 189 | 0.968 | 0.978 | 0.973 | 3 / 189 |
| lightgbm | text | 282 | 93 | 189 | 0.962 | 0.817 | 0.884 | 3 / 189 |

Machine-readable reports in `ml/models/deployment_model.json` include confusion
counts, denominators, 95% Wilson intervals, source/content-type intersections and
artifact hashes. An undefined precision or recall must not be reported as evidence
of success. Small groups and the existing validation source mix cannot settle deployment readiness.
