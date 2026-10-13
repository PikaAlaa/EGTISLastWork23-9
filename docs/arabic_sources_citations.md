# ETIS — Arabic Data Source Citations

For use in Chapter 3.3 (Data Collection Methodology) and the References list.
Style matches Group_Project_Proposal_final.docx (Harvard-style, matching existing refs).

---

## Sources used as training data

**1. Salloum/Gaber bilingual corpus (300 rows: 150 phishing + 150 legitimate)**

Salloum, S., Gaber, T., Vadera, S. and Shaalan, K., 2023. *A New English/Arabic
Parallel Corpus for Phishing Emails*. ACM Transactions on Asian and Low-Resource
Language Information Processing, 22(4), Article 3606031.
Available at: https://doi.org/10.1145/3606031
[Accessed 15 7 2026].

> Note: one of the co-authors (Tarek Gaber) is affiliated with Suez Canal
> University, Egypt — worth mentioning in Chapter 3.3 as a point of relevance,
> not just citing the DOI.

---

**2. Kaggle "Fully Dataset" (1,250 rows: 1,000 legitimate + 250 phishing)**

Hosni, A., n.d. *BERT for Arabic Phishing and Legitimate Emails*. [Online]
Available at: https://www.kaggle.com/code/ahmadhosni/bert-for-arabic-phishing-and-legitimate-emails
[Accessed 15 7 2026].

> Note: this dataset's phishing rows are translated 419/advance-fee-fraud
> scam letters and its legitimate rows are translated from the UCI SMS Spam
> Collection's ham messages — worth disclosing this as a limitation in
> Chapter 3.3 or 7.3 (translated, not organically Egyptian/Arabic-authored
> content).

---

**3. Kaggle dialectal Arabic phishing/safe SMS — training only**

Listed as dialectal Arabic phishing/safe SMS; 500 rows, 250/250, 333 unique; Moroccan and Levantine dialect markers alongside Egyptian-associated wording; patterns consistent with template generation; collection method and licence not verified; used for training only and reported separately; not evidence of Egyptian-dialect performance.

Correction to the supplied review: the local safe rows include `النهارده` and `متتأخرش`. Thus “no Egyptian markers found in legitimate rows” is not supported by the file. Regional wording does not establish origin, authenticity or consent. The source is a mixed-regional, apparently templated resource, not an authenticated Egyptian SMS collection.

Candidate source: Nizar, S., n.d. *Arabic Phishing & Social Engineering Dataset*.
https://www.kaggle.com/datasets/sultannizar/arabic-phishing-dataset
The local file-to-page identity remains unverified. These are reviewer provenance findings, not a verified collection-method statement.

---

**4. GitHub Arabic-Text-Spam-Detection (78 rows: 26 spam + 52 non-spam,
Saudi/Gulf dialect)**

Mukhairez, H., n.d. *Arabic-Text-Spam-Detection*. [Online]
Available at: https://github.com/HosamMukhairez/Arabic-Text-Spam-Detection
[Accessed 15 7 2026].

> Note: also the source of the ~44-word Arabic phishing keyword blacklist
> saved for Phase 2's rule-based engine. No license file in the repo — cite
> as a GitHub repository per above, not as a formally licensed dataset.

---

## Sources cited in Literature Review only (not used as training data)

**5. Arabic SMS Scam detection paper — cite in §2.3 (Academic Research in
Phishing Detection) as evidence of the Arabic-phishing-research gap**

Zawari, A.H., Alsulami, B.S. and Alqurashi, F.A., 2025. *Detecting Arabic
SMS Scam Messages Using a Hybrid Ensemble Machine Learning Algorithms*.
Journal of Information Systems Engineering and Management, 10(55s), pp.148-156.

---

**6. Alhayan et al. deceptive-text paper — cite in §2.3, pairs well with
citation 5 as a second data point on Arabic deception-detection scarcity**

Alhayan, F., Himdi, H.T. and Alharbi, B., 2024. *Unveiling Deception in
Arabic: Optimization of Deceptive Text Detection Across Formal and Informal
Genres*. IEEE Access, 12, pp.94216-94230.

---

## Methodology wording

The development material includes translated fraud letters and UCI ham, translated/parallel emails, and a mixed-regional dialectal source whose patterns are consistent with templates. The dialectal source is training-only. Its collection origin is unverified and cannot be called Egyptian. The GitHub spam source is excluded from the phishing benchmark. These data do not provide an authentic Egyptian SMS test set. Existing synthetic fixtures are labelled and are never evidence of real-message accuracy.
