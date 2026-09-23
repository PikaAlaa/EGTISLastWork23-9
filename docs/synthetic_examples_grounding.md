# Synthetic example grounding

Rows with source `synthetic_egyptian_brands` are defensive test/training examples, not observed incidents and not evidence of prevalence. They model credential and OTP requests, fake rewards, urgent account action, institution impersonation, and suspicious links; additional wording variants are synthetic stress cases.

The core patterns are grounded in these public Egyptian financial-sector sources:

- Central Bank of Egypt, “The Central Bank of Egypt Asserts on the Importance of Protecting Banking and Personal Information,” 16 October 2024: warns about smishing, phishing, pharming, vishing, impersonation, requests for card/PIN/CVV/OTP data, and unofficial requests to update customer information. https://www.cbe.org.eg/en/news-publications/news/2024/10/16/13/44/the-central-bank-of-egypt-asserts-on-the-importance-of-protecting-banking-and-personal-information
- Central Bank of Egypt, “Cybersecurity Issues Training and Awareness,” updated 23 March 2023: documents fake-gain messages, malicious links, credential/card-data theft, sender impersonation, and phone phishing. https://www.cbe.org.eg/en/cybersecurity/cybersecurity-issues-training-and-awareness
- CIB Egypt, “How to Keep your Digital Banking Secure”: describes phishing messages that imitate trusted companies and seek usernames, passwords, or card details, plus OTP use. https://www.cibeg.com/en/learning-center/banking-101/security-in-digital-channels

These references justify the pattern families only. They do not validate any specific synthetic message as a real-world event.
