# 🛡️ PhishGuard AI V3

### Smart Phishing URL Detection & Explainable Security Analysis

**Developed by Albin Joseph** · BCA Student · AI & Cybersecurity

PhishGuard AI V3 is a portfolio-focused web application that analyzes URL structure without opening the submitted website. It combines a transparent rule engine with a lightweight local statistical model and presents the result through a polished responsive cybersecurity dashboard.

## V3 highlights
- Animated aurora / gradient background
- Glassmorphism cybersecurity UI
- Responsive desktop + mobile layout
- Hybrid rule + local statistical scoring
- Risk score, confidence and component scores
- Explainable security findings
- Browser-based recent scan history
- Local analysis; the detector does not visit the submitted URL
- Professional About section featuring Albin Joseph
- Automated tests

## Run locally

```bash
python -m pip install -r requirements.txt
python app.py
```

Open:

`http://127.0.0.1:5000`

## Test

```bash
pytest
```

## Scoring

The final risk score combines a transparent heuristic score and a lightweight local logistic-style score. V3 is intentionally honest about the model: it is **not yet a model trained on a large labeled phishing dataset**.

### Planned V4
- Train an actual scikit-learn model on a labeled URL dataset
- Evaluate precision, recall, F1 and confusion matrix
- Add optional reputation/threat-intelligence sources
- Add report export and deployment

## Author

**Albin Joseph**  
BCA Student | AI & Cybersecurity Enthusiast

## Disclaimer

This is an educational defensive-security project. A low risk score does not guarantee that a URL is safe. Analyze only URLs you are authorized to examine and never open suspicious links just to test them.
