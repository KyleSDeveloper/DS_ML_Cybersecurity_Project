# PhishGuard: Real-Time Phishing Detection with XGBoost


This project automates phishing webpage detection using an XGBoost classifier, achieving 92-95% recall to safeguard users from sophisticated cyberthreats.

## Domain Background
In 2022, over 1.2 million phishing attacks ([APWG, 2023](https://www.apwg.org)) exploited trust with fake webpages, causing financial losses and identity theft. Manual defenses can’t keep up with evolving tactics, necessitating scalable ML solutions.

## Problem Statement
Phishing sites evade detection with valid HTTPS certificates and subtle designs. Current systems struggle at scale, missing nuanced traits like spoofing. This project uses XGBoost to detect phishing with high recall (92-95%), bridging the gap for real-time protection.

## Datasets
- **Source**:  
  - [Phishtank](https://phishtank.org) (325,327 phishing URLs).  
  - [Tranco](https://tranco-list.eu) (3,592,391 benign sites).  
- **Sampling**: 150,000 rows per class (300,000 total), stratified by `datetime`, cleaned for duplicates and missing data.  
- **Features**: Extracted into [`features.csv`](features.csv) (to be uploaded). See [Feature Engineering](#feature-engineering).

## Solution
An XGBoost classifier analyzes URL structure, certificate validity, and suspicious keywords, outperforming simpler models on noisy web data. Trained on 300,000 pages, it enables real-time tools (e.g., browser extensions) with <100 ms inference. See implementation in [`sandbox.ipynb`](sandbox.ipynb).

## Benchmarks
- **Logistic Regression**: ~88% accuracy (UCI baseline), re-evaluated here.  
- **Dummy Classifier**: 50% (random guess).  
- **Rule-Based**: Flags HTTPS + "login" (baseline context).  
XGBoost targets >90% F1, surpassing these.

## Evaluation
- **Metrics**: Recall (92-95%), Precision (>85%), F1 (>90%) for phishing class.  
- **Tools**: Confusion matrices, precision-recall curves in [`sandbox.ipynb`](sandbox.ipynb).  

## Project Design

### Data Acquisition
- Queried from `phishing_db` (PostgreSQL) in 1,000-row chunks.  
- See [`sandbox.ipynb`](sandbox.ipynb) for SQLAlchemy code.

### Feature Engineering
Features target spoofing and malicious code:

| Feature             | Description                  | Rationale                  |
|---------------------|------------------------------|----------------------------|
| `url_length`        | Character count             | Longer URLs often phishing |
| `num_subdomains`    | Dots minus 1                | Subdomain abuse in spoofing|
| `has_https`         | 1 if "https" else 0         | Misused in fake trust      |
| `num_hyphens`       | Hyphen count                | Spoofed domains (e.g., pay-pal) |
| `num_special_chars` | Count of @, %, #, $         | Obfuscation markers        |
| `has_suspicious`    | 1 if "login," "secure," etc.| Mimics trusted actions     |
| `num_external_links`| "href=" count               | Redirects to malicious sites |
| `num_scripts`       | "<script>" tag count        | Potential malicious code   |

### Model Development
- **Split**: 80% train, 20% test.  
- **Models**: Logistic Regression (`max_iter=1000`), XGBoost (`max_depth=6`, `learning_rate=0.1`).  
- **Tuning**: 5-fold CV, grid search on `max_depth` and `learning_rate`.  

### Results
- XGBoost achieves 92-95% recall, >90% F1 (pending full run).  
- Feature importance and threshold tuning in [`sandbox.ipynb`](sandbox.ipynb).

## Setup Instructions
1. Clone the repo:
   ```bash
   git clone https://github.com/KyleSDeveloper/DS_ML_Cybersecurity_Project.git
