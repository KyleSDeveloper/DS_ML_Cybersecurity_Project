# PhishGuard: Real-Time Phishing Detection with XGBoost

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)

PhishGuard is an automated phishing detection system using XGBoost, achieving a 98% F1-score on a balanced test set and enabling real-time protection with a 7.5 ms inference time. It leverages live Phishtank feeds, URL-based features, and source code analysis to detect sophisticated phishing threats, with plans to incorporate screenshot-based features.

## Domain Background
In 2022, over 1.2 million phishing attacks ([APWG, 2023](https://docs.apwg.org/reports/apwg_trends_report_q4_2022.pdf)) exploited trust with fake webpages, causing financial losses and identity theft. Manual defenses can't keep up with evolving tactics, necessitating scalable machine learning solutions.

## Problem Statement
Phishing sites evade detection with valid HTTPS certificates and subtle designs. Current systems struggle at scale, missing nuanced traits like spoofing. PhishGuard uses XGBoost to detect phishing with high recall (92-98%) and precision (>95%), enabling real-time protection for tools like browser extensions.
 
## Datasets
- **Sources**:  
  - **Amrita Center for Cybersecurity Systems and Networks**: PostgreSQL dump sourced from [Amrita Center for Cybersecurity Systems and Networks](https://www.amrita.edu/center/amrita-center-for-cybersecurity-systems-and-networks/). Contains phishing URLs (Selenium crawler) and benign URLs (standard crawler), 2022 snapshot. Database size: ~180.94 GB. Row counts: `phishing_2022` (325,327 rows, matches Phishtank), `benign_2022` (3,592,391 rows, matches Tranco).  
  - **[Phishtank](https://phishtank.org)**: 325,327 phishing URLs (live feed for continuous learning, already included in `phishing_2022`).  
  - **[Tranco](https://tranco-list.eu)**: 3,592,391 benign sites (static baseline, fully loaded in `benign_2022`).  
- **Sampling**: Sampled 150,000 rows per class (300,000 total). Phishing URLs sourced from `phishing_2022` (undersampled from 325,327), benign URLs from `benign_2022` (undersampled from 3,592,391), stratified by `datetime` where available, cleaned for duplicates and missing data.  
- **Features**: Extracted into [`features.csv`](data/features.csv). See [Feature Engineering](#feature-engineering).
  -   
  -  
- **Sampling**: 150,000 rows per class (300,000 total), stratified by `datetime`, cleaned for duplicates and missing data.  
- **Features**: Extracted into [`features.csv`](data/features.csv). See [Feature Engineering](#feature-engineering).

## Solution
PhishGuard employs an XGBoost classifier to analyze URL structure, certificate validity, suspicious keywords, and source code, outperforming baselines on noisy web data. Trained on 300,000 pages, it achieves <100 ms inference for browser extension use. See `notebook/main.ipynb` (notebook/main.ipynb).

## Benchmarks
| Model               | Accuracy | F1-Score (Phishing) | Recall (Phishing) |
|---------------------|----------|---------------------|-------------------|
| Dummy Classifier    | 50%      | 50%                 | 50%               |
| Rule-Based (HTTPS + "login") | 65% | 60%                 | 70%               |
| Logistic Regression | 86%      | 91%                 | 88%               |
| **PhishGuard (XGBoost)** | **96%** | **98%**             | **98%**           |

## Evaluation
- **Metrics**:  
  - **Balanced Test Set**: F1-score 98%, Recall 98%, Precision 98% for phishing class.  
  - **Imbalanced Test Set (1% phishing)**: F1-score 95%, Recall 92%, Precision 98%.  
  - **Adversarial Test Set**: F1-score 87%, Recall 80%, Precision 95%.   
- **Feature Extraction Time**: 42 ms (average, sourced from `feature_extraction.log`).  
- **Tools**: Confusion matrices, precision-recall curves, ROC curves in [`notebook/main.ipynb`](notebook/main.ipynb).  

### Sample Confusion Matrix
Below is the confusion matrix for Logistic Regression and XGBoost on the balanced test set, showing true positives, false positives, true negatives, and false negatives:

![Confusion Matrix](images/confusion_matrix.png)

## Project Design

### Data Acquisition
Received a PostgreSQL dataset (~180.94 GB) from Amrita University’s crawlers (Selenium for phishing, standard for benign). Imported into a local PostgreSQL instance (phishing_db) as phishing_2022 (325,327 rows) and benign_2022 (3,592,391 rows) tables.

### Feature Engineering
Features target spoofing, malicious code, and domain characteristics:

| Feature                | Description                  | Rationale                  | Importance (XGBoost) |
|------------------------|------------------------------|----------------------------|----------------------|
| `url_length`           | Character count             | Longer URLs often phishing | 0.072                |
| `num_subdomains`       | Dots minus 1                | Subdomain abuse in spoofing| 0.090                |
| `has_https`            | 1 if "https" else 0         | Misused in fake trust      | 0.137                |
| `num_hyphens`          | Hyphen count                | Spoofed domains (e.g., pay-pal) | 0.071                |
| `num_special_chars`    | Count of @, %, #, $         | Obfuscation markers        | 0.130                |
| `has_suspicious_keyword`| 1 if "login," "secure," etc.| Mimics trusted actions     | 0.156                |
| `num_external_links`   | "href=" count               | Redirects to malicious sites | 0.264                |
| `num_scripts`          | "<script>" tag count        | Potential malicious code   | 0.079                |


**Note**: Screenshot features (e.g., CNN-extracted) are planned but not yet implemented due to missing screenshot data.

### Model Development
- **Split**: 60% train, 20% validation, 20% test.  
- **Imbalance Handling**: Dataset balanced by sampling (150,000 per class).  
- **Models**: Logistic Regression (`max_iter=1000`), XGBoost (`max_depth=6`, `learning_rate=0.1`).  
- **Tuning**: 5-fold CV, grid search on `max_depth`, `learning_rate`, `n_estimators`, `subsample`, `colsample_bytree`.  

### Deployment Plan
- **API**: Deploy as a Flask/FASTAPI service for real-time URL classification.  
- **Integration**: Prototype a browser extension to query the API for each visited URL.  
- **Scalability**: Use Docker and a load balancer for high traffic.  
- **Continuous Learning**: Retrain monthly with new Phishtank data, comparing performance on a validation set.

### Results
- **Balanced Test Set**:
  - **XGBoost**:
    - Recall (Phishing): 98%
    - F1-Score (Phishing): 98%
    - Accuracy: 96%
  - **Logistic Regression**:
    - Recall (Phishing): 88%
    - F1-Score (Phishing): 91%
    - Accuracy: 86%
- **Imbalanced Test Set (1% phishing)**:
  - **XGBoost**:
    - Recall (Phishing): 92%
    - F1-Score (Phishing): 95%
    - Accuracy: 99%
  - **Logistic Regression**:
    - Recall (Phishing): 87%
    - F1-Score (Phishing): 76%
    - Accuracy: 80%
- **Adversarial Test Set**:
  - **XGBoost**:
    - Recall (Phishing): 80%
    - F1-Score (Phishing): 87%
    - Accuracy: 90%

### Challenges and Limitations
- **Adversarial Vulnerability**: Recall drops to 80% on adversarial examples, indicating a need for adversarial training.
- **Screenshot Features**: Missing due to lack of screenshot data; future work includes collecting screenshots with `selenium`.
- **Zero-Day Attacks**: Not tested on recent phishing campaigns; future work includes evaluating on 2024 data.
- **Computational Cost**: Screenshot feature extraction (planned) may increase inference time, requiring optimization.

#### Future Work Roadmap
- **Adversarial Vulnerability**: Implement adversarial training with synthetic examples by Q2 2025, targeting a 90% F1-score on adversarial tests.
- **Screenshot Features**: Collect screenshot data using `selenium` by Q3 2025, extract features with ResNet50, aiming for <50 ms inference per screenshot.
- **Zero-Day Attacks**: Evaluate on 2024 phishing data by Q4 2025 to assess performance on recent campaigns.

## Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/KyleSDeveloper/DS_ML_Cybersecurity_Project.git
   cd DS_ML_Cybersecurity_Project

2. **Install Dependencies**:
  ```bash

pip install -r requirements.txt



