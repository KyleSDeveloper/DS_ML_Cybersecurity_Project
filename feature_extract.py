import logging
import pandas as pd
import csv
import re
from urllib.parse import urlparse
import os
import time
import numpy as np
import cProfile
import pstats
from sqlalchemy import create_engine
from tenacity import retry, stop_after_attempt, wait_fixed

# Set up logging
logging.basicConfig(
    filename='feature_extraction.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Securely load database string
db_string = os.getenv('DB_STRING', "postgresql://postgres:YOUR_PASSWORD@localhost:5432/phishing_db?sslmode=require")
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def connect_to_db():
    engine = create_engine(db_string)
    with engine.connect() as connection:
        logging.info("Connection to PostgreSQL successful!")
        print("Connection to PostgreSQL successful!")
    return engine

try:
    engine = connect_to_db()
except Exception as e:
    logging.error(f"Error connecting to PostgreSQL: {e}")
    print(f"Error connecting to PostgreSQL: {e}")
    raise

# Optimized vectorized feature extraction with improved accuracy
def count_subdomains(url):
    try:
        parsed = urlparse(url)
        return len(parsed.netloc.split('.')) - 2 if parsed.netloc else 0
    except Exception as e:
        logging.warning(f"Error parsing URL for subdomains: {url}, Error: {e}")
        return 0

def extract_features(chunk):
    try:
        # Ensure columns are strings
        chunk['url'] = chunk['url'].fillna('').astype(str)
        chunk['source_code'] = chunk['source_code'].fillna('').astype(str)
        
        # Precompute lowercase only for necessary columns
        url_lower = chunk['url'].str.lower()
        
        # Vectorized feature extraction with improved accuracy
        features = pd.DataFrame({
            'url_length': chunk['url'].str.len(),
            'num_subdomains': chunk['url'].apply(count_subdomains),
            'has_https': chunk['url'].str.startswith('https').astype(int),
            'num_hyphens': chunk['url'].str.count('-'),
            'num_special_chars': chunk['url'].str.count(r'[@%#\$]'),
            'has_suspicious_keyword': url_lower.str.contains('login|secure|account|verify|update|password', na=False).astype(int),
            'num_external_links': chunk['source_code'].str.count(r'href=["\']http'),
            'num_scripts': chunk['source_code'].str.count(r'<script(?:\s[^>]*)?>'),
            'label': chunk['label']
        })
        
        # Validate features
        if (features['num_subdomains'] < 0).any():
            logging.warning("Negative num_subdomains detected, setting to 0")
            features['num_subdomains'] = features['num_subdomains'].clip(lower=0)
        
        return features.to_dict('records')
    except Exception as e:
        logging.error(f"Error in feature extraction: {e}")
        raise

# Append features to CSV with error handling
def add_to_csv_file(features, filename='features.csv', first_write=False):
    if not features:
        return
    headers = features[0].keys()
    mode = 'w' if first_write else 'a'
    try:
        with open(filename, mode, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            if mode == 'w':
                writer.writeheader()
            writer.writerows(features)
        # Verify row count
        expected_rows = len(features)
        written_rows = sum(1 for _ in open(filename)) - 1  # Subtract header
        if first_write and written_rows != expected_rows:
            logging.warning(f"Expected {expected_rows} rows, but wrote {written_rows}")
            print(f"Warning: Expected {expected_rows} rows, but wrote {written_rows}")
    except Exception as e:
        logging.error(f"Error writing to CSV: {e}")
        print(f"Error writing to CSV: {e}")
        raise

# Process data with profiling and timing isolation
first_write = True
phishing_domains = set()
benign_domains = set()
extract_times = []
csv_times = []

# Phishing data
phishing_chunks = pd.read_sql("SELECT url, source_code, datetime FROM phishing_2022 LIMIT 150000", engine, chunksize=1000)
for i, chunk in enumerate(phishing_chunks):
    try:
        chunk = chunk.dropna(subset=['url', 'source_code'])
        chunk['datetime'] = pd.to_datetime(chunk['datetime'])
        
        # Stratify by month with proportional sampling
        grouped = chunk.groupby(pd.Grouper(key='datetime', freq='ME'))
        stratified_chunk = pd.concat([group.sample(min(len(group), 1000 // len(grouped))) for _, group in grouped if not group.empty])
        stratified_chunk['label'] = 1
        
        logging.info(f"Phishing Chunk {i+1} - Before stratification: {len(chunk)}, After: {len(stratified_chunk)}")
        print(f"Phishing Chunk {i+1} - Before stratification: {len(chunk)}, After: {len(stratified_chunk)}")
        
        phishing_domains.update(urlparse(row['url']).netloc for _, row in stratified_chunk.iterrows())
        
        # Profile feature extraction
        profiler = cProfile.Profile()
        profiler.enable()
        
        start_extract = time.time()
        features = extract_features(stratified_chunk)
        extract_time = (time.time() - start_extract) * 1000
        extract_times.append(extract_time)
        
        profiler.disable()
        stats_file = f'profile_stats_phishing_chunk_{i+1}.prof'
        profiler.dump_stats(stats_file)
        
        # Time CSV writing separately
        start_csv = time.time()
        add_to_csv_file(features, first_write=first_write)
        csv_time = (time.time() - start_csv) * 1000
        csv_times.append(csv_time)
        
        logging.info(f"Phishing Chunk {i+1} - Feature extraction time: {extract_time:.2f} ms, CSV writing time: {csv_time:.2f} ms")
        print(f"Phishing Chunk {i+1} - Feature extraction time: {extract_time:.2f} ms, CSV writing time: {csv_time:.2f} ms")
        print(f"Profiling stats saved to {stats_file}")
        
        if i == 0:
            ps = pstats.Stats(stats_file)
            ps.sort_stats('cumulative').print_stats(10)
        
        first_write = False
    except Exception as e:
        logging.error(f"Error processing phishing chunk: {e}")
        print(f"Error processing phishing chunk: {e}")

# Benign data
benign_chunks = pd.read_sql("SELECT url, source_code, datetime FROM benign_2022 LIMIT 150000", engine, chunksize=1000)
for i, chunk in enumerate(benign_chunks):
    try:
        chunk = chunk.dropna(subset=['url', 'source_code'])
        chunk['datetime'] = pd.to_datetime(chunk['datetime'])
        
        # Stratify by month with proportional sampling
        grouped = chunk.groupby(pd.Grouper(key='datetime', freq='ME'))
        stratified_chunk = pd.concat([group.sample(min(len(group), 1000 // len(grouped))) for _, group in grouped if not group.empty])
        stratified_chunk['label'] = 0
        
        logging.info(f"Benign Chunk {i+1} - Before stratification: {len(chunk)}, After: {len(stratified_chunk)}")
        print(f"Benign Chunk {i+1} - Before stratification: {len(chunk)}, After: {len(stratified_chunk)}")
        
        benign_domains.update(urlparse(row['url']).netloc for _, row in stratified_chunk.iterrows())
        
        # Profile feature extraction
        profiler = cProfile.Profile()
        profiler.enable()
        
        start_extract = time.time()
        features = extract_features(stratified_chunk)
        extract_time = (time.time() - start_extract) * 1000
        extract_times.append(extract_time)
        
        profiler.disable()
        stats_file = f'profile_stats_benign_chunk_{i+1}.prof'
        profiler.dump_stats(stats_file)
        
        # Time CSV writing separately
        start_csv = time.time()
        add_to_csv_file(features, first_write=first_write)
        csv_time = (time.time() - start_csv) * 1000
        csv_times.append(csv_time)
        
        logging.info(f"Benign Chunk {i+1} - Feature extraction time: {extract_time:.2f} ms, CSV writing time: {csv_time:.2f} ms")
        print(f"Benign Chunk {i+1} - Feature extraction time: {extract_time:.2f} ms, CSV writing time: {csv_time:.2f} ms")
        print(f"Profiling stats saved to {stats_file}")
        
        if i == 0:
            ps = pstats.Stats(stats_file)
            ps.sort_stats('cumulative').print_stats(10)
        
    except Exception as e:
        logging.error(f"Error processing benign chunk: {e}")
        print(f"Error processing benign chunk: {e}")

# Check domain overlap
overlap = phishing_domains & benign_domains
if overlap:
    logging.warning(f"Domain overlap detected: {overlap}")
    print(f"Warning: Domain overlap detected: {overlap}")

# Aggregate timing stats
logging.info(f"Average Feature Extraction Time: {np.mean(extract_times):.2f} ms")
logging.info(f"Average CSV Writing Time: {np.mean(csv_times):.2f} ms")
print(f"Average Feature Extraction Time: {np.mean(extract_times):.2f} ms")
print(f"Average CSV Writing Time: {np.mean(csv_times):.2f} ms")

logging.info("Feature extraction and CSV writing completed!")
print("Feature extraction and CSV writing completed!")