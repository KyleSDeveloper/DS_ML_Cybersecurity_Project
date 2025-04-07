import pandas as pd
import csv
from urllib.parse import urlparse
import os
import time
import numpy as np
from sqlalchemy import create_engine

# Load password from environment variable
postgres_password = os.getenv('POSTGRES_PASSWORD')
if not postgres_password:
    raise ValueError("Environment variable 'POSTGRES_PASSWORD' is not set!")

# Construct the database string with the password
db_string = f"postgresql://postgres:{postgres_password}@localhost:5432/phishing_db?sslmode=require"

def connect_to_db():
    engine = create_engine(db_string)
    with engine.connect() as connection:
        print("Connection to PostgreSQL successful!")
    return engine

try:
    engine = connect_to_db()
except Exception as e:
    print(f"Error connecting to PostgreSQL: {e}")
    raise

def count_subdomains(url):
    try:
        parsed = urlparse(url)
        return len(parsed.netloc.split('.')) - 2 if parsed.netloc else 0
    except Exception as e:
        print(f"Error parsing URL for subdomains: {url}, Error: {e}")
        return 0

def extract_features(chunk):
    try:
        chunk['url'] = chunk['url'].fillna('').astype(str)
        chunk['source_code'] = chunk['source_code'].fillna('').astype(str)
        url_lower = chunk['url'].str.lower()
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
        if (features['num_subdomains'] < 0).any():
            print("Negative num_subdomains detected, setting to 0")
            features['num_subdomains'] = features['num_subdomains'].clip(lower=0)
        return features.to_dict('records')
    except Exception as e:
        print(f"Error in feature extraction: {e}")
        raise

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
        expected_rows = len(features)
        written_rows = sum(1 for _ in open(filename)) - 1
        if first_write and written_rows != expected_rows:
            print(f"Expected {expected_rows} rows, but wrote {written_rows}")
    except Exception as e:
        print(f"Error writing to CSV: {e}")
        raise

def process_data_in_chunks(query, label, output_file, chunk_size=100000, total_rows=None):
    """Process data in chunks and write to specified output file"""
    if total_rows is None:
        # Get total row count
        count_query = f"SELECT COUNT(*) FROM ({query}) as subquery"
        total_rows = pd.read_sql(count_query, engine).iloc[0, 0]
    
    num_chunks = (total_rows + chunk_size - 1) // chunk_size
    domains = set()
    extract_times = []
    csv_times = []
    
    for chunk_num in range(num_chunks):
        offset = chunk_num * chunk_size
        print(f"\nProcessing chunk {chunk_num + 1}/{num_chunks} (offset: {offset})")
        
        chunks = pd.read_sql(f"{query} LIMIT {chunk_size} OFFSET {offset}", engine, chunksize=1000)
        first_write = (chunk_num == 0)
        
        for i, chunk in enumerate(chunks):
            try:
                chunk = chunk.dropna(subset=['url', 'source_code'])
                chunk['datetime'] = pd.to_datetime(chunk['datetime'])
                grouped = chunk.groupby(pd.Grouper(key='datetime', freq='ME'))
                stratified_chunk = pd.concat([group.sample(min(len(group), 1000 // len(grouped))) for _, group in grouped if not group.empty])
                stratified_chunk['label'] = label
                
                print(f"Sub-chunk {i+1} - Before stratification: {len(chunk)}, After: {len(stratified_chunk)}")
                
                domains.update(urlparse(row['url']).netloc for _, row in stratified_chunk.iterrows())
                
                start_extract = time.time()
                features = extract_features(stratified_chunk)
                extract_time = (time.time() - start_extract) * 1000
                extract_times.append(extract_time)
                
                start_csv = time.time()
                add_to_csv_file(features, filename=output_file, first_write=first_write)
                csv_time = (time.time() - start_csv) * 1000
                csv_times.append(csv_time)
                
                print(f"Sub-chunk {i+1} - Feature extraction time: {extract_time:.2f} ms, CSV writing time: {csv_time:.2f} ms")
                first_write = False
            except Exception as e:
                print(f"Error processing sub-chunk: {e}")
    
    return domains, extract_times, csv_times

# Create output directory if it doesn't exist
os.makedirs('dataset_chunks', exist_ok=True)

# Process phishing data
print("Processing phishing data...")
phishing_domains, phishing_extract_times, phishing_csv_times = process_data_in_chunks(
    "SELECT url, source_code, datetime FROM phishing_2022",
    label=1,
    output_file='dataset_chunks/phishing_features.csv',
    total_rows=707587
)

# Process benign data
print("\nProcessing benign data...")
benign_domains, benign_extract_times, benign_csv_times = process_data_in_chunks(
    "SELECT url, source_code, datetime FROM benign_2022",
    label=0,
    output_file='dataset_chunks/benign_features.csv',
    total_rows=3592391
)

# Check for domain overlaps
overlap = phishing_domains & benign_domains
if overlap:
    print(f"\nWarning: Domain overlap detected: {overlap}")

# Print performance metrics
all_extract_times = phishing_extract_times + benign_extract_times
all_csv_times = phishing_csv_times + benign_csv_times

print(f"\nAverage Feature Extraction Time: {np.mean(all_extract_times):.2f} ms")
print(f"Average CSV Writing Time: {np.mean(all_csv_times):.2f} ms")
print("\nFeature extraction and CSV writing completed!")
print("Files created:")
print("- dataset_chunks/phishing_features.csv")
print("- dataset_chunks/benign_features.csv")