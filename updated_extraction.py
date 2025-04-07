import pandas as pd
import csv
from urllib.parse import urlparse
import os
from sqlalchemy import create_engine

postgres_password = os.getenv('POSTGRES_PASSWORD')
if not postgres_password:
    raise ValueError("Environment variable 'POSTGRES_PASSWORD' is not set!")
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
        return features
    except Exception as e:
        print(f"Error in feature extraction: {e}")
        raise

# Process data into multiple CSV files
def process_table(table_name, label, chunksize=1000, rows_per_file=100000):
    chunks = pd.read_sql(f"SELECT url, source_code, datetime FROM {table_name}", engine, chunksize=chunksize)
    file_idx = 0
    accumulated_rows = pd.DataFrame()
    total_rows = 0

    for i, chunk in enumerate(chunks):
        try:
            chunk = chunk.dropna(subset=['url', 'source_code'])
            chunk['label'] = label
            features = extract_features(chunk)
            accumulated_rows = pd.concat([accumulated_rows, features])
            total_rows += len(chunk)

            if len(accumulated_rows) >= rows_per_file:
                output_file = f"{table_name}_features_{file_idx}.csv"
                accumulated_rows.to_csv(output_file, index=False)
                print(f"Wrote {len(accumulated_rows)} rows to {output_file}, Total so far: {total_rows}")
                accumulated_rows = pd.DataFrame()  # Reset
                file_idx += 1

            if i % 100 == 0:
                print(f"Processed chunk {i+1} from {table_name} - Rows: {len(chunk)}, Total so far: {total_rows}")

        except Exception as e:
            print(f"Error processing chunk {i+1} from {table_name}: {e}")

    # Write any remaining rows
    if not accumulated_rows.empty:
        output_file = f"{table_name}_features_{file_idx}.csv"
        accumulated_rows.to_csv(output_file, index=False)
        print(f"Wrote {len(accumulated_rows)} rows to {output_file}, Total so far: {total_rows}")

    print(f"Finished processing {table_name}. Total rows: {total_rows}")

# Run for both tables
process_table("phishing_2022", label=1)
process_table("benign_2022", label=0)