import pandas as pd
import numpy as np
from pathlib import Path

def combine_datasets():
    # Read both CSV files
    print("Reading phishing dataset...")
    phishing_df = pd.read_csv('dataset_chunks/phishing_features.csv')
    print(f"Read {len(phishing_df)} phishing samples")
    
    print("\nReading benign dataset...")
    benign_df = pd.read_csv('dataset_chunks/benign_features.csv')
    print(f"Read {len(benign_df)} benign samples")
    
    # Combine the datasets
    print("\nCombining datasets...")
    combined_df = pd.concat([phishing_df, benign_df], ignore_index=True)
    
    # Shuffle the combined dataset
    print("Shuffling combined dataset...")
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save the combined dataset
    output_file = 'combined_dataset.csv'
    print(f"\nSaving combined dataset to {output_file}...")
    combined_df.to_csv(output_file, index=False)
    
    # Print dataset statistics
    print("\nDataset Statistics:")
    print(f"Total samples: {len(combined_df)}")
    print(f"Phishing samples: {len(phishing_df)}")
    print(f"Benign samples: {len(benign_df)}")
    print(f"Phishing ratio: {len(phishing_df)/len(combined_df):.2%}")
    print(f"Benign ratio: {len(benign_df)/len(combined_df):.2%}")
    
    # Verify the combined file
    if Path(output_file).exists():
        print(f"\nSuccessfully created {output_file}")
        print(f"File size: {Path(output_file).stat().st_size / (1024*1024):.2f} MB")
    else:
        print("\nError: Failed to create combined dataset file")

if __name__ == "__main__":
    combine_datasets() 