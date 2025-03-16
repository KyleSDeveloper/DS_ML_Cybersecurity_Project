import os
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Define folder paths and suspicious keywords
benign_folder = 'benign_sites'
phishing_folder = 'phishing_sites'
suspicious_keywords = ['login', 'password', 'verify', 'account', 'secure', 'update', 'bank', 'credit card', 'ssn', 'social security']

# Function to extract base domain from filename (e.g., 'www_example_com.html' -> 'www.example.com')
def get_base_domain(filename):
    return filename.replace('_', '.').replace('.html', '')

# Function to clean HTML by removing scripts and styles
def clean_soup(soup):
    for script in soup(["script", "style"]):
        script.decompose()
    return soup

# Feature extraction functions
def get_num_forms(soup):
    """Count the number of <form> tags."""
    return len(soup.find_all('form'))

def get_num_inputs(soup):
    """Count the number of <input> tags within forms."""
    forms = soup.find_all('form')
    return sum(len(form.find_all('input')) for form in forms)

def has_password_field(soup):
    """Check if there's an <input type='password'> (1 if yes, 0 if no)."""
    return 1 if soup.find('input', type='password') else 0

def get_num_links(soup):
    """Count the number of <a> tags with href."""
    return len(soup.find_all('a', href=True))

def has_suspicious_keywords(soup, keywords):
    """Check if any suspicious keywords are present in the text (1 if yes, 0 if no)."""
    clean_soup(soup)  # Remove scripts and styles
    text = soup.get_text().lower()
    return 1 if any(keyword in text for keyword in keywords) else 0

def is_external_link(base_domain, link):
    """Determine if a link points to an external domain."""
    if not link.startswith('http'):
        return False  # Relative link, considered internal
    link_domain = urlparse(link).netloc
    return link_domain != base_domain

def get_num_external_links(soup, base_domain):
    """Count the number of external links."""
    links = soup.find_all('a', href=True)
    return sum(1 for link in links if is_external_link(base_domain, link['href']))

def has_external_form_action(soup, base_domain):
    """Check if any form action points to an external domain (1 if yes, 0 if no)."""
    forms = soup.find_all('form', action=True)
    for form in forms:
        action = form['action']
        if is_external_link(base_domain, action):
            return 1
    return 0

# Function to extract all features from an HTML string
def extract_features(html, base_domain, keywords):
    soup = BeautifulSoup(html, 'html.parser')
    features = {
        'num_forms': get_num_forms(soup),
        'num_inputs': get_num_inputs(soup),
        'has_password_field': has_password_field(soup),
        'num_links': get_num_links(soup),
        'has_suspicious_keywords': has_suspicious_keywords(soup, keywords),
        'num_external_links': get_num_external_links(soup, base_domain),
        'has_external_form_action': has_external_form_action(soup, base_domain)
    }
    return features

# Main script to process files and extract features
data = []
for folder, label in [(benign_folder, 0), (phishing_folder, 1)]:
    for filename in os.listdir(folder):
        if filename.endswith('.html'):
            file_path = os.path.join(folder, filename)
            with open(file_path, 'r', encoding='utf-8') as file:
                html = file.read()
            base_domain = get_base_domain(filename)
            features = extract_features(html, base_domain, suspicious_keywords)
            features['label'] = label
            data.append(features)

# Convert the list of feature dictionaries to a DataFrame and save to CSV
df = pd.DataFrame(data)
df.to_csv('features.csv', index=False)

print("Features extracted and saved to 'features.csv'.")