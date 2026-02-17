"""
Recompute Features from URLs - No Network Needed
Reads URLs from balanced_features.csv and computes improved numerical features.
"""
import pandas as pd
import numpy as np
import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "data/processed/balanced_urls.csv"
OUTPUT_FILE = PROJECT_ROOT / "data/processed/balanced_features.csv"

# Known URL shorteners
SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'tiny.cc',
    'cutt.ly', 'buff.ly', 'rb.gy', 'short.to', 'adf.ly', 'bc.vc', 'j.mp',
    'v.gd', 'po.st', 'q-r.to', 'qrco.de', 'l.ead.me', 'rebrand.ly',
    'shorturl.at', 'ur0.jp', 'zpr.io', 'href.li', 'urlz.fr', 'lnkd.in',
    'lihi1.com', 'tiny1.org', 'inx.lv', 'u.to'
}

# Free hosting platforms often abused by phishers
FREE_HOSTING = {
    'weebly.com', 'wixsite.com', 'firebaseapp.com', 'web.app', 'pages.dev',
    'netlify.app', 'herokuapp.com', 'blogspot.com', 'wordpress.com',
    'godaddysites.com', 'webflow.io', 'framer.app', 'carrd.co',
    'myfreesites.net', 'boxmode.io', 'ukit.me', 'start.page',
    'bolt.host', 'webcindario.com', 'liveblog365.com', 'orson.website',
    'weeblysite.com', 'ghost.io', 'webwave.dev', 'squarespace.com',
    'workers.dev', 'r2.dev', 'appspot.com'
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'password', 'credential', 'auth',
    'authenticate', 'wallet', 'recover', 'suspend', 'locked', 'unusual',
    'billing', 'invoice', 'payment', 'bank', 'paypal', 'amazon', 'apple',
    'microsoft', 'netflix', 'facebook', 'instagram', 'whatsapp'
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.website', '.space',
    '.fun', '.icu', '.buzz', '.click', '.shop', '.store', '.live',
    '.host', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq'
}

# Trusted TLDs
TRUSTED_TLDS = {
    '.edu', '.gov', '.mil', '.int', '.ac.uk', '.edu.au', '.gov.uk',
    '.ac.ke', '.edu.eg', '.ac.kr', '.edu.vn', '.edu.br', '.edu.in',
    '.lg.jp', '.go.jp', '.gov.il', '.gov.pl', '.org.uk', '.co.uk'
}

# Trusted domains
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
    'netflix.com', 'paypal.com', 'outlook.com', 'live.com', 'office.com',
    'yahoo.com', 'bing.com', 'whatsapp.com', 'zoom.us', 'spotify.com',
    'twitch.tv', 'adobe.com', 'dropbox.com', 'slack.com', 'notion.so',
    'medium.com', 'quora.com', 'pinterest.com', 'tumblr.com', 'flickr.com',
    'bbc.com', 'cnn.com', 'nytimes.com', 'washingtonpost.com', 'reuters.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
    'googleapis.com', 'gstatic.com', 'cloudflare.com', 'akamai.com'
}


def shannon_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


def extract_features_from_url(url):
    """Extract 30 improved features from URL string only"""
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    if not parsed or not parsed.netloc:
        domain = ""
        path = ""
        query = ""
    else:
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

    # Remove www. prefix
    clean_domain = domain.replace("www.", "")
    url_lower = url.lower()

    features = {}

    # ===== URL STRUCTURE FEATURES =====

    # 1. url_length - actual length (normalized later by scaler)
    features['url_length'] = len(url)

    # 2. domain_length
    features['domain_length'] = len(clean_domain)

    # 3. path_length
    features['path_length'] = len(path)

    # 4. num_dots - more dots = more subdomains = suspicious
    features['num_dots'] = url.count('.')

    # 5. num_hyphens - many hyphens in domain = suspicious
    features['num_hyphens'] = domain.count('-')

    # 6. num_subdomains
    parts = clean_domain.split('.')
    features['num_subdomains'] = max(0, len(parts) - 2)  # e.g. a.b.c.com = 2 sub

    # 7. num_digits_in_domain
    features['num_digits_in_domain'] = sum(c.isdigit() for c in clean_domain)

    # 8. num_special_chars - @, !, ~, etc.
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9./:?&=\-_]', url))

    # 9. has_ip_address - domain is an IP
    try:
        ipaddress.ip_address(domain.split(':')[0])  # strip port
        features['has_ip_address'] = 1
    except ValueError:
        features['has_ip_address'] = 0

    # 10. has_at_symbol - only flag @ in netloc (phishing trick like http://legit.com@evil.com)
    features['has_at_symbol'] = 1 if '@' in domain else 0

    # 11. has_double_slash_redirect - // after protocol
    features['has_double_slash_redirect'] = 1 if url.find('//') > 7 else 0

    # 12. has_https
    features['has_https'] = 1 if url.startswith('https') else 0

    # 13. has_prefix_suffix - hyphen in domain name
    features['has_prefix_suffix'] = 1 if '-' in clean_domain else 0

    # ===== SHORTENER & HOSTING =====

    # 14. uses_shortener
    features['uses_shortener'] = 1 if any(s in domain for s in SHORTENERS) else 0

    # 15. uses_free_hosting
    features['uses_free_hosting'] = 1 if any(h in domain for h in FREE_HOSTING) else 0

    # ===== ENTROPY & RANDOMNESS =====

    # 16. url_entropy - random strings have high entropy
    features['url_entropy'] = round(shannon_entropy(url), 4)

    # 17. domain_entropy
    features['domain_entropy'] = round(shannon_entropy(clean_domain), 4)

    # 18. path_entropy
    features['path_entropy'] = round(shannon_entropy(path), 4)

    # ===== QUERY & PATH =====

    # 19. num_query_params
    features['num_query_params'] = len(parse_qs(query))

    # 20. path_depth - number of / in path
    features['path_depth'] = path.count('/') if path else 0

    # 21. query_length
    features['query_length'] = len(query)

    # ===== LEXICAL ANALYSIS =====

    # 22. digit_ratio - ratio of digits to total chars in URL
    total_chars = len(url) if url else 1
    features['digit_ratio'] = round(sum(c.isdigit() for c in url) / total_chars, 4)

    # 23. letter_ratio
    features['letter_ratio'] = round(sum(c.isalpha() for c in url) / total_chars, 4)

    # 24. longest_word_in_path
    if path:
        words = re.split(r'[/\-_.?&=]', path)
        features['longest_word_in_path'] = max((len(w) for w in words), default=0)
    else:
        features['longest_word_in_path'] = 0

    # 25. avg_token_length_in_domain
    tokens = re.split(r'[.\-]', clean_domain)
    features['avg_token_length_domain'] = round(
        sum(len(t) for t in tokens) / max(len(tokens), 1), 2
    )

    # ===== SUSPICIOUS PATTERNS =====

    # 26. has_suspicious_keywords
    features['has_suspicious_keywords'] = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0

    # 27. has_suspicious_tld
    features['has_suspicious_tld'] = 1 if any(url_lower.endswith(tld) or tld + '/' in url_lower for tld in SUSPICIOUS_TLDS) else 0

    # 28. has_trusted_tld
    features['has_trusted_tld'] = 1 if any(tld in url_lower for tld in TRUSTED_TLDS) else 0

    # 29. brand_in_subdomain - known brand names appearing in subdomains (phishing trick)
    brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
              'netflix', 'instagram', 'whatsapp', 'outlook', 'linkedin', 'chase',
              'wells', 'bankof', 'scotiabank', 'att', 'naver']
    # Check if brand is in subdomain but NOT the primary domain
    if len(parts) > 2:
        subdomain_text = '.'.join(parts[:-2])
        features['brand_in_subdomain'] = 1 if any(b in subdomain_text for b in brands) else 0
    else:
        features['brand_in_subdomain'] = 0

    # 30. is_trusted_domain
    parts_for_base = clean_domain.split('.')
    base_domain = '.'.join(parts_for_base[-2:]) if len(parts_for_base) >= 2 else clean_domain
    features['is_trusted_domain'] = 1 if base_domain in TRUSTED_DOMAINS else 0

    return features


def main():
    print("=" * 60)
    print("RECOMPUTING FEATURES FROM URLs (No Network Needed)")
    print("=" * 60)

    # Load existing data
    print(f"\n[1/3] Loading URLs from {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    urls = df['url'].tolist()
    labels = df['label'].tolist()
    print(f"  - Loaded {len(urls)} URLs")

    # Extract features
    print(f"\n[2/3] Extracting 30 improved features...")
    all_features = []
    for i, url in enumerate(urls):
        feats = extract_features_from_url(str(url))
        feats['label'] = labels[i]
        feats['url'] = url
        all_features.append(feats)

        if (i + 1) % 10000 == 0:
            print(f"  - Processed {i+1}/{len(urls)} URLs")

    # Save
    print(f"\n[3/3] Saving to {OUTPUT_FILE}...")
    result_df = pd.DataFrame(all_features)

    # Reorder: url first, then features, then label
    feature_cols = [c for c in result_df.columns if c not in ('url', 'label')]
    result_df = result_df[['url'] + feature_cols + ['label']]
    result_df.to_csv(OUTPUT_FILE, index=False)

    print(f"\n  - Saved {len(result_df)} rows with {len(feature_cols)} features")
    print(f"  - Features: {feature_cols}")
    print("\n  DONE! Now run: python scripts/train_models.py")


if __name__ == "__main__":
    main()
