"""
Feature Extraction Module v2
Extracts 30 numerical features from URLs for Phishing Detection
Uses URL-string analysis only - no network requests needed for fast prediction.
"""

import re
import math
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import Counter
import logging

# Configure logger
logger = logging.getLogger('DeepShield_FeatureExtraction')

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

# Brand names for subdomain detection
BRANDS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
    'netflix', 'instagram', 'whatsapp', 'outlook', 'linkedin', 'chase',
    'wells', 'bankof', 'scotiabank', 'att', 'naver'
]

# Trusted domains (won't be phishing themselves)
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
    'googleapis.com', 'gstatic.com', 'cloudflare.com', 'akamai.com',
    'vce.ac.in', 'india.gov.in', 'bcci.tv', 'irctc.co.in',
    'viswam.ai', 'openai.com', 'anthropic.com'
}


def _shannon_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


# Feature names in order (must match training)
FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'num_dots', 'num_hyphens',
    'num_subdomains', 'num_digits_in_domain', 'num_special_chars',
    'has_ip_address', 'has_at_symbol', 'has_double_slash_redirect',
    'has_https', 'has_prefix_suffix', 'uses_shortener', 'uses_free_hosting',
    'url_entropy', 'domain_entropy', 'path_entropy', 'num_query_params',
    'path_depth', 'query_length', 'digit_ratio', 'letter_ratio',
    'longest_word_in_path', 'avg_token_length_domain',
    'has_suspicious_keywords', 'has_suspicious_tld', 'has_trusted_tld',
    'brand_in_subdomain', 'is_trusted_domain'
]


class FeatureExtractor:
    """Extracts 30 numerical features from URLs for ML model prediction"""

    def __init__(self):
        self.features = []
        self.project_root = Path(__file__).resolve().parent.parent

    def extract_features(self, url):
        """
        Extract all 30 features from the URL.
        Returns a list of numerical feature values (matching FEATURE_NAMES order).
        """
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
        domain_parts = clean_domain.split('.')

        features = []

        # 1. url_length
        features.append(len(url))

        # 2. domain_length
        features.append(len(clean_domain))

        # 3. path_length
        features.append(len(path))

        # 4. num_dots
        features.append(url.count('.'))

        # 5. num_hyphens
        features.append(domain.count('-'))

        # 6. num_subdomains
        features.append(max(0, len(domain_parts) - 2))

        # 7. num_digits_in_domain
        features.append(sum(c.isdigit() for c in clean_domain))

        # 8. num_special_chars
        features.append(len(re.findall(r'[^a-zA-Z0-9./:?&=\-_]', url)))

        # 9. has_ip_address
        try:
            ipaddress.ip_address(domain.split(':')[0])
            features.append(1)
        except ValueError:
            features.append(0)

        # 10. has_at_symbol - only flag @ in netloc (phishing trick), not in path
        features.append(1 if '@' in domain else 0)

        # 11. has_double_slash_redirect
        features.append(1 if url.find('//') > 7 else 0)

        # 12. has_https
        features.append(1 if url.startswith('https') else 0)

        # 13. has_prefix_suffix
        features.append(1 if '-' in clean_domain else 0)

        # 14. uses_shortener
        features.append(1 if any(s in domain for s in SHORTENERS) else 0)

        # 15. uses_free_hosting
        features.append(1 if any(h in domain for h in FREE_HOSTING) else 0)

        # 16. url_entropy
        features.append(round(_shannon_entropy(url), 4))

        # 17. domain_entropy
        features.append(round(_shannon_entropy(clean_domain), 4))

        # 18. path_entropy
        features.append(round(_shannon_entropy(path), 4))

        # 19. num_query_params
        features.append(len(parse_qs(query)))

        # 20. path_depth
        features.append(path.count('/') if path else 0)

        # 21. query_length
        features.append(len(query))

        # 22. digit_ratio
        total_chars = len(url) if url else 1
        features.append(round(sum(c.isdigit() for c in url) / total_chars, 4))

        # 23. letter_ratio
        features.append(round(sum(c.isalpha() for c in url) / total_chars, 4))

        # 24. longest_word_in_path
        if path:
            words = re.split(r'[/\-_.?&=]', path)
            features.append(max((len(w) for w in words), default=0))
        else:
            features.append(0)

        # 25. avg_token_length_domain
        tokens = re.split(r'[.\-]', clean_domain)
        features.append(round(
            sum(len(t) for t in tokens) / max(len(tokens), 1), 2
        ))

        # 26. has_suspicious_keywords
        features.append(1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0)

        # 27. has_suspicious_tld
        features.append(1 if any(
            url_lower.endswith(tld) or tld + '/' in url_lower
            for tld in SUSPICIOUS_TLDS
        ) else 0)

        # 28. has_trusted_tld
        features.append(1 if any(tld in url_lower for tld in TRUSTED_TLDS) else 0)

        # 29. brand_in_subdomain
        if len(domain_parts) > 2:
            subdomain_text = '.'.join(domain_parts[:-2])
            features.append(1 if any(b in subdomain_text for b in BRANDS) else 0)
        else:
            features.append(0)

        # 30. is_trusted_domain
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else clean_domain
        features.append(1 if base_domain in TRUSTED_DOMAINS else 0)

        return features

    def get_feature_names(self):
        """Return list of feature names in order"""
        return FEATURE_NAMES
