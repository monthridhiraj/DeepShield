"""Quick API test for false positives/negatives"""
import requests
import json

API_URL = "http://localhost:8000/predict"

test_urls = [
    # Should be PHISHING
    ("https://official-gov-portal.co.uk", "PHISHING"),
    ("http://secure-banking-login.xyz/verify", "PHISHING"),
    ("http://paypal-update.tk/account", "PHISHING"),
    ("http://login-microsoft365.ml/auth", "PHISHING"),
    # Should be SAFE
    ("https://www.google.com", "SAFE"),
    ("https://www.flipkart.com/search?q=laptop", "SAFE"),
    ("https://en.wikipedia.org/wiki/Machine_learning", "SAFE"),
    ("https://www.royalchallengers.com/", "SAFE"),
]

print("API PREDICTION TEST")
print("=" * 80)

for url, expected in test_urls:
    try:
        r = requests.post(API_URL, json={"url": url}, timeout=10)
        d = r.json()
        verdict = d["verdict"]
        confidence = d["confidence"]
        
        # Check if correct
        is_correct = (expected == "PHISHING" and verdict == "Phishing") or \
                     (expected == "SAFE" and verdict == "Legitimate")
        status = "OK" if is_correct else "WRONG"
        
        print(f"\n[{status}] {url}")
        print(f"  Expected: {expected}  |  Got: {verdict} (conf={confidence:.4f})")
        
        for m, v in d.get("ml_models", {}).items():
            print(f"  ML {m}: pred={v['prediction']} prob={v['probability']:.4f}")
        for m, v in d.get("dl_models", {}).items():
            print(f"  DL {m}: pred={v['prediction']} prob={v['probability']:.4f}")
    except Exception as e:
        print(f"\n[ERROR] {url}: {e}")

print("\n" + "=" * 80)

# Also save to file
import sys
with open(r"p:\DeepShield_v0.2\api_test_results.txt", "w") as f:
    for url, expected in test_urls:
        try:
            r = requests.post(API_URL, json={"url": url}, timeout=10)
            d = r.json()
            verdict = d["verdict"]
            confidence = d["confidence"]
            is_correct = (expected == "PHISHING" and verdict == "Phishing") or \
                         (expected == "SAFE" and verdict == "Legitimate")
            status = "OK" if is_correct else "WRONG"
            f.write(f"[{status}] {url}\n")
            f.write(f"  Expected: {expected}  Got: {verdict} conf={confidence:.4f}\n")
            for m, v in d.get("ml_models", {}).items():
                f.write(f"  ML {m}: pred={v['prediction']} prob={v['probability']:.4f}\n")
            for m, v in d.get("dl_models", {}).items():
                f.write(f"  DL {m}: pred={v['prediction']} prob={v['probability']:.4f}\n")
            f.write("\n")
        except Exception as e:
            f.write(f"[ERROR] {url}: {e}\n\n")
print("Results saved to api_test_results.txt")
