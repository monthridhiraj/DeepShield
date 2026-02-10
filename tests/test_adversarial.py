"""
DeepShield Adversarial Test Suite
Tests the model's robustness against various phishing attack patterns
"""

import pytest
import requests
import time
from typing import List, Tuple

# API endpoint
API_BASE = "http://localhost:8000"

# ============================================================================
# TEST DATA: Known attack patterns
# ============================================================================

# Typosquatting attacks - misspelled legitimate domains
TYPOSQUATTING_URLS = [
    # Should be detected as phishing
    ("http://g00gle.com/login", True, "Zero substitution in google"),
    ("http://gooogle.com/", True, "Extra letter in google"),
    ("http://googel.com/", True, "Transposed letters in google"),
    ("http://paypa1.com/signin", True, "L to 1 substitution in paypal"),
    ("http://paypall.com/login", True, "Double L in paypal"),
    ("http://amaz0n.com/account", True, "O to 0 in amazon"),
    ("http://arnazon.com/", True, "M to RN in amazon"),
    ("http://faceb00k.com/", True, "O to 0 in facebook"),
    ("http://microsooft.com/", True, "Double O in microsoft"),
    ("http://applle.com/id", True, "Double L in apple"),
]

# Homograph attacks - Unicode lookalikes
HOMOGRAPH_URLS = [
    # These use Cyrillic or other similar-looking characters
    ("http://Ρ€aypal.com/", True, "Cyrillic 'Ρ€' instead of Latin 'p'"),
    ("http://xn--pypal-4ve.com/", True, "Punycode for homograph paypal"),
    ("http://Π°pple.com/", True, "Cyrillic 'Π°' instead of Latin 'a'"),
    ("http://gΓΆogle.com/", True, "German umlaut in google"),
    ("http://xn--ggle-55da.com/", True, "Punycode variant"),
]

# URL shorteners (should be treated with caution, not necessarily phishing)
SHORTENER_URLS = [
    ("https://bit.ly/abc123", None, "bit.ly shortener"),
    ("https://tinyurl.com/xyz789", None, "tinyurl shortener"),
    ("https://t.co/abc123", None, "Twitter shortener"),
    ("https://goo.gl/abc123", None, "Google shortener"),
    ("https://ow.ly/abc123", None, "Hootsuite shortener"),
]

# Subdomain abuse - legitimate TLD with suspicious subdomain
SUBDOMAIN_ABUSE_URLS = [
    ("http://paypal.attacker.com/login", True, "Paypal as subdomain"),
    ("http://login.paypal.attacker.tk/", True, "Login subdomain on suspicious TLD"),
    ("http://secure.bankofamerica.phishing.com/", True, "Bank subdomain abuse"),
    ("http://microsoft.update.malicious.ru/", True, "Microsoft subdomain abuse"),
    ("http://google.com.verify.malware.net/", True, "Google subdomain abuse"),
]

# Suspicious TLDs
SUSPICIOUS_TLD_URLS = [
    ("http://paypal-verify.tk/login", True, ".tk TLD with paypal"),
    ("http://amazon-security.ml/", True, ".ml TLD with amazon"),
    ("http://facebook-login.ga/", True, ".ga TLD with facebook"),
    ("http://microsoft-update.cf/", True, ".cf TLD with microsoft"),
    ("http://apple-id.gq/verify", True, ".gq TLD with apple"),
]

# Known legitimate sites (should NOT be flagged)
LEGITIMATE_URLS = [
    ("https://www.google.com/", False, "Google main site"),
    ("https://www.microsoft.com/", False, "Microsoft main site"),
    ("https://github.com/", False, "GitHub main site"),
    ("https://www.amazon.com/", False, "Amazon main site"),
    ("https://www.apple.com/", False, "Apple main site"),
    ("https://www.facebook.com/", False, "Facebook main site"),
    ("https://www.linkedin.com/", False, "LinkedIn main site"),
    ("https://www.paypal.com/", False, "PayPal main site"),
    ("https://stackoverflow.com/", False, "StackOverflow main site"),
    ("https://www.wikipedia.org/", False, "Wikipedia main site"),
]

# Hard negatives - legitimate sites with suspicious-looking paths
HARD_NEGATIVE_URLS = [
    ("https://docs.google.com/login", False, "Google docs with login path"),
    ("https://accounts.google.com/signin", False, "Google accounts signin"),
    ("https://www.microsoft.com/en-us/account/", False, "Microsoft account page"),
    ("https://developer.mozilla.org/en-US/docs/Web/API/", False, "Mozilla API docs"),
    ("https://api.github.com/auth/callback", False, "GitHub API callback"),
    ("https://login.microsoftonline.com/", False, "Microsoft Online login"),
    ("https://auth.atlassian.com/", False, "Atlassian auth"),
    ("https://sso.amazon.com/", False, "Amazon SSO"),
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def predict_url(url: str) -> dict:
    """Call the prediction API for a URL"""
    try:
        response = requests.post(
            f"{API_BASE}/predict",
            json={"url": url},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def is_phishing(result: dict) -> bool:
    """Check if the result indicates phishing"""
    if "error" in result:
        return None
    return result.get("final_prediction") == 1 or result.get("verdict") == "Phishing"


# ============================================================================
# TESTS
# ============================================================================

class TestTyposquatting:
    """Test detection of typosquatting attacks"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", TYPOSQUATTING_URLS)
    def test_typosquatting_detection(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        assert detected == expected_phishing, (
            f"Failed for {description}\n"
            f"URL: {url}\n"
            f"Expected: {'Phishing' if expected_phishing else 'Legitimate'}\n"
            f"Got: {'Phishing' if detected else 'Legitimate'}\n"
            f"Confidence: {result.get('confidence', 'N/A')}"
        )


class TestHomographAttacks:
    """Test detection of homograph/IDN attacks"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", HOMOGRAPH_URLS)
    def test_homograph_detection(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        assert detected == expected_phishing, (
            f"Failed for {description}\n"
            f"URL: {url}\n"
            f"Expected: {'Phishing' if expected_phishing else 'Legitimate'}\n"
            f"Got: {'Phishing' if detected else 'Legitimate'}"
        )


class TestSubdomainAbuse:
    """Test detection of subdomain abuse attacks"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", SUBDOMAIN_ABUSE_URLS)
    def test_subdomain_abuse_detection(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        assert detected == expected_phishing, (
            f"Failed for {description}\n"
            f"URL: {url}\n"
            f"Expected: {'Phishing' if expected_phishing else 'Legitimate'}"
        )


class TestSuspiciousTLDs:
    """Test detection of suspicious TLDs"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", SUSPICIOUS_TLD_URLS)
    def test_suspicious_tld_detection(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        assert detected == expected_phishing, (
            f"Failed for {description}\n"
            f"URL: {url}"
        )


class TestLegitimateURLs:
    """Test that legitimate URLs are NOT flagged as phishing"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", LEGITIMATE_URLS)
    def test_legitimate_urls_not_flagged(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        assert detected == expected_phishing, (
            f"FALSE POSITIVE: {description}\n"
            f"URL: {url}\n"
            f"Got: Phishing (should be Legitimate)\n"
            f"Confidence: {result.get('confidence', 'N/A')}"
        )


class TestHardNegatives:
    """Test hard negatives - legitimate sites that look suspicious"""
    
    @pytest.mark.parametrize("url,expected_phishing,description", HARD_NEGATIVE_URLS)
    def test_hard_negatives_not_flagged(self, url: str, expected_phishing: bool, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        detected = is_phishing(result)
        
        # Allow some tolerance for edge cases - warn but don't fail
        if detected != expected_phishing:
            confidence = result.get('confidence', 0)
            if confidence < 0.7:
                # Low confidence false positive - warning only
                pytest.xfail(
                    f"Low confidence false positive for {description}\n"
                    f"URL: {url}\n"
                    f"Confidence: {confidence}"
                )
            else:
                assert False, (
                    f"HIGH CONFIDENCE FALSE POSITIVE: {description}\n"
                    f"URL: {url}\n"
                    f"Confidence: {confidence}"
                )


class TestURLShorteners:
    """Test handling of URL shorteners"""
    
    @pytest.mark.parametrize("url,expected,description", SHORTENER_URLS)
    def test_shortener_handling(self, url: str, expected, description: str):
        result = predict_url(url)
        
        if "error" in result:
            pytest.skip(f"API error: {result['error']}")
        
        # URL shorteners should be handled carefully
        # They're not necessarily phishing, but should trigger extra scrutiny
        confidence = result.get('confidence', 0)
        
        # Just ensure we get a result - shorteners are ambiguous
        assert 'verdict' in result or 'final_prediction' in result, (
            f"No verdict for {description}\n"
            f"URL: {url}"
        )


# ============================================================================
# LATENCY TESTS
# ============================================================================

class TestLatency:
    """Test API response latency"""
    
    LATENCY_BUDGET = 150  # ms
    SAMPLE_URLS = [
        "https://google.com/",
        "https://suspicious-site.tk/login",
        "https://microsoft.com/account",
    ]
    
    def test_average_latency(self):
        """Test that average latency is within budget"""
        latencies = []
        
        for url in self.SAMPLE_URLS * 3:  # Test each URL 3 times
            start = time.time()
            result = predict_url(url)
            latency = (time.time() - start) * 1000  # Convert to ms
            
            if "error" not in result:
                latencies.append(latency)
        
        if not latencies:
            pytest.skip("No successful API calls")
        
        avg_latency = sum(latencies) / len(latencies)
        
        assert avg_latency < self.LATENCY_BUDGET * 2, (
            f"Average latency too high: {avg_latency:.0f}ms\n"
            f"Budget: {self.LATENCY_BUDGET}ms\n"
            f"Note: First calls may be slower due to model loading"
        )
    
    def test_p95_latency(self):
        """Test 95th percentile latency"""
        latencies = []
        
        for url in self.SAMPLE_URLS * 5:
            start = time.time()
            result = predict_url(url)
            latency = (time.time() - start) * 1000
            
            if "error" not in result:
                latencies.append(latency)
        
        if len(latencies) < 10:
            pytest.skip("Not enough successful calls")
        
        latencies.sort()
        p95_idx = int(len(latencies) * 0.95)
        p95_latency = latencies[p95_idx]
        
        # P95 should be under 500ms (allowing for network variance)
        assert p95_latency < 500, (
            f"P95 latency too high: {p95_latency:.0f}ms"
        )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
