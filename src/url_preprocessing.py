"""
URL Preprocessing for Deep Learning Branch

Handles:
1. Character-level tokenization
2. URL cleaning and normalization
3. Sequence padding/truncation
4. Creating training batches
"""

import numpy as np
import re
from typing import List, Tuple
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split


class URLTokenizer:
    """Character-level tokenizer for URLs"""
    
    def __init__(self, max_url_length: int = 200):
        """
        Args:
            max_url_length: Maximum URL length (truncate/pad to this)
        """
        self.max_url_length = max_url_length
        
        # Character vocabulary (ASCII printable + special tokens)
        self.char_to_idx = {
            '<PAD>': 0,
            '<UNK>': 1,
        }
        
        # Add ASCII printable characters (32-126)
        for i in range(32, 127):
            char = chr(i)
            self.char_to_idx[char] = len(self.char_to_idx)
        
        self.idx_to_char = {idx: char for char, idx in self.char_to_idx.items()}
        self.vocab_size = len(self.char_to_idx)
        
        print(f"URLTokenizer initialized with vocab_size={self.vocab_size}")
    
    def clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        # Convert to lowercase
        url = url.lower().strip()
        
        # Remove protocol if present (optional - keeps URL structure)
        # url = re.sub(r'^https?://', '', url)
        
        # Remove trailing slashes
        url = url.rstrip('/')
        
        return url
    
    def encode_url(self, url: str) -> List[int]:
        """
        Convert URL string to sequence of character indices
        
        Args:
            url: URL string
            
        Returns:
            List of character indices
        """
        url = self.clean_url(url)
        
        # Convert each character to index
        indices = []
        for char in url:
            if char in self.char_to_idx:
                indices.append(self.char_to_idx[char])
            else:
                indices.append(self.char_to_idx['<UNK>'])
        
        return indices
    
    def encode_batch(self, urls: List[str]) -> np.ndarray:
        """
        Encode a batch of URLs and pad/truncate to max_length
        
        Args:
            urls: List of URL strings
            
        Returns:
            Numpy array of shape (batch_size, max_url_length)
        """
        # Encode all URLs
        encoded = [self.encode_url(url) for url in urls]
        
        # Pad/truncate to max_length
        padded = pad_sequences(
            encoded,
            maxlen=self.max_url_length,
            padding='post',
            truncating='post',
            value=self.char_to_idx['<PAD>']
        )
        
        return padded
    
    def decode_url(self, indices: List[int]) -> str:
        """
        Convert sequence of indices back to URL string
        
        Args:
            indices: List of character indices
            
        Returns:
            URL string
        """
        chars = []
        for idx in indices:
            if idx == self.char_to_idx['<PAD>']:
                break  # Stop at padding
            if idx in self.idx_to_char:
                chars.append(self.idx_to_char[idx])
        
        return ''.join(chars)


class DLDataGenerator:
    """Data generator for Deep Learning branch"""
    
    def __init__(
        self,
        tokenizer: URLTokenizer,
        batch_size: int = 64,
        shuffle: bool = True
    ):
        self.tokenizer = tokenizer
        self.batch_size = batch_size
        self.shuffle = shuffle
    
    def prepare_dl_dataset(
        self,
        phishing_urls: List[str],
        legitimate_urls: List[str],
        test_size: float = 0.2,
        random_state: int = 42
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare DL training dataset from phishing + legitimate URLs
        
        Args:
            phishing_urls: List of phishing URLs
            legitimate_urls: List of legitimate URLs
            test_size: Ratio for validation split
            random_state: Random seed
            
        Returns:
            X_train, X_val, y_train, y_val
        """
        print(f"\nPreparing DL Dataset:")
        print(f"  - Phishing URLs: {len(phishing_urls):,}")
        print(f"  - Legitimate URLs: {len(legitimate_urls):,}")
        
        # Combine URLs and labels
        all_urls = phishing_urls + legitimate_urls
        all_labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
        
        # Encode URLs
        print(f"  - Encoding URLs (max_length={self.tokenizer.max_url_length})...")
        X = self.tokenizer.encode_batch(all_urls)
        y = np.array(all_labels)
        
        # Split
        X_train, X_val, y_train, y_val = train_test_split(
            X, y,
            test_size=test_size,
            stratify=y,
            random_state=random_state
        )
        
        print(f"  - Train: {len(X_train):,} samples (phishing: {y_train.sum():,})")
        print(f"  - Val:   {len(X_val):,} samples (phishing: {y_val.sum():,})")
        
        return X_train, X_val, y_train, y_val
    
    def create_batches(
        self,
        X: np.ndarray,
        y: np.ndarray
    ):
        """
        Create shuffled batches for training
        
        Yields:
            (X_batch, y_batch)
        """
        n_samples = len(X)
        indices = np.arange(n_samples)
        
        if self.shuffle:
            np.random.shuffle(indices)
        
        for start_idx in range(0, n_samples, self.batch_size):
            end_idx = min(start_idx + self.batch_size, n_samples)
            batch_indices = indices[start_idx:end_idx]
            
            yield X[batch_indices], y[batch_indices]


class URLFeatureExtractor:
    """Extract basic URL features for analysis"""
    
    @staticmethod
    def extract_features(url: str) -> dict:
        """Extract interpretable features from URL"""
        features = {}
        
        # Length
        features['url_length'] = len(url)
        
        # Domain-related
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Special characters
        features['has_at'] = int('@' in url)
        features['has_IP'] = int(any(char.isdigit() for char in url.split('/')[2]) if '/' in url else 0)
        
        # Entropy (randomness measure)
        features['entropy'] = URLFeatureExtractor.calculate_entropy(url)
        
        return features
    
    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of string"""
        from collections import Counter
        import math
        
        if not s:
            return 0.0
        
        counts = Counter(s)
        total = len(s)
        
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy


if __name__ == "__main__":
    # Example usage
    print("="*60)
    print("URL TOKENIZER DEMO")
    print("="*60)
    
    tokenizer = URLTokenizer(max_url_length=100)
    
    # Test URLs
    test_urls = [
        "http://paypal.com/login",
        "http://paypal-verify-account.tk/login",
        "https://secure.google.com",
        "http://g00gle.com"
    ]
    
    print("\nEncoding URLs:")
    for url in test_urls:
        encoded = tokenizer.encode_url(url)
        decoded = tokenizer.decode_url(encoded)
        print(f"  - Original: {url}")
        print(f"    Encoded length: {len(encoded)}")
        print(f"    Decoded: {decoded}")
        print()
    
    # Batch encoding
    print("\nBatch Encoding:")
    batch_encoded = tokenizer.encode_batch(test_urls)
    print(f"  Shape: {batch_encoded.shape}")
    print(f"  Sample (first URL): {batch_encoded[0][:50]}...")
