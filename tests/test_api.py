"""
DeepShield API Integration Tests
Tests the API endpoints and model integration
"""

import pytest
import requests
import json

API_BASE = "http://localhost:8000"


class TestHealthEndpoint:
    """Test the /health endpoint"""
    
    def test_health_check(self):
        response = requests.get(f"{API_BASE}/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "models_loaded" in data
        assert "total_models" in data
    
    def test_health_models_loaded(self):
        response = requests.get(f"{API_BASE}/health")
        data = response.json()
        
        # Should have at least one model loaded
        assert data["total_models"] >= 1, "No models loaded"


class TestPredictEndpoint:
    """Test the /predict endpoint"""
    
    def test_predict_valid_url(self):
        response = requests.post(
            f"{API_BASE}/predict",
            json={"url": "https://www.google.com"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "verdict" in data
        assert "confidence" in data
        assert "final_prediction" in data
        assert data["verdict"] in ["Phishing", "Legitimate"]
    
    def test_predict_phishing_url(self):
        response = requests.post(
            f"{API_BASE}/predict",
            json={"url": "http://paypal-verify.tk/login"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "verdict" in data
        assert "confidence" in data
    
    def test_predict_returns_model_details(self):
        response = requests.post(
            f"{API_BASE}/predict",
            json={"url": "https://example.com"}
        )
        assert response.status_code == 200
        
        data = response.json()
        
        # Should include model breakdown
        assert "ml_models" in data or "dl_models" in data
    
    def test_predict_missing_url(self):
        response = requests.post(
            f"{API_BASE}/predict",
            json={}
        )
        # Should return 422 for validation error
        assert response.status_code == 422
    
    def test_predict_invalid_json(self):
        response = requests.post(
            f"{API_BASE}/predict",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


class TestModelsEndpoint:
    """Test the /models endpoint"""
    
    def test_list_models(self):
        response = requests.get(f"{API_BASE}/models")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        
        # Check model structure
        if len(data) > 0:
            model = data[0]
            assert "name" in model
            assert "type" in model
            assert "status" in model


class TestCORS:
    """Test CORS headers for extension compatibility"""
    
    def test_cors_headers_present(self):
        response = requests.options(
            f"{API_BASE}/predict",
            headers={
                "Origin": "chrome-extension://abc123",
                "Access-Control-Request-Method": "POST"
            }
        )
        
        # Should allow the request
        headers = response.headers
        assert "access-control-allow-origin" in headers or response.status_code in [200, 204]


class TestResponseFormat:
    """Test response format consistency"""
    
    def test_predict_response_structure(self):
        response = requests.post(
            f"{API_BASE}/predict",
            json={"url": "https://www.example.com"}
        )
        data = response.json()
        
        # Verify required fields
        required_fields = ["url", "verdict", "confidence", "final_prediction"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        # Verify types
        assert isinstance(data["url"], str)
        assert isinstance(data["verdict"], str)
        assert isinstance(data["confidence"], (int, float))
        assert isinstance(data["final_prediction"], int)
        
        # Verify value ranges
        assert 0 <= data["confidence"] <= 1
        assert data["final_prediction"] in [0, 1]
        assert data["verdict"] in ["Phishing", "Legitimate"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
