import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_health_endpoint():
    """Простой тест health endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"

def test_favicon_endpoint():
    """Тест favicon endpoint"""
    response = client.get("/favicon.ico")
    assert response.status_code == 200

@pytest.mark.timeout(5)
def test_quick_performance():
    """Быстрый тест производительности"""
    import time
    start_time = time.time()
    response = client.get("/api/health")
    end_time = time.time()
    
    assert response.status_code == 200
    assert (end_time - start_time) < 1.0  # Должен выполниться менее чем за 1 секунду 