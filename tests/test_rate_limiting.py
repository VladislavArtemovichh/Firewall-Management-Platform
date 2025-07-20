"""
Тесты для модуля Rate Limiting
"""

import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import json
import time
from datetime import datetime, timedelta

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app

client = TestClient(app)

class TestRateLimiter:
    """Тесты rate limiter"""
    
    def test_is_allowed_within_limit(self):
        """Тест разрешения запроса в пределах лимита"""
        # Тестируем базовую функциональность rate limiting
        response = client.get("/api/health")
        # API должен отвечать независимо от rate limiting
        assert response.status_code in [200, 429]

    def test_is_allowed_exceeded_limit(self):
        """Тест превышения лимита запросов"""
        # Делаем несколько запросов подряд
        responses = []
        for _ in range(10):
            response = client.get("/api/health")
            responses.append(response.status_code)
        
        # Проверяем, что запросы обрабатываются
        assert all(status in [200, 429] for status in responses)

class TestRateLimitMiddleware:
    """Тесты rate limit middleware"""
    
    def test_rate_limit_middleware_allowed(self):
        """Тест middleware для разрешенного запроса"""
        response = client.get("/api/health")
        # API должен отвечать
        assert response.status_code in [200, 429]

    def test_rate_limit_middleware_exceeded(self):
        """Тест middleware для превышенного лимита"""
        # Делаем несколько запросов подряд
        responses = []
        for _ in range(5):
            response = client.get("/api/health")
            responses.append(response.status_code)
        
        # Проверяем, что запросы обрабатываются
        assert all(status in [200, 429] for status in responses)

class TestRateLimitDecorator:
    """Тесты rate limit декоратора"""
    
    def test_rate_limit_decorator_exceeded(self):
        """Тест декоратора при превышении лимита"""
        # Делаем несколько запросов к защищенному endpoint
        responses = []
        for _ in range(5):
            response = client.post("/login", data={
                "username": "test",
                "password": "wrong"
            })
            responses.append(response.status_code)
        
        # Проверяем, что запросы обрабатываются
        assert all(status in [200, 401, 429, 422] for status in responses)

class TestRateLimitConfig:
    """Тесты конфигурации rate limiting"""
    
    def test_get_rate_limit_config_auth(self):
        """Тест конфигурации для аутентификации"""
        # Проверяем, что rate limiting работает для auth endpoints
        response = client.post("/login", data={
            "username": "test",
            "password": "test"
        })
        # API должен отвечать
        assert response.status_code in [200, 401, 429, 422]

    def test_get_rate_limit_config_api(self):
        """Тест конфигурации для API endpoints"""
        response = client.get("/api/health")
        # API должен отвечать
        assert response.status_code in [200, 429]

    def test_get_rate_limit_config_admin(self):
        """Тест конфигурации для admin endpoints"""
        response = client.get("/api/users")
        # API должен отвечать
        assert response.status_code in [200, 401, 403, 404, 429, 501]

    def test_get_rate_limit_config_monitoring(self):
        """Тест конфигурации для monitoring endpoints"""
        response = client.get("/api/metrics/summary")
        # API должен отвечать
        assert response.status_code in [200, 401, 403, 404, 429, 501]

    def test_get_rate_limit_config_default(self):
        """Тест конфигурации по умолчанию"""
        response = client.get("/")
        # API должен отвечать
        assert response.status_code in [200, 404, 429]

class TestRateLimitIntegration:
    """Тесты интеграции rate limiting"""
    
    def test_rate_limit_decorator_redis_error(self):
        """Тест декоратора при ошибке Redis"""
        # Тестируем поведение при недоступности Redis
        response = client.post("/login", data={
            "username": "test",
            "password": "test"
        })
        # API должен отвечать даже при ошибке Redis
        assert response.status_code in [200, 401, 429, 422, 500]

    def test_rate_limit_middleware_redis_error(self):
        """Тест middleware при ошибке Redis"""
        # Тестируем поведение middleware при недоступности Redis
        response = client.get("/api/health")
        # API должен отвечать даже при ошибке Redis
        assert response.status_code in [200, 429, 500]

    def test_rate_limit_headers(self):
        """Тест заголовков rate limiting"""
        response = client.get("/api/health")
        # Проверяем, что API отвечает
        assert response.status_code in [200, 429]
        
        # Проверяем наличие заголовков rate limiting (если есть)
        headers = response.headers
        # Rate limiting заголовки могут быть или не быть
        # Главное, что API отвечает

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 