"""
Тесты для модуля Rate Limiting
"""

import pytest
import time
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from app.rate_limiting import (
    RateLimiter, 
    rate_limit_middleware, 
    rate_limit, 
    get_rate_limit_config,
    RATE_LIMIT_CONFIGS
)


class TestRateLimiter:
    """Тесты для класса RateLimiter"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.rate_limiter = RateLimiter("redis://localhost:6379")
    
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Тест успешного подключения к Redis"""
        with patch('redis.asyncio.Redis.from_url') as mock_redis:
            mock_client = Mock()
            mock_client.ping = AsyncMock(return_value=True)
            mock_redis.return_value = mock_client
            
            await self.rate_limiter.connect()
            
            assert self.rate_limiter.redis_client is not None
            mock_client.ping.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Тест неудачного подключения к Redis"""
        with patch('redis.asyncio.Redis.from_url') as mock_redis:
            mock_client = Mock()
            mock_client.ping = AsyncMock(side_effect=Exception("Connection failed"))
            mock_redis.return_value = mock_client
            
            with pytest.raises(Exception, match="Connection failed"):
                await self.rate_limiter.connect()
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Тест отключения от Redis"""
        with patch('redis.asyncio.Redis.from_url') as mock_redis:
            mock_client = Mock()
            mock_client.close = AsyncMock()
            mock_redis.return_value = mock_client
            
            self.rate_limiter.redis_client = mock_client
            await self.rate_limiter.disconnect()
            
            mock_client.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_is_allowed_within_limit(self):
        """Тест запроса в пределах лимита"""
        with patch('redis.asyncio.Redis.from_url') as mock_redis:
            mock_client = Mock()
            mock_client.ping = AsyncMock(return_value=True)
            mock_client.pipeline.return_value = Mock()
            
            pipeline_mock = Mock()
            pipeline_mock.zremrangebyscore.return_value = pipeline_mock
            pipeline_mock.zadd.return_value = pipeline_mock
            pipeline_mock.zcard.return_value = pipeline_mock
            pipeline_mock.expire.return_value = pipeline_mock
            pipeline_mock.execute.return_value = [0, 1, 5, True]  # current_requests = 5
            
            mock_client.pipeline.return_value = pipeline_mock
            mock_redis.return_value = mock_client
            
            self.rate_limiter.redis_client = mock_client
            
            is_allowed, info = await self.rate_limiter.is_allowed("test_key", 10, 60)
            
            assert is_allowed is True
            assert info['current_requests'] == 5
            assert info['remaining'] == 5
            assert info['limit'] == 10
    
    @pytest.mark.asyncio
    async def test_is_allowed_exceeded_limit(self):
        """Тест запроса превышающего лимит"""
        with patch('redis.asyncio.Redis.from_url') as mock_redis:
            mock_client = Mock()
            mock_client.ping = AsyncMock(return_value=True)
            mock_client.pipeline.return_value = Mock()
            
            pipeline_mock = Mock()
            pipeline_mock.zremrangebyscore.return_value = pipeline_mock
            pipeline_mock.zadd.return_value = pipeline_mock
            pipeline_mock.zcard.return_value = pipeline_mock
            pipeline_mock.expire.return_value = pipeline_mock
            pipeline_mock.execute.return_value = [0, 1, 15, True]  # current_requests = 15
            
            mock_client.pipeline.return_value = pipeline_mock
            mock_redis.return_value = mock_client
            
            self.rate_limiter.redis_client = mock_client
            
            is_allowed, info = await self.rate_limiter.is_allowed("test_key", 10, 60)
            
            assert is_allowed is False
            assert info['current_requests'] == 15
            assert info['remaining'] == 0
            assert info['limit'] == 10


class TestRateLimitMiddleware:
    """Тесты для middleware Rate Limiting"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_allowed(self):
        """Тест middleware когда запрос разрешен"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        call_next = AsyncMock()
        call_next.return_value = Mock()
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = (True, {
                'limit': 100,
                'remaining': 95,
                'reset': int(time.time()) + 60,
                'reset_time': '2022-01-01T12:00:00',
                'current_requests': 5
            })
            
            response = await rate_limit_middleware(request, call_next)
            
            assert response is not None
            assert response.headers["X-RateLimit-Limit"] == "100"
            assert response.headers["X-RateLimit-Remaining"] == "95"
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_exceeded(self):
        """Тест middleware когда превышен лимит"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        call_next = AsyncMock()
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = (False, {
                'limit': 100,
                'remaining': 0,
                'reset': int(time.time()) + 60,
                'reset_time': '2022-01-01T12:00:00',
                'current_requests': 100
            })
            
            response = await rate_limit_middleware(request, call_next)
            
            assert isinstance(response, JSONResponse)
            assert response.status_code == 429
            assert "Too Many Requests" in response.body.decode()
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_with_user_id(self):
        """Тест middleware с user_id"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = 123
        
        call_next = AsyncMock()
        call_next.return_value = Mock()
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = (True, {
                'limit': 100,
                'remaining': 95,
                'reset': int(time.time()) + 60,
                'reset_time': '2022-01-01T12:00:00',
                'current_requests': 5
            })
            
            await rate_limit_middleware(request, call_next)
            
            # Проверяем, что ключ содержит user_id
            call_args = mock_limiter.is_allowed.call_args[0]
            assert "user:123" in call_args[0]


class TestRateLimitDecorator:
    """Тесты для декоратора rate_limit"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_allowed(self):
        """Тест декоратора когда запрос разрешен"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        @rate_limit(max_requests=10, window_seconds=60)
        async def test_function(request, param):
            return {"result": "success", "param": param}
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = (True, {
                'limit': 10,
                'remaining': 5,
                'reset': int(time.time()) + 60,
                'reset_time': '2022-01-01T12:00:00',
                'current_requests': 5
            })
            
            result = await test_function(request, "test_param")
            
            assert result["result"] == "success"
            assert result["param"] == "test_param"
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_exceeded(self):
        """Тест декоратора когда превышен лимит"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        @rate_limit(max_requests=10, window_seconds=60)
        async def test_function(request, param):
            return {"result": "success", "param": param}
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.return_value = (False, {
                'limit': 10,
                'remaining': 0,
                'reset': int(time.time()) + 60,
                'reset_time': '2022-01-01T12:00:00',
                'current_requests': 10
            })
            
            with pytest.raises(HTTPException) as exc_info:
                await test_function(request, "test_param")
            
            assert exc_info.value.status_code == 429
            assert "Too Many Requests" in str(exc_info.value.detail)


class TestRateLimitConfig:
    """Тесты для конфигурации Rate Limiting"""
    
    def test_get_rate_limit_config_auth(self):
        """Тест конфигурации для аутентификации"""
        config = get_rate_limit_config("/auth/login")
        assert config == RATE_LIMIT_CONFIGS["auth"]
        assert config["max_requests"] == 5
        assert config["window_seconds"] == 300
    
    def test_get_rate_limit_config_api(self):
        """Тест конфигурации для API"""
        config = get_rate_limit_config("/api/firewall-rules")
        assert config == RATE_LIMIT_CONFIGS["api"]
        assert config["max_requests"] == 1000
        assert config["window_seconds"] == 3600
    
    def test_get_rate_limit_config_admin(self):
        """Тест конфигурации для админ функций"""
        config = get_rate_limit_config("/admin/users")
        assert config == RATE_LIMIT_CONFIGS["admin"]
        assert config["max_requests"] == 1000
        assert config["window_seconds"] == 60
    
    def test_get_rate_limit_config_monitoring(self):
        """Тест конфигурации для мониторинга"""
        config = get_rate_limit_config("/metrics")
        assert config == RATE_LIMIT_CONFIGS["monitoring"]
        assert config["max_requests"] == 10
        assert config["window_seconds"] == 60
    
    def test_get_rate_limit_config_default(self):
        """Тест конфигурации по умолчанию"""
        config = get_rate_limit_config("/some/random/path")
        assert config == RATE_LIMIT_CONFIGS["default"]
        assert config["max_requests"] == 100
        assert config["window_seconds"] == 60
    
    def test_rate_limit_configs_structure(self):
        """Тест структуры конфигураций"""
        required_keys = ["max_requests", "window_seconds", "description"]
        
        for config_name, config in RATE_LIMIT_CONFIGS.items():
            for key in required_keys:
                assert key in config, f"Missing key '{key}' in config '{config_name}'"
            
            assert isinstance(config["max_requests"], int)
            assert isinstance(config["window_seconds"], int)
            assert isinstance(config["description"], str)
            assert config["max_requests"] > 0
            assert config["window_seconds"] > 0


class TestRateLimitIntegration:
    """Интеграционные тесты Rate Limiting"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_redis_error(self):
        """Тест middleware при ошибке Redis"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        call_next = AsyncMock()
        call_next.return_value = Mock()
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.side_effect = Exception("Redis connection failed")
            
            # При ошибке Redis middleware должен пропустить запрос
            response = await rate_limit_middleware(request, call_next)
            
            assert response is not None
            call_next.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_redis_error(self):
        """Тест декоратора при ошибке Redis"""
        request = Mock()
        request.client.host = "192.168.1.1"
        request.state.user_id = None
        
        @rate_limit(max_requests=10, window_seconds=60)
        async def test_function(request, param):
            return {"result": "success", "param": param}
        
        with patch('app.rate_limiting.rate_limiter') as mock_limiter:
            mock_limiter.is_allowed.side_effect = Exception("Redis connection failed")
            
            # При ошибке Redis декоратор должен пропустить запрос
            result = await test_function(request, "test_param")
            
            assert result["result"] == "success"
            assert result["param"] == "test_param"


# Фикстуры для тестов
@pytest.fixture
def mock_redis_client():
    """Фикстура для мока Redis клиента"""
    with patch('redis.asyncio.Redis.from_url') as mock_redis:
        mock_client = Mock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_redis.return_value = mock_client
        yield mock_client


@pytest.fixture
def sample_request():
    """Фикстура для тестового запроса"""
    request = Mock()
    request.client.host = "192.168.1.1"
    request.state.user_id = None
    return request


@pytest.fixture
def sample_rate_limit_info():
    """Фикстура для информации о Rate Limiting"""
    return {
        'limit': 100,
        'remaining': 95,
        'reset': int(time.time()) + 60,
        'reset_time': '2022-01-01T12:00:00',
        'current_requests': 5
    } 