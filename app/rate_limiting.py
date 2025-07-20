import time
from datetime import datetime, timedelta

import redis.asyncio as redis
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class RateLimiter:
    """Rate Limiter с использованием Redis"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client: redis.Redis | None = None
        
    async def connect(self):
        """Подключение к Redis"""
        if not self.redis_client:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            await self.redis_client.ping()
    
    async def disconnect(self):
        """Отключение от Redis"""
        if self.redis_client:
            await self.redis_client.close()
    
    async def is_allowed(
        self, 
        key: str, 
        max_requests: int = 100, 
        window_seconds: int = 60
    ) -> tuple[bool, dict]:
        """
        Проверяет, разрешен ли запрос
        
        Args:
            key: Уникальный ключ (обычно IP адрес или user_id)
            max_requests: Максимальное количество запросов
            window_seconds: Временное окно в секундах
            
        Returns:
            (is_allowed, rate_limit_info)
        """
        await self.connect()
        
        current_time = int(time.time())
        window_start = current_time - window_seconds
        
        # Получаем все запросы в текущем окне
        pipeline = self.redis_client.pipeline()
        pipeline.zremrangebyscore(key, 0, window_start)
        pipeline.zadd(key, {str(current_time): current_time})
        pipeline.zcard(key)
        pipeline.expire(key, window_seconds)
        results = await pipeline.execute()
        
        current_requests = results[2]
        
        # Проверяем лимит
        is_allowed = current_requests <= max_requests
        
        # Вычисляем время до сброса
        reset_time = current_time + window_seconds
        
        rate_limit_info = {
            "limit": max_requests,
            "remaining": max(0, max_requests - current_requests),
            "reset": reset_time,
            "reset_time": datetime.fromtimestamp(reset_time).isoformat(),
            "current_requests": current_requests
        }
        
        return is_allowed, rate_limit_info

# Глобальный экземпляр Rate Limiter
rate_limiter = RateLimiter()

async def rate_limit_middleware(
    request: Request,
    call_next,
    max_requests: int = 100,
    window_seconds: int = 60,
    key_prefix: str = "rate_limit"
):
    """
    Middleware для Rate Limiting
    
    Args:
        request: FastAPI Request
        call_next: Следующий обработчик
        max_requests: Максимальное количество запросов
        window_seconds: Временное окно в секундах
        key_prefix: Префикс для ключа в Redis
    """
    
    # Получаем ключ для Rate Limiting
    client_ip = request.client.host
    user_id = getattr(request.state, "user_id", None)
    
    # Приоритет: user_id > IP адрес
    if user_id:
        rate_limit_key = f"{key_prefix}:user:{user_id}"
    else:
        rate_limit_key = f"{key_prefix}:ip:{client_ip}"
    
    try:
        # Проверяем лимит
        is_allowed, rate_limit_info = await rate_limiter.is_allowed(
            rate_limit_key, 
            max_requests, 
            window_seconds
        )
        
        if not is_allowed:
            # Превышен лимит запросов
            retry_after = rate_limit_info["reset"] - int(time.time())
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": "Превышен лимит запросов. Попробуйте позже.",
                    "retry_after": retry_after,
                    "rate_limit_info": rate_limit_info
                },
                headers={
                    "X-RateLimit-Limit": str(rate_limit_info["limit"]),
                    "X-RateLimit-Remaining": str(rate_limit_info["remaining"]),
                    "X-RateLimit-Reset": str(rate_limit_info["reset"]),
                    "Retry-After": str(retry_after)
                }
            )
        
        # Запрос разрешен, добавляем заголовки
        response = await call_next(request)
        
        # Добавляем заголовки Rate Limiting
        response.headers["X-RateLimit-Limit"] = str(rate_limit_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_limit_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rate_limit_info["reset"])
        
        return response
        
    except Exception as e:
        # В случае ошибки Redis, пропускаем Rate Limiting
        print(f"Rate Limiting error: {e}")
        return await call_next(request)

def rate_limit(
    max_requests: int = 100,
    window_seconds: int = 60,
    key_prefix: str = "rate_limit"
):
    """
    Декоратор для Rate Limiting конкретных endpoints
    
    Args:
        max_requests: Максимальное количество запросов
        window_seconds: Временное окно в секундах
        key_prefix: Префикс для ключа в Redis
    """
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Получаем ключ для Rate Limiting
            client_ip = request.client.host
            user_id = getattr(request.state, "user_id", None)
            
            if user_id:
                rate_limit_key = f"{key_prefix}:user:{user_id}"
            else:
                rate_limit_key = f"{key_prefix}:ip:{client_ip}"
            
            try:
                # Проверяем лимит
                is_allowed, rate_limit_info = await rate_limiter.is_allowed(
                    rate_limit_key, 
                    max_requests, 
                    window_seconds
                )
                
                if not is_allowed:
                    retry_after = rate_limit_info["reset"] - int(time.time())
                    
                    raise HTTPException(
                        status_code=429,
                        detail={
                            "error": "Too Many Requests",
                            "message": "Превышен лимит запросов. Попробуйте позже.",
                            "retry_after": retry_after,
                            "rate_limit_info": rate_limit_info
                        }
                    )
                
                # Запрос разрешен
                return await func(request, *args, **kwargs)
                
            except HTTPException:
                raise
            except Exception as e:
                # В случае ошибки Redis, пропускаем Rate Limiting
                print(f"Rate Limiting error: {e}")
                return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator

# Конфигурации Rate Limiting для разных типов endpoints
RATE_LIMIT_CONFIGS = {
    "default": {
        "max_requests": 100,
        "window_seconds": 60,
        "description": "Общий лимит для всех endpoints"
    },
    "auth": {
        "max_requests": 5,
        "window_seconds": 300,  # 5 минут
        "description": "Строгий лимит для аутентификации"
    },
    "api": {
        "max_requests": 1000,
        "window_seconds": 3600,  # 1 час
        "description": "Лимит для API endpoints"
    },
    "admin": {
        "max_requests": 1000,
        "window_seconds": 60,
        "description": "Лимит для административных функций"
    },
    "monitoring": {
        "max_requests": 10,
        "window_seconds": 60,
        "description": "Лимит для мониторинга"
    }
}

async def get_rate_limit_config(endpoint_path: str) -> dict:
    """
    Получает конфигурацию Rate Limiting для endpoint
    
    Args:
        endpoint_path: Путь к endpoint
        
    Returns:
        Конфигурация Rate Limiting
    """
    if "/auth/" in endpoint_path:
        return RATE_LIMIT_CONFIGS["auth"]
    elif "/api/" in endpoint_path:
        return RATE_LIMIT_CONFIGS["api"]
    elif "/admin/" in endpoint_path:
        return RATE_LIMIT_CONFIGS["admin"]
    elif "/metrics/" in endpoint_path or "/monitoring/" in endpoint_path:
        return RATE_LIMIT_CONFIGS["monitoring"]
    else:
        return RATE_LIMIT_CONFIGS["default"]

def setup_rate_limiting_middleware(app):
    """Настройка Rate Limiting middleware для приложения (должно быть вызвано до запуска)"""
    
    @app.middleware("http")
    async def rate_limit_middleware_wrapper(request: Request, call_next):
        # Получаем конфигурацию для текущего endpoint
        config = await get_rate_limit_config(request.url.path)
        
        return await rate_limit_middleware(
            request,
            call_next,
            max_requests=config["max_requests"],
            window_seconds=config["window_seconds"],
            key_prefix=f"rate_limit:{config['description'].lower().replace(' ', '_')}"
        )

async def setup_rate_limiting(app):
    """Настройка Rate Limiting для приложения (устаревшая функция)"""
    
    # Эта функция больше не нужна, так как middleware настраивается заранее
    # Оставляем для обратной совместимости
    pass
    
    # Добавляем endpoint для просмотра статистики Rate Limiting
    @app.get("/api/rate-limit/stats")
    async def get_rate_limit_stats():
        """Получить статистику Rate Limiting"""
        try:
            await rate_limiter.connect()
            
            # Получаем все ключи Rate Limiting
            keys = await rate_limiter.redis_client.keys("rate_limit:*")
            stats = {}
            
            for key in keys:
                # Получаем количество запросов для каждого ключа
                count = await rate_limiter.redis_client.zcard(key)
                ttl = await rate_limiter.redis_client.ttl(key)
                
                stats[key] = {
                    "current_requests": count,
                    "ttl_seconds": ttl,
                    "expires_at": datetime.now() + timedelta(seconds=ttl) if ttl > 0 else None
                }
            
            return {
                "total_keys": len(keys),
                "stats": stats,
                "configs": RATE_LIMIT_CONFIGS
            }
            
        except Exception as e:
            return {"error": f"Не удалось получить статистику: {e}"}
    
    @app.delete("/api/rate-limit/reset")
    async def reset_rate_limits():
        """Сбросить все Rate Limits (только для администраторов)"""
        try:
            await rate_limiter.connect()
            
            # Получаем все ключи Rate Limiting
            keys = await rate_limiter.redis_client.keys("rate_limit:*")
            
            if keys:
                # Удаляем все ключи
                await rate_limiter.redis_client.delete(*keys)
            
            return {
                "message": f"Сброшено {len(keys)} Rate Limits",
                "reset_keys": keys
            }
            
        except Exception as e:
            return {"error": f"Не удалось сбросить Rate Limits: {e}"} 