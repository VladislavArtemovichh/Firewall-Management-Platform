from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from .database import update_user_activity
from .metrics import metrics_collector
import asyncio
import time

class ActivityTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware для отслеживания активности пользователей"""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Исключаем статические файлы и API-запросы активности
        if (not request.url.path.startswith('/static') and 
            request.url.path != '/api/user-activity' and
            request.url.path != '/api/online-users' and
            request.url.path != '/api/user-sessions'):
            
            session_token = request.cookies.get("session_token")
            if session_token:
                # Обновляем активность пользователя асинхронно
                try:
                    await update_user_activity(session_token)
                except Exception as e:
                    print(f"Ошибка при обновлении активности: {e}")
        
        response = await call_next(request)
        
        # Записываем метрики запроса
        response_time = time.time() - start_time
        is_error = response.status_code >= 400
        error_code = response.status_code if is_error else None
        
        try:
            metrics_collector.record_request(response_time, is_error, error_code)
        except Exception as e:
            print(f"Ошибка при записи метрик запроса: {e}")
        
        return response

def setup_middleware(app: FastAPI):
    """Настраивает middleware для приложения"""
    
    # Добавляем middleware для отслеживания активности
    app.add_middleware(ActivityTrackingMiddleware)
    
    # Разрешаем CORS для тестирования (можно убрать в продакшене)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    ) 