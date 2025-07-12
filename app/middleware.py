from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from .database import update_user_activity
import asyncio

class ActivityTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware для отслеживания активности пользователей"""
    
    async def dispatch(self, request: Request, call_next):
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