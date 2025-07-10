import time
import base64
from fastapi import Request
from fastapi.responses import RedirectResponse
from .models import login_attempts, MAX_LOGIN_ATTEMPTS, LOCKOUT_TIME, users

def check_login_attempts(username: str, request: Request):
    """Проверяет количество попыток входа и блокирует при превышении лимита"""
    now = time.time()
    attempts = login_attempts[username]
    
    # Удаляем устаревшие попытки
    attempts = [attempt for attempt in attempts if now - attempt < LOCKOUT_TIME]
    login_attempts[username] = attempts
    
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        remaining_time = LOCKOUT_TIME - (now - attempts[0]) if attempts else LOCKOUT_TIME
        minutes = int(remaining_time // 60)
        
        error_message = f"Слишком много попыток входа. Попробуйте через {minutes} мин"
        
        # Перенаправляем на главную страницу с ошибкой в куки
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="error", value=base64.b64encode(error_message.encode('utf-8')).decode('ascii'), max_age=5)
        return response
    return None

def authenticate_user(username: str, password: str):
    """Аутентифицирует пользователя"""
    return username in users and users[username] == password

def record_login_attempt(username: str):
    """Записывает попытку входа"""
    login_attempts[username].append(time.time())

def clear_login_attempts(username: str):
    """Очищает попытки входа для пользователя"""
    login_attempts[username].clear()

def encode_error_message(message: str) -> str:
    """Кодирует сообщение об ошибке в base64 для сохранения в куки"""
    return base64.b64encode(message.encode('utf-8')).decode('ascii')

def decode_error_message(encoded_message: str) -> str:
    """Декодирует сообщение об ошибке из base64"""
    try:
        return base64.b64decode(encoded_message.encode('ascii')).decode('utf-8')
    except:
        return "Ошибка декодирования" 