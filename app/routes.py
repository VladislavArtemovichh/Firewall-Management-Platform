from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from .security import (
    check_login_attempts, 
    authenticate_user, 
    record_login_attempt, 
    clear_login_attempts,
    encode_error_message,
    decode_error_message
)

templates = Jinja2Templates(directory=".")

def setup_routes(app: FastAPI):
    """Настраивает маршруты приложения"""
    
    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...)):
        """Обработчик входа пользователя"""
        # Проверяем блокировку
        lockout_response = check_login_attempts(username, request)
        if lockout_response:
            return lockout_response

        # Проверяем аутентификацию
        if authenticate_user(username, password):
            clear_login_attempts(username)
            return RedirectResponse(url="/dashboard", status_code=303)

        # Записываем неудачную попытку
        record_login_attempt(username)

        # Перенаправляем с ошибкой
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="error", value=encode_error_message("Неверный логин или пароль"), max_age=5)
        return response

    @app.get("/")
    def get_login_page(request: Request):
        """Главная страница с формой входа"""
        # Получаем ошибку из куки
        error = request.cookies.get("error")
        
        # Декодируем ошибку из base64
        if error:
            error = decode_error_message(error)
        
        # Создаём ответ
        response = templates.TemplateResponse("auth.html", {"request": request, "error": error})
        
        # Удаляем куки с ошибкой после отображения
        if error:
            response.delete_cookie("error")
        
        return response

    @app.get("/dashboard")
    def get_dashboard():
        """Страница дашборда"""
        return FileResponse("dashboard.html", media_type="text/html")

    @app.exception_handler(429)
    async def too_many_requests_handler(request: Request, exc: HTTPException):
        """Обработчик ошибки 429 (Too Many Requests)"""
        return RedirectResponse(url="/", status_code=303) 