from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from .security import (
    check_login_attempts, 
    authenticate_user, 
    record_login_attempt, 
    clear_login_attempts,
    encode_error_message,
    decode_error_message
)
from .models import users, UserRole, get_role_name, next_user_id

templates = Jinja2Templates(directory="templates")

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
            response = RedirectResponse(url="/dashboard", status_code=303)
            response.set_cookie(key="username", value=username)
            return response

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
    def get_dashboard(request: Request):
        """Страница дашборда"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        return templates.TemplateResponse("dashboard.html", {"request": request, "user_role": user_role})

    @app.get("/nastroyki")
    def get_nastroyki(request: Request):
        """Страница управления пользователями"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return RedirectResponse(url="/dashboard", status_code=303)
        return templates.TemplateResponse("nastroyki.html", {"request": request})

    @app.get("/api/users")
    def get_users():
        """API для получения списка пользователей"""
        user_list = []
        for i, (username, user_data) in enumerate(users.items(), 1):
            user_list.append({
                "id": i,
                "login": username,
                "password": user_data["password"],
                "role": user_data["role"]
            })
        return JSONResponse(content=user_list)

    @app.post("/api/users")
    async def add_user(request: Request):
        """API для добавления нового пользователя"""
        form_data = await request.form()
        login = str(form_data.get("login", "")).strip()
        password = str(form_data.get("password", "")).strip()
        role = str(form_data.get("role", ""))
        
        # Валидация
        if len(login) < 3 or not login.replace("_", "").isalnum():
            return JSONResponse(content={"error": "Некорректный логин"}, status_code=400)
        
        if len(password) < 6:
            return JSONResponse(content={"error": "Пароль должен содержать не менее 6 символов"}, status_code=400)
        
        if role not in [r.value for r in UserRole]:
            return JSONResponse(content={"error": "Некорректная роль"}, status_code=400)
        
        if login in users:
            return JSONResponse(content={"error": "Пользователь с таким логином уже существует"}, status_code=400)
        
        # Добавляем пользователя
        users[login] = {
            "password": password,
            "role": UserRole(role)
        }
        
        return JSONResponse(content={"success": True})

    @app.put("/api/users/{user_id}")
    async def update_user_role(user_id: int, request: Request):
        """API для изменения роли пользователя"""
        form_data = await request.form()
        role = str(form_data.get("role", ""))
        
        if role not in [r.value for r in UserRole]:
            return JSONResponse(content={"error": "Некорректная роль"}, status_code=400)
        
        # Находим пользователя по ID
        user_list = list(users.items())
        if user_id <= 0 or user_id > len(user_list):
            return JSONResponse(content={"error": "Пользователь не найден"}, status_code=404)
        
        username = user_list[user_id - 1][0]
        users[username]["role"] = UserRole(role)
        
        return JSONResponse(content={"success": True})

    @app.delete("/api/users/{user_id}")
    def delete_user(user_id: int):
        """API для удаления пользователя"""
        user_list = list(users.items())
        if user_id <= 0 or user_id > len(user_list):
            return JSONResponse(content={"error": "Пользователь не найден"}, status_code=404)
        
        username = user_list[user_id - 1][0]
        del users[username]
        
        return JSONResponse(content={"success": True})

    @app.exception_handler(429)
    async def too_many_requests_handler(request: Request, exc: HTTPException):
        """Обработчик ошибки 429 (Too Many Requests)"""
        return RedirectResponse(url="/", status_code=303) 
