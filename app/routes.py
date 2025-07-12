from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import asyncpg
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
from .security import (
    check_login_attempts, 
    authenticate_user, 
    record_login_attempt, 
    clear_login_attempts,
    encode_error_message,
    decode_error_message
)
from .models import users, UserRole, get_role_name, next_user_id
from .database import (
    get_online_users, 
    get_user_sessions, 
    create_user_session, 
    update_user_activity,
    logout_user_session,
    get_user_id_by_username,
    cleanup_anomalous_sessions,
    cleanup_user_sessions
)

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
            
            # Создаём сессию пользователя
            import secrets
            session_token = secrets.token_urlsafe(32)
            
            # Получаем ID пользователя из базы данных
            try:
                user_id = await get_user_id_by_username(username)
                if user_id:
                    ip_address = request.client.host if request.client else None
                    user_agent = request.headers.get("user-agent")
                    await create_user_session(user_id, session_token, ip_address, user_agent)
                else:
                    print(f"Пользователь {username} не найден в базе данных")
            except Exception as e:
                print(f"Ошибка при создании сессии: {e}")
            
            response = RedirectResponse(url="/dashboard", status_code=303)
            response.set_cookie(key="username", value=username)
            response.set_cookie(key="session_token", value=session_token)
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
        if not username or username not in users:
            return RedirectResponse(url="/", status_code=303)
        user_role = users[username]["role"].value
        return templates.TemplateResponse("dashboard.html", {"request": request, "user_role": user_role})

    @app.get("/logout")
    async def logout(request: Request):
        """Обработчик выхода пользователя"""
        session_token = request.cookies.get("session_token")
        if session_token:
            try:
                await logout_user_session(session_token)
            except Exception as e:
                print(f"Ошибка при завершении сессии: {e}")
        
        response = RedirectResponse(url="/", status_code=303)
        response.delete_cookie("username")
        response.delete_cookie("session_token")
        return response

    @app.get("/settings")
    def get_settings(request: Request):
        """Страница управления пользователями"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return RedirectResponse(url="/dashboard", status_code=303)
        return templates.TemplateResponse("settings.html", {"request": request})

    @app.get("/event-log")
    async def get_event_log(request: Request):
        """Страница журнала событий"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return RedirectResponse(url="/dashboard", status_code=303)
        
        # Получаем пользователей из базы данных
        try:
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            
            db_users = await conn.fetch('SELECT id, username, password FROM users ORDER BY id')
            await conn.close()
            
            # Подготавливаем данные пользователей для шаблона
            user_list = []
            for db_user in db_users:
                # Получаем роль из памяти (пока не перенесли роли в БД)
                role = users.get(db_user['username'], {}).get('role', UserRole.NETWORK_AUDITOR)
                user_list.append({
                    "id": db_user['id'],
                    "login": db_user['username'],
                    "password": db_user['password'],
                    "role": role.value,
                    "role_name": get_role_name(role)
                })
            
        except Exception as e:
            print(f"Ошибка при получении пользователей: {e}")
            # Fallback к данным из памяти
            user_list = []
            for i, (username, user_data) in enumerate(users.items(), 1):
                user_list.append({
                    "id": i,
                    "login": username,
                    "password": user_data["password"],
                    "role": user_data["role"].value,
                    "role_name": get_role_name(user_data["role"])
                })
        
        return templates.TemplateResponse("event_log.html", {
            "request": request, 
            "users": user_list,
            "user_role": user_role
        })

    @app.get("/api/users")
    async def get_users():
        """API для получения списка пользователей"""
        try:
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            
            db_users = await conn.fetch('SELECT id, username, password, role FROM users ORDER BY id')
            await conn.close()
            
            user_list = []
            for db_user in db_users:
                user_list.append({
                    "id": db_user['id'],
                    "login": db_user['username'],
                    "password": db_user['password'],
                    "role": db_user['role']
                })
            
            return JSONResponse(content=user_list)
            
        except Exception as e:
            print(f"Ошибка при получении пользователей из БД: {e}")
            # Fallback к данным из памяти
            user_list = []
            for i, (username, user_data) in enumerate(users.items(), 1):
                user_list.append({
                    "id": i,
                    "login": username,
                    "password": user_data["password"],
                    "role": user_data["role"].value
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
        
        try:
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            
            # Проверяем, существует ли пользователь
            existing_user = await conn.fetchval('SELECT id FROM users WHERE username = $1', login)
            if existing_user:
                await conn.close()
                return JSONResponse(content={"error": "Пользователь с таким логином уже существует"}, status_code=400)
            
            # Добавляем пользователя в базу данных
            await conn.execute('''
                INSERT INTO users (username, password, role)
                VALUES ($1, $2, $3)
            ''', login, password, role)
            
            await conn.close()
            return JSONResponse(content={"success": True})
            
        except Exception as e:
            print(f"Ошибка при добавлении пользователя: {e}")
            return JSONResponse(content={"error": "Ошибка при добавлении пользователя"}, status_code=500)

    @app.put("/api/users/{user_id}")
    async def update_user_role(user_id: int, request: Request):
        """API для изменения роли пользователя"""
        form_data = await request.form()
        role = str(form_data.get("role", ""))
        
        if role not in [r.value for r in UserRole]:
            return JSONResponse(content={"error": "Некорректная роль"}, status_code=400)
        
        try:
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            
            # Обновляем роль пользователя в базе данных
            result = await conn.execute('''
                UPDATE users SET role = $1 WHERE id = $2
            ''', role, user_id)
            
            await conn.close()
            
            if result == "UPDATE 0":
                return JSONResponse(content={"error": "Пользователь не найден"}, status_code=404)
            
            return JSONResponse(content={"success": True})
            
        except Exception as e:
            print(f"Ошибка при обновлении роли пользователя: {e}")
            return JSONResponse(content={"error": "Ошибка при обновлении роли"}, status_code=500)

    @app.delete("/api/users/{user_id}")
    async def delete_user(user_id: int):
        """API для удаления пользователя"""
        try:
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            
            # Удаляем пользователя из базы данных
            result = await conn.execute('''
                DELETE FROM users WHERE id = $1
            ''', user_id)
            
            await conn.close()
            
            if result == "DELETE 0":
                return JSONResponse(content={"error": "Пользователь не найден"}, status_code=404)
            
            return JSONResponse(content={"success": True})
            
        except Exception as e:
            print(f"Ошибка при удалении пользователя: {e}")
            return JSONResponse(content={"error": "Ошибка при удалении пользователя"}, status_code=500)

    @app.get("/api/online-users")
    async def get_online_users_api():
        """API для получения списка пользователей онлайн"""
        try:
            online_users = await get_online_users()
            return JSONResponse(content=online_users)
        except Exception as e:
            print(f"Ошибка в API /api/online-users: {e}")
            import traceback
            traceback.print_exc()
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/api/user-sessions/{user_id}")
    async def get_user_sessions_api(user_id: int):
        """API для получения сессий конкретного пользователя"""
        try:
            sessions = await get_user_sessions(user_id)
            return JSONResponse(content=sessions)
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/user-login")
    async def user_login_api(request: Request):
        """API для записи входа пользователя в систему"""
        try:
            form_data = await request.form()
            user_id = int(form_data.get("user_id"))
            session_token = str(form_data.get("session_token"))
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
            
            await create_user_session(user_id, session_token, ip_address, user_agent)
            return JSONResponse(content={"success": True})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/user-activity")
    async def update_user_activity_api(request: Request):
        """API для обновления активности пользователя"""
        try:
            form_data = await request.form()
            session_token = str(form_data.get("session_token"))
            
            await update_user_activity(session_token)
            return JSONResponse(content={"success": True})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/user-logout")
    async def user_logout_api(request: Request):
        """API для записи выхода пользователя из системы"""
        try:
            form_data = await request.form()
            session_token = str(form_data.get("session_token"))
            
            await logout_user_session(session_token)
            return JSONResponse(content={"success": True})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/cleanup-sessions")
    async def cleanup_sessions_api():
        """API для очистки аномальных сессий"""
        try:
            await cleanup_anomalous_sessions()
            return JSONResponse(content={"success": True, "message": "Аномальные сессии очищены"})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/cleanup-user-sessions/{user_id}")
    async def cleanup_user_sessions_api(user_id: int):
        """API для очистки сессий конкретного пользователя"""
        try:
            deleted_count = await cleanup_user_sessions(user_id)
            return JSONResponse(content={
                "success": True, 
                "message": f"Удалено сессий: {deleted_count}. Все оффлайн сессии и старые онлайн сессии очищены."
            })
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.exception_handler(429)
    async def too_many_requests_handler(request: Request, exc: HTTPException):
        """Обработчик ошибки 429 (Too Many Requests)"""
        return RedirectResponse(url="/", status_code=303) 
