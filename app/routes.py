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
from .models import users, UserRole, get_role_name, next_user_id, firewall_rules, FirewallRule, next_rule_id
from .database import (
    get_online_users, 
    get_user_sessions, 
    create_user_session, 
    update_user_activity,
    logout_user_session,
    get_user_id_by_username,
    cleanup_anomalous_sessions,
    cleanup_user_sessions,
    get_all_firewall_rules, add_firewall_rule, update_firewall_rule, delete_firewall_rule, toggle_firewall_rule,
    add_audit_log, get_audit_log, create_firewall_rules_table
)
from .metrics import metrics_collector, start_metrics_collection
import datetime
import re
import psutil
import time

templates = Jinja2Templates(directory="templates")
audit_log = []

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
        ip_address = request.client.host if request.client else None
        record_login_attempt(username, ip_address)

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

    # --- API для управления правилами ---
    @app.on_event("startup")
    async def startup_event():
        await create_firewall_rules_table()

    @app.get("/api/rules")
    async def get_rules():
        return await get_all_firewall_rules()

    @app.post("/api/rules")
    async def add_rule(request: Request):
        try:
            form = await request.form()
            data = {
                'name': str(form.get("name", "")).strip(),
                'protocol': str(form.get("protocol", "any")),
                'port': str(form.get("port", "")) if form.get("port") is not None else None,
                'direction': str(form.get("direction", "any")),
                'action': str(form.get("action", "allow")),
                'enabled': str(form.get("enabled", "true")).lower() == "true",
                'comment': str(form.get("comment", ""))
            }
            # Валидация дубликатов и портов (можно вынести в отдельную функцию)
            rules = await get_all_firewall_rules()
            for r in rules:
                if r['name'].strip().lower() == data['name'].lower() and r['protocol'] == data['protocol'] and r['port'] == data['port'] and r['direction'] == data['direction'] and r['action'] == data['action']:
                    return {"error": "Такое правило уже существует!"}
            if data['port']:
                import re
                if not re.match(r'^\d+(-\d+)?$', data['port']):
                    return {"error": "Порт должен быть числом или диапазоном (например, 80 или 1000-2000)"}
                parts = data['port'].split('-')
                start = int(parts[0])
                end = int(parts[1]) if len(parts) == 2 else start
                if start < 1 or (end < start):
                    return {"error": "Некорректный диапазон портов"}
            rule = await add_firewall_rule(data)
            user = request.cookies.get('username', 'system')
            user_role = users.get(user, {}).get("role", "unknown").value if user in users else "unknown"
            await add_audit_log(user, user_role, 'Добавление', f'Добавлено правило: {rule["name"]} ({rule["protocol"]}/{rule["port"]})')
            return {"success": True, "rule": rule}
        except Exception as e:
            print(f"Ошибка при добавлении правила: {e}")
            import traceback
            traceback.print_exc()
            return {"error": f"Ошибка при добавлении правила: {str(e)}"}

    @app.put("/api/rules/{rule_id}")
    async def update_rule(rule_id: int, request: Request):
        form = await request.form()
        data = {
            'name': str(form.get("name", "")).strip(),
            'protocol': str(form.get("protocol", "any")),
            'port': str(form.get("port", "")) if form.get("port") is not None else None,
            'direction': str(form.get("direction", "any")),
            'action': str(form.get("action", "allow")),
            'enabled': str(form.get("enabled", "true")).lower() == "true",
            'comment': str(form.get("comment", ""))
        }
        rules = await get_all_firewall_rules()
        for r in rules:
            if r['id'] != rule_id and r['name'].strip().lower() == data['name'].lower() and r['protocol'] == data['protocol'] and r['port'] == data['port'] and r['direction'] == data['direction'] and r['action'] == data['action']:
                return {"error": "Такое правило уже существует!"}
        if data['port']:
            import re
            if not re.match(r'^\d+(-\d+)?$', data['port']):
                return {"error": "Порт должен быть числом или диапазоном (например, 80 или 1000-2000)"}
            parts = data['port'].split('-')
            start = int(parts[0])
            end = int(parts[1]) if len(parts) == 2 else start
            if start < 1 or (end < start):
                return {"error": "Некорректный диапазон портов"}
        rule = await update_firewall_rule(rule_id, data)
        user = request.cookies.get('username', 'system')
        user_role = users.get(user, {}).get("role", "unknown").value if user in users else "unknown"
        await add_audit_log(user, user_role, 'Изменение', f'Изменено правило: {rule["name"]} ({rule["protocol"]}/{rule["port"]})')
        return {"success": True, "rule": rule}

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(rule_id: int, request: Request):
        rules = await get_all_firewall_rules()
        rule = next((r for r in rules if r['id'] == rule_id), None)
        await delete_firewall_rule(rule_id)
        user = request.cookies.get('username', 'system')
        user_role = users.get(user, {}).get("role", "unknown").value if user in users else "unknown"
        if rule:
            await add_audit_log(user, user_role, 'Удаление', f'Удалено правило: {rule["name"]} ({rule["protocol"]}/{rule["port"]})')
        return {"success": True}

    @app.post("/api/rules/{rule_id}/toggle")
    async def toggle_rule(rule_id: int, request: Request):
        rule = await toggle_firewall_rule(rule_id)
        user = request.cookies.get('username', 'system')
        user_role = users.get(user, {}).get("role", "unknown").value if user in users else "unknown"
        await add_audit_log(user, user_role, 'Включение' if rule['enabled'] else 'Отключение', f'{"Включено" if rule["enabled"] else "Отключено"} правило: {rule["name"]} ({rule["protocol"]}/{rule["port"]})')
        return {"success": True, "enabled": rule['enabled']}

    @app.get("/api/rules/audit")
    async def get_rules_audit():
        return await get_audit_log()

    @app.get("/rules")
    def get_rules_page(request: Request):
        username = request.cookies.get("username")
        if not username or username not in users:
            return RedirectResponse(url="/", status_code=303)
        user_role = users[username]["role"].value
        return templates.TemplateResponse("rules.html", {"request": request, "user_role": user_role})

    @app.get("/firewalls")
    def get_firewalls(request: Request):
        username = request.cookies.get("username")
        if not username or username not in users:
            return RedirectResponse(url="/", status_code=303)
        user_role = users[username]["role"].value
        return templates.TemplateResponse("firewalls.html", {"request": request, "user_role": user_role})

    @app.exception_handler(429)
    async def too_many_requests_handler(request: Request, exc: HTTPException):
        """Обработчик ошибки 429 (Too Many Requests)"""
        return RedirectResponse(url="/", status_code=303)

    # --- Маршруты для метрик (только для админов) ---
    @app.get("/metrics")
    def get_metrics_page(request: Request):
        """Страница метрик (только для администраторов)"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return RedirectResponse(url="/dashboard", status_code=303)
        return templates.TemplateResponse("metrics.html", {"request": request, "user_role": user_role})

    @app.get("/api/metrics/summary")
    async def get_metrics_summary(request: Request):
        """API для получения сводки метрик"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return JSONResponse(content={"error": "Доступ запрещен"}, status_code=403)
        
        try:
            # Получаем данные для метрик приложения
            online_users = await get_online_users()
            active_users = len(online_users)
            
            rules = await get_all_firewall_rules()
            firewall_rules_count = len(rules)
            
            # Получаем активные сессии
            conn = await asyncpg.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT
            )
            active_sessions = await conn.fetchval('SELECT COUNT(*) FROM user_sessions WHERE is_online = true')
            await conn.close()
            
            # Собираем метрики приложения
            metrics_collector.collect_app_metrics(active_users, firewall_rules_count, active_sessions)
            metrics_collector.collect_security_metrics()
            
            # Получаем сводку
            summary = metrics_collector.get_metrics_summary()
            return JSONResponse(content=summary)
            
        except Exception as e:
            import traceback
            print(f"[METRICS API ERROR] Ошибка при получении метрик: {e}")
            traceback.print_exc()
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/api/metrics/charts")
    async def get_metrics_charts(request: Request):
        """API для получения данных для графиков"""
        username = request.cookies.get("username")
        user_role = None
        if username and username in users:
            user_role = users[username]["role"].value
        if user_role != "firewall-admin":
            return JSONResponse(content={"error": "Доступ запрещен"}, status_code=403)
        
        try:
            chart_data = metrics_collector.get_chart_data()
            return JSONResponse(content=chart_data)
        except Exception as e:
            print(f"Ошибка при получении данных графиков: {e}")
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/metrics/record-request")
    async def record_request_metrics(request: Request):
        """API для записи метрик запроса"""
        try:
            form_data = await request.form()
            response_time = float(form_data.get("response_time", 0))
            is_error = form_data.get("is_error", "false").lower() == "true"
            
            metrics_collector.record_request(response_time, is_error)
            return JSONResponse(content={"success": True})
        except Exception as e:
            print(f"Ошибка при записи метрик запроса: {e}")
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/metrics/record-security")
    async def record_security_metrics(request: Request):
        """API для записи метрик безопасности"""
        try:
            form_data = await request.form()
            event_type = form_data.get("event_type", "")
            ip_address = form_data.get("ip_address", "")
            
            if event_type == "failed_login":
                metrics_collector.record_failed_login(ip_address)
            elif event_type == "suspicious_activity":
                metrics_collector.record_suspicious_activity()
            elif event_type == "firewall_block":
                metrics_collector.record_firewall_block()
            
            return JSONResponse(content={"success": True})
        except Exception as e:
            print(f"Ошибка при записи метрик безопасности: {e}")
            return JSONResponse(content={"error": str(e)}, status_code=500)

    # Кэш для предыдущих значений трафика
    if not hasattr(app, 'adapters_traffic_cache'):
        app.adapters_traffic_cache = {}
        app.adapters_traffic_time = {}

    @app.get("/api/adapters")
    async def get_adapters():
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io_counters = psutil.net_io_counters(pernic=True)

        active = []
        inactive = []

        now = time.time()
        prev_counters = app.adapters_traffic_cache
        prev_time = app.adapters_traffic_time
        app.adapters_traffic_cache = {}
        app.adapters_traffic_time = {}

        for name, stat in stats.items():
            mac = "-"
            ip = "-"
            if name in addrs:
                for addr in addrs[name]:
                    if hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                        mac = addr.address
                    elif addr.family == 2:  # AF_INET
                        ip = addr.address
            speed = stat.speed if stat.speed > 0 else None
            in_packets = io_counters[name].packets_recv if name in io_counters else None
            out_packets = io_counters[name].packets_sent if name in io_counters else None
            in_errors = io_counters[name].errin if name in io_counters else None
            out_errors = io_counters[name].errout if name in io_counters else None
            in_bytes = io_counters[name].bytes_recv if name in io_counters else 0
            out_bytes = io_counters[name].bytes_sent if name in io_counters else 0

            # --- расчёт текущей загрузки ---
            prev = prev_counters.get(name)
            prev_t = prev_time.get(name)
            in_rate = out_rate = 0.0
            if prev and prev_t:
                dt = now - prev_t
                if dt > 0:
                    in_rate = (in_bytes - prev[0]) * 8 / dt / 1024 / 1024  # Мбит/с
                    out_rate = (out_bytes - prev[1]) * 8 / dt / 1024 / 1024
                    in_rate = max(in_rate, 0)
                    out_rate = max(out_rate, 0)
            # сохраняем текущие значения для следующего запроса
            app.adapters_traffic_cache[name] = (in_bytes, out_bytes)
            app.adapters_traffic_time[name] = now

            adapter_info = {
                "name": name,
                "mac": mac,
                "ip": ip,
                "speed": speed,
                "in_packets": in_packets,
                "out_packets": out_packets,
                "in_errors": in_errors,
                "out_errors": out_errors,
                "in_mbps": round(in_rate, 3),
                "out_mbps": round(out_rate, 3),
            }
            if stat.isup:
                active.append(adapter_info)
            else:
                inactive.append(adapter_info)

        return {"active": active, "inactive": inactive}
