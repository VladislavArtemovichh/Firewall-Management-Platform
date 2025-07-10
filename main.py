from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi import Request
from contextlib import asynccontextmanager
import asyncpg
import asyncio
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
import time
from collections import defaultdict
import base64

app = FastAPI()
@asynccontextmanager
async def startup_event():
    # Проверяем, есть ли таблица users, если нет — создаём
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'users'
        );
    """)
    if not table_exists:
        await conn.execute('''
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(128) NOT NULL
            );
        ''')
    await conn.close()

# Разрешаем CORS для тестирования (можно убрать в продакшене)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {
    "admin": "admin",
    "user1": "pass1",
    "user2": "pass2"
}

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 900
login_attempts = defaultdict(list)

async def create_users_table():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(128) NOT NULL
        );
    ''')
    await conn.close()

templates = Jinja2Templates(directory=".")

def check_login_attempts(username: str, request: Request):
    now = time.time()
    attempts = login_attempts[username]
    
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

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    lockout_response = check_login_attempts(username, request)
    if lockout_response:
        return lockout_response

    if username in users and users[username] == password:
        login_attempts[username].clear()
        return RedirectResponse(url="/dashboard", status_code=303)

    login_attempts[username].append(time.time())

    # Перенаправляем на главную страницу с ошибкой в куки
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="error", value=base64.b64encode("Неверный логин или пароль".encode('utf-8')).decode('ascii'), max_age=5)
    return response

@app.get("/")
def get_login_page(request: Request):
    # Получаем ошибку из куки
    error = request.cookies.get("error")
    
    # Декодируем ошибку из base64
    if error:
        try:
            error = base64.b64decode(error.encode('ascii')).decode('utf-8')
        except:
            error = "Ошибка декодирования"
    
    # Создаём ответ
    response = templates.TemplateResponse("auth.html", {"request": request, "error": error})
    
    if error:
        response.delete_cookie("error")
    
    return response

@app.get("/dashboard")
def get_dashboard():
    return FileResponse("dashboard.html", media_type="text/html")

@app.exception_handler(429)
async def too_many_requests_handler(request: Request, exc: HTTPException):
    return RedirectResponse(url="/", status_code=303)
