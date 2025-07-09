from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi import Request
from contextlib import asynccontextmanager
import asyncpg
import asyncio
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT

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

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username in users and users[username] == password:
        return RedirectResponse(url="/dashboard", status_code=303)
    # Если ошибка, возвращаем страницу авторизации с сообщением
    return templates.TemplateResponse(
        "авторизация2.html",
        {"request": request, "error": "Неверный логин или пароль"},
        status_code=401
    )

@app.get("/")
def get_login_page():
<<<<<<< HEAD
    return FileResponse("авторизация2.html", media_type="text/html")

@app.get("/dashboard")
def get_dashboard():
    return FileResponse("dashboard.html", media_type="text/html")

 
=======
    return FileResponse("auth.html", media_type="text/html")

@app.get("/dashboard")
def get_dashboard():
    return FileResponse("dashboard.html", media_type="text/html")
>>>>>>> d61ee58 (Добавил переадресацию с помощью FastAPI)
