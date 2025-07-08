from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncpg
import asyncio
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT

app = FastAPI()
# uvicorn main:app --reload
@app.on_event("startup")
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

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username in users and users[username] == password:
        return {"message": "Успешная авторизация", "user": username}
    raise HTTPException(status_code=401, detail="Неверный логин или пароль")

@app.get("/")
def get_login_page():
    return FileResponse("авторизация2.html", media_type="text/html")


