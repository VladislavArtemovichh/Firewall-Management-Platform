import asyncpg
from contextlib import asynccontextmanager
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT

async def create_users_table():
    """Создаёт таблицу пользователей, если она не существует"""
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

async def startup_event():
    """Событие запуска приложения - проверяет и создаёт таблицы"""
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