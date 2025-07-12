import asyncpg
from contextlib import asynccontextmanager
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
from .models import users
from datetime import datetime

def convert_row_for_json(row_dict):
    """Преобразует datetime объекты и IP-адреса в строки для JSON сериализации"""
    # Преобразуем datetime объекты
    datetime_fields = ['login_time', 'logout_time', 'last_activity', 'created_at']
    for field in datetime_fields:
        if field in row_dict and row_dict[field] is not None:
            if isinstance(row_dict[field], datetime):
                row_dict[field] = row_dict[field].isoformat()
    
    # Преобразуем IP-адреса
    if 'ip_address' in row_dict and row_dict['ip_address'] is not None:
        row_dict['ip_address'] = str(row_dict['ip_address'])
    
    return row_dict

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
            password VARCHAR(128) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user'
        );
    ''')
    await conn.close()

async def create_user_sessions_table():
    """Создаёт таблицу сессий пользователей для отслеживания авторизаций и онлайн статуса"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            logout_time TIMESTAMP WITH TIME ZONE NULL,
            is_online BOOLEAN DEFAULT TRUE,
            ip_address INET,
            user_agent TEXT,
            last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    ''')
    
    # Создаём индексы для оптимизации запросов
    await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);')
    await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_online ON user_sessions(is_online);')
    await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions(last_activity);')
    
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
    
    # Проверяем и создаём таблицу пользователей
    users_table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'users'
        );
    """)
    if not users_table_exists:
        await conn.execute('''
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(128) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user'
            );
        ''')
    else:
        # Проверяем, есть ли поле role в таблице
        role_column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'role'
            );
        """)
        if not role_column_exists:
            await conn.execute('ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT \'user\';')
    
    # Проверяем и создаём таблицу сессий
    sessions_table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'user_sessions'
        );
    """)
    if not sessions_table_exists:
        await conn.execute('''
            CREATE TABLE user_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                logout_time TIMESTAMP WITH TIME ZONE NULL,
                is_online BOOLEAN DEFAULT TRUE,
                ip_address INET,
                user_agent TEXT,
                last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        ''')
        
        # Создаём индексы для оптимизации запросов
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_online ON user_sessions(is_online);')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions(last_activity);')
    
    await conn.close()
    
    # Синхронизируем пользователей с базой данных
    await sync_users_to_database()
    
    # Очищаем аномальные сессии
    await cleanup_anomalous_sessions()

# Функции для работы с сессиями пользователей
async def create_user_session(user_id: int, session_token: str, ip_address: str = None, user_agent: str = None):
    """Создаёт новую сессию пользователя"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        await conn.execute('''
            INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent)
            VALUES ($1, $2, $3, $4)
        ''', user_id, session_token, ip_address, user_agent)
    finally:
        await conn.close()

async def update_user_activity(session_token: str):
    """Обновляет время последней активности пользователя"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        await conn.execute('''
            UPDATE user_sessions 
            SET last_activity = NOW()
            WHERE session_token = $1 AND is_online = TRUE
        ''', session_token)
    finally:
        await conn.close()

async def logout_user_session(session_token: str):
    """Завершает сессию пользователя (выход из системы)"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        await conn.execute('''
            UPDATE user_sessions 
            SET logout_time = NOW(), is_online = FALSE
            WHERE session_token = $1
        ''', session_token)
    finally:
        await conn.close()

async def get_online_users():
    """Возвращает список пользователей, которые сейчас онлайн"""
    try:
        conn = await asyncpg.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST,
            port=DB_PORT
        )
        try:
            rows = await conn.fetch('''
                SELECT u.username, us.login_time, us.last_activity, us.ip_address
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.is_online = TRUE
                ORDER BY us.last_activity DESC
            ''')
            # Преобразуем объекты для JSON сериализации
            result = []
            for row in rows:
                user_dict = convert_row_for_json(dict(row))
                result.append(user_dict)
            return result
        finally:
            await conn.close()
    except Exception as e:
        print(f"Ошибка при получении пользователей онлайн: {e}")
        return []

async def get_user_sessions(user_id: int):
    """Возвращает все сессии конкретного пользователя"""
    try:
        conn = await asyncpg.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST,
            port=DB_PORT
        )
        try:
            rows = await conn.fetch('''
                SELECT session_token, login_time, logout_time, is_online, 
                       ip_address, user_agent, last_activity
                FROM user_sessions
                WHERE user_id = $1
                ORDER BY login_time DESC
            ''', user_id)
            # Преобразуем объекты для JSON сериализации
            result = []
            for row in rows:
                session_dict = convert_row_for_json(dict(row))
                result.append(session_dict)
            return result
        finally:
            await conn.close()
    except Exception as e:
        print(f"Ошибка при получении сессий пользователя {user_id}: {e}")
        return []

async def cleanup_old_sessions(hours_old: int = 24):
    """Удаляет старые сессии (по умолчанию старше 24 часов)"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        await conn.execute('''
            DELETE FROM user_sessions 
            WHERE created_at < NOW() - INTERVAL '$1 hours'
        ''', hours_old)
    finally:
        await conn.close()

async def mark_inactive_users_as_offline(minutes_inactive: int = 30):
    """Помечает пользователей как оффлайн, если они неактивны более указанного времени"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        await conn.execute('''
            UPDATE user_sessions 
            SET is_online = FALSE, logout_time = NOW()
            WHERE is_online = TRUE 
            AND last_activity < NOW() - INTERVAL '$1 minutes'
        ''', minutes_inactive)
    finally:
        await conn.close() 

async def sync_users_to_database():
    """Синхронизирует пользователей из models.py с базой данных"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        # Проверяем, есть ли пользователи в базе данных
        existing_users = await conn.fetch('SELECT username FROM users')
        existing_usernames = {row['username'] for row in existing_users}
        
        # Добавляем пользователей, которых нет в базе данных
        for username, user_data in users.items():
            if username not in existing_usernames:
                await conn.execute('''
                    INSERT INTO users (username, password, role)
                    VALUES ($1, $2, $3)
                ''', username, user_data['password'], user_data['role'].value)
                print(f"Добавлен пользователь: {username} с ролью: {user_data['role'].value}")
            else:
                # Обновляем роль существующего пользователя
                await conn.execute('''
                    UPDATE users SET role = $1 WHERE username = $2
                ''', user_data['role'].value, username)
                print(f"Обновлена роль пользователя: {username} -> {user_data['role'].value}")
    finally:
        await conn.close()

async def get_user_id_by_username(username: str) -> int:
    """Получает ID пользователя по имени пользователя"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        user_id = await conn.fetchval('SELECT id FROM users WHERE username = $1', username)
        return user_id
    finally:
        await conn.close() 

async def cleanup_anomalous_sessions():
    """Очищает аномальные сессии без времени выхода, но помеченные как неактивные"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        # Устанавливаем время выхода для неактивных сессий без logout_time
        await conn.execute('''
            UPDATE user_sessions 
            SET logout_time = last_activity
            WHERE is_online = FALSE AND logout_time IS NULL
        ''')
        
        # Также можно удалить очень старые сессии без logout_time (старше 1 часа)
        await conn.execute('''
            DELETE FROM user_sessions 
            WHERE logout_time IS NULL 
            AND last_activity < NOW() - INTERVAL '1 hour'
        ''')
    finally:
        await conn.close() 

async def cleanup_user_sessions(user_id: int):
    """Очищает все сессии конкретного пользователя"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        # Сначала получаем количество сессий до очистки
        sessions_before = await conn.fetchval('''
            SELECT COUNT(*) FROM user_sessions 
            WHERE user_id = $1
        ''', user_id)
        
        # Устанавливаем время выхода для активных сессий пользователя
        await conn.execute('''
            UPDATE user_sessions 
            SET logout_time = last_activity, is_online = FALSE
            WHERE user_id = $1 AND is_online = TRUE
        ''', user_id)
        
        # Удаляем ВСЕ оффлайн сессии пользователя (независимо от возраста)
        await conn.execute('''
            DELETE FROM user_sessions 
            WHERE user_id = $1 AND is_online = FALSE
        ''', user_id)
        
        # Удаляем старые онлайн сессии пользователя (старше 24 часов)
        await conn.execute('''
            DELETE FROM user_sessions 
            WHERE user_id = $1 
            AND created_at < NOW() - INTERVAL '24 hours'
        ''', user_id)
        
        # Возвращаем количество удаленных сессий
        sessions_after = await conn.fetchval('''
            SELECT COUNT(*) FROM user_sessions 
            WHERE user_id = $1
        ''', user_id)
        
        deleted_count = sessions_before - sessions_after
        return deleted_count
    finally:
        await conn.close() 