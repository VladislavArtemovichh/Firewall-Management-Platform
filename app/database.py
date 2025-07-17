import asyncpg
from contextlib import asynccontextmanager
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
from .models import users
from datetime import datetime
import subprocess
import socket

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

async def create_firewall_devices_table():
    """Создаёт таблицу firewall-устройств, если не существует"""
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS firewall_devices (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            ip VARCHAR(50) NOT NULL,
            type VARCHAR(50) NOT NULL,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'Неизвестно',
            last_poll VARCHAR(50) DEFAULT '-'
        );
    ''')
    await conn.close()

async def get_all_firewall_devices():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    rows = await conn.fetch('SELECT * FROM firewall_devices ORDER BY id')
    await conn.close()
    devices = [dict(row) for row in rows]
    updated_devices = []
    for device in devices:
        updated_device = await update_device_status(device)
        updated_devices.append(updated_device)
    return updated_devices

async def add_firewall_device(device):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        INSERT INTO firewall_devices (name, ip, type, username, password)
        VALUES ($1, $2, $3, $4, $5)
    ''', device.name, device.ip, device.type, device.username, device.password)
    await conn.close()

async def delete_firewall_device(device_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('DELETE FROM firewall_devices WHERE id = $1', int(device_id))
    await conn.close()

async def get_firewall_device_by_id(device_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    row = await conn.fetchrow('SELECT * FROM firewall_devices WHERE id = $1', int(device_id))
    await conn.close()
    return dict(row) if row else None

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
    
    # Создаём таблицу firewall-устройств
    await create_firewall_devices_table()
    await create_device_configs_table()
    
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

async def create_firewall_rules_table():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id SERIAL PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            protocol VARCHAR(16) NOT NULL,
            port VARCHAR(32),
            direction VARCHAR(16) NOT NULL,
            action VARCHAR(16) NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            comment TEXT
        );
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            username VARCHAR(64),
            user_role VARCHAR(32),
            action VARCHAR(32),
            details TEXT,
            time TIMESTAMP DEFAULT NOW()
        );
    ''')
    
    # Миграция: добавляем поле user_role если его нет
    try:
        await conn.execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_role VARCHAR(32)')
        # Обновляем существующие записи, устанавливая user_role = 'unknown' для старых записей
        await conn.execute('UPDATE audit_log SET user_role = \'unknown\' WHERE user_role IS NULL')
    except Exception as e:
        print(f"Ошибка при миграции audit_log: {e}")
    
    await conn.close()

async def get_all_firewall_rules():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    rows = await conn.fetch('SELECT * FROM firewall_rules ORDER BY id')
    await conn.close()
    return [dict(row) for row in rows]

async def add_firewall_rule(rule):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    row = await conn.fetchrow('''
        INSERT INTO firewall_rules (name, protocol, port, direction, action, enabled, comment)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
    ''', rule['name'], rule['protocol'], rule['port'], rule['direction'], rule['action'], rule['enabled'], rule['comment'])
    await conn.close()
    return dict(row)

async def update_firewall_rule(rule_id, rule):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    row = await conn.fetchrow('''
        UPDATE firewall_rules SET
            name=$1, protocol=$2, port=$3, direction=$4, action=$5, enabled=$6, comment=$7
        WHERE id=$8 RETURNING *
    ''', rule['name'], rule['protocol'], rule['port'], rule['direction'], rule['action'], rule['enabled'], rule['comment'], rule_id)
    await conn.close()
    return dict(row)

async def delete_firewall_rule(rule_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('DELETE FROM firewall_rules WHERE id=$1', rule_id)
    await conn.close()

async def toggle_firewall_rule(rule_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    row = await conn.fetchrow('''
        UPDATE firewall_rules SET enabled = NOT enabled WHERE id=$1 RETURNING *
    ''', rule_id)
    await conn.close()
    return dict(row)

async def add_audit_log(username, user_role, action, details):
    try:
        conn = await asyncpg.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST,
            port=DB_PORT
        )
        await conn.execute('''
            INSERT INTO audit_log (username, user_role, action, details) VALUES ($1, $2, $3, $4)
        ''', username, user_role, action, details)
        await conn.close()
    except Exception as e:
        print(f"Ошибка при записи в audit_log: {e}")
        import traceback
        traceback.print_exc()

async def get_audit_log():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    rows = await conn.fetch('SELECT * FROM audit_log ORDER BY time DESC LIMIT 100')
    await conn.close()
    return [dict(row) for row in rows] 

async def check_device_online(ip, tcp_port=22):
    if not ip:
        print('IP is None')
        return False
    # Сначала пробуем ping
    try:
        result = subprocess.run(['ping', '-n', '1', str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f'Ping {ip} result: {result.returncode}, stdout: {result.stdout}, stderr: {result.stderr}')
        if result.returncode == 0:
            return True
    except Exception as e:
        print(f'Ping exception: {e}')
    # Если ping не сработал — пробуем TCP connect
    try:
        with socket.create_connection((ip, tcp_port), timeout=2):
            print(f'TCP connect to {ip}:{tcp_port} success')
            return True
    except Exception as e:
        print(f'TCP connect to {ip}:{tcp_port} failed: {e}')
    return False

async def update_device_status(device):
    online = await check_device_online(device.get('ip'))
    status = "Онлайн" if online else "Оффлайн"
    last_poll = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute(
        "UPDATE firewall_devices SET status=$1, last_poll=$2 WHERE id=$3",
        status, last_poll, int(device['id'])
    )
    await conn.close()
    device['status'] = status if status is not None else 'Неизвестно'
    device['last_poll'] = last_poll if last_poll is not None else '-'
    print('RETURN DEVICE:', device)
    return device 

async def create_device_configs_table():
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS device_configs (
            id SERIAL PRIMARY KEY,
            device_id INTEGER NOT NULL,
            config TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT NOW()
        );
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS device_config_backups (
            id SERIAL PRIMARY KEY,
            device_id INTEGER NOT NULL,
            config TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS device_config_audit (
            id SERIAL PRIMARY KEY,
            device_id INTEGER NOT NULL,
            username VARCHAR(64),
            action VARCHAR(32),
            details TEXT,
            time TIMESTAMP DEFAULT NOW()
        );
    ''')
    await conn.close()

async def get_device_config(device_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    row = await conn.fetchrow('SELECT config FROM device_configs WHERE device_id=$1 ORDER BY updated_at DESC LIMIT 1', device_id)
    await conn.close()
    return row['config'] if row else ""

async def save_device_config(device_id, config, username):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('INSERT INTO device_configs (device_id, config) VALUES ($1, $2)', device_id, config)
    await conn.execute('INSERT INTO device_config_audit (device_id, username, action, details) VALUES ($1, $2, $3, $4)', device_id, username, 'save', 'Сохранена новая конфигурация')
    await conn.close()

async def backup_device_config(device_id, config, username):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    await conn.execute('INSERT INTO device_config_backups (device_id, config) VALUES ($1, $2)', device_id, config)
    await conn.execute('INSERT INTO device_config_audit (device_id, username, action, details) VALUES ($1, $2, $3, $4)', device_id, username, 'backup', 'Создана резервная копия')
    await conn.close()

async def get_device_config_backups(device_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    rows = await conn.fetch('SELECT id, created_at FROM device_config_backups WHERE device_id=$1 ORDER BY created_at DESC', device_id)
    await conn.close()
    return [{"id": r["id"], "created_at": r["created_at"]} for r in rows]

async def get_device_config_audit(device_id):
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    rows = await conn.fetch('SELECT username, action, time, details FROM device_config_audit WHERE device_id=$1 ORDER BY time DESC', device_id)
    await conn.close()
    return [{"username": r["username"], "action": r["action"], "time": r["time"], "details": r["details"]} for r in rows] 