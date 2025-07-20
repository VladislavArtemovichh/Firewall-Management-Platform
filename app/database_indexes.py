import asyncpg
import logging
from db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT

async def create_database_indexes():
    """
    Создает все необходимые индексы для оптимизации производительности
    """
    logging.info("[DB-INDEXES] Starting database indexes creation")
    
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    
    try:
        # Индексы для таблицы users
        await create_users_indexes(conn)
        
        # Индексы для таблицы user_sessions
        await create_user_sessions_indexes(conn)
        
        # Индексы для таблицы firewall_devices
        await create_firewall_devices_indexes(conn)
        
        # Индексы для таблицы firewall_rules
        await create_firewall_rules_indexes(conn)
        
        # Индексы для таблицы audit_log
        await create_audit_log_indexes(conn)
        
        # Индексы для таблиц конфигураций устройств
        await create_device_configs_indexes(conn)
        
        logging.info("[DB-INDEXES] All database indexes created successfully")
        
    except Exception as e:
        logging.error(f"[DB-INDEXES] Error creating indexes: {e}")
        raise
    finally:
        await conn.close()

async def create_users_indexes(conn):
    """Создает индексы для таблицы users"""
    logging.info("[DB-INDEXES] Creating indexes for users table")
    
    # Индекс по username для быстрого поиска пользователей
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username 
        ON users(username);
    ''')
    
    # Индекс по role для фильтрации по ролям
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_role 
        ON users(role);
    ''')
    
    # Составной индекс для аутентификации
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_auth 
        ON users(username, password);
    ''')

async def create_user_sessions_indexes(conn):
    """Создает индексы для таблицы user_sessions"""
    logging.info("[DB-INDEXES] Creating indexes for user_sessions table")
    
    # Индекс по user_id для быстрого поиска сессий пользователя
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_id 
        ON user_sessions(user_id);
    ''')
    
    # Индекс по session_token для быстрого поиска сессии
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token 
        ON user_sessions(session_token);
    ''')
    
    # Индекс по is_online для фильтрации онлайн пользователей
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_online 
        ON user_sessions(is_online);
    ''')
    
    # Индекс по last_activity для очистки старых сессий
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_last_activity 
        ON user_sessions(last_activity);
    ''')
    
    # Индекс по created_at для анализа активности
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_created_at 
        ON user_sessions(created_at);
    ''')
    
    # Составной индекс для поиска активных сессий пользователя
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_active 
        ON user_sessions(user_id, is_online, last_activity);
    ''')

async def create_firewall_devices_indexes(conn):
    """Создает индексы для таблицы firewall_devices"""
    logging.info("[DB-INDEXES] Creating indexes for firewall_devices table")
    
    # Индекс по ip для быстрого поиска устройства по IP
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_devices_ip 
        ON firewall_devices(ip);
    ''')
    
    # Индекс по name для поиска по имени устройства
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_devices_name 
        ON firewall_devices(name);
    ''')
    
    # Индекс по type для фильтрации по типу устройства
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_devices_type 
        ON firewall_devices(type);
    ''')
    
    # Индекс по status для фильтрации по статусу
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_devices_status 
        ON firewall_devices(status);
    ''')
    
    # Составной индекс для поиска устройств по типу и статусу
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_devices_type_status 
        ON firewall_devices(type, status);
    ''')

async def create_firewall_rules_indexes(conn):
    """Создает индексы для таблицы firewall_rules"""
    logging.info("[DB-INDEXES] Creating indexes for firewall_rules table")
    
    # Индекс по enabled для фильтрации активных/неактивных правил
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_enabled 
        ON firewall_rules(enabled);
    ''')
    
    # Индекс по protocol для фильтрации по протоколу
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_protocol 
        ON firewall_rules(protocol);
    ''')
    
    # Индекс по action для фильтрации по действию
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_action 
        ON firewall_rules(action);
    ''')
    
    # Индекс по direction для фильтрации по направлению
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_direction 
        ON firewall_rules(direction);
    ''')
    
    # Индекс по port для поиска правил по порту
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_port 
        ON firewall_rules(port);
    ''')
    
    # Составной индекс для поиска правил по протоколу и порту
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_protocol_port 
        ON firewall_rules(protocol, port);
    ''')
    
    # Составной индекс для поиска активных правил по протоколу
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_firewall_rules_enabled_protocol 
        ON firewall_rules(enabled, protocol);
    ''')

async def create_audit_log_indexes(conn):
    """Создает индексы для таблицы audit_log"""
    logging.info("[DB-INDEXES] Creating indexes for audit_log table")
    
    # Индекс по username для поиска действий пользователя
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_username 
        ON audit_log(username);
    ''')
    
    # Индекс по user_role для фильтрации по роли
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_user_role 
        ON audit_log(user_role);
    ''')
    
    # Индекс по action для фильтрации по типу действия
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_action 
        ON audit_log(action);
    ''')
    
    # Индекс по time для поиска по времени
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_time 
        ON audit_log(time);
    ''')
    
    # Составной индекс для поиска действий пользователя по времени
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_username_time 
        ON audit_log(username, time);
    ''')
    
    # Составной индекс для поиска действий по роли и времени
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_role_time 
        ON audit_log(user_role, time);
    ''')

async def create_device_configs_indexes(conn):
    """Создает индексы для таблиц конфигураций устройств"""
    logging.info("[DB-INDEXES] Creating indexes for device configs tables")
    
    # Индексы для таблицы device_configs
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_configs_device_id 
        ON device_configs(device_id);
    ''')
    
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_configs_updated_at 
        ON device_configs(updated_at);
    ''')
    
    # Составной индекс для получения последней конфигурации
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_configs_device_updated 
        ON device_configs(device_id, updated_at DESC);
    ''')
    
    # Индексы для таблицы device_config_backups
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_backups_device_id 
        ON device_config_backups(device_id);
    ''')
    
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_backups_created_at 
        ON device_config_backups(created_at);
    ''')
    
    # Составной индекс для получения резервных копий по времени
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_backups_device_created 
        ON device_config_backups(device_id, created_at DESC);
    ''')
    
    # Индексы для таблицы device_config_audit
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_audit_device_id 
        ON device_config_audit(device_id);
    ''')
    
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_audit_username 
        ON device_config_audit(username);
    ''')
    
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_audit_action 
        ON device_config_audit(action);
    ''')
    
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_audit_time 
        ON device_config_audit(time);
    ''')
    
    # Составной индекс для поиска аудита устройства по времени
    await conn.execute('''
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_config_audit_device_time 
        ON device_config_audit(device_id, time DESC);
    ''')

async def analyze_table_statistics():
    """
    Анализирует статистику таблиц для оптимизации запросов
    """
    logging.info("[DB-INDEXES] Analyzing table statistics")
    
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    
    try:
        # Анализируем все таблицы
        tables = [
            'users', 'user_sessions', 'firewall_devices', 
            'firewall_rules', 'audit_log', 'device_configs',
            'device_config_backups', 'device_config_audit'
        ]
        
        for table in tables:
            await conn.execute(f'ANALYZE {table};')
            logging.info(f"[DB-INDEXES] Analyzed table: {table}")
        
        logging.info("[DB-INDEXES] All table statistics updated")
        
    except Exception as e:
        logging.error(f"[DB-INDEXES] Error analyzing statistics: {e}")
        raise
    finally:
        await conn.close()

async def get_index_usage_statistics():
    """
    Получает статистику использования индексов
    """
    logging.info("[DB-INDEXES] Getting index usage statistics")
    
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    
    try:
        # Запрос для получения статистики использования индексов
        query = '''
        SELECT 
            schemaname,
            tablename,
            indexname,
            idx_scan as index_scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched
        FROM pg_stat_user_indexes 
        WHERE schemaname = 'public'
        ORDER BY idx_scan DESC;
        '''
        
        rows = await conn.fetch(query)
        
        logging.info("[DB-INDEXES] Index usage statistics:")
        for row in rows:
            logging.info(f"  {row['tablename']}.{row['indexname']}: {row['index_scans']} scans, {row['tuples_read']} reads")
        
        return [dict(row) for row in rows]
        
    except Exception as e:
        logging.error(f"[DB-INDEXES] Error getting index statistics: {e}")
        raise
    finally:
        await conn.close()

async def optimize_slow_queries():
    """
    Оптимизирует медленные запросы на основе статистики
    """
    logging.info("[DB-INDEXES] Optimizing slow queries")
    
    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT
    )
    
    try:
        # Получаем медленные запросы
        slow_queries_query = '''
        SELECT 
            query,
            calls,
            total_time,
            mean_time,
            rows
        FROM pg_stat_statements 
        WHERE mean_time > 100  -- запросы медленнее 100ms
        ORDER BY mean_time DESC
        LIMIT 10;
        '''
        
        try:
            rows = await conn.fetch(slow_queries_query)
            logging.info("[DB-INDEXES] Slow queries detected:")
            for row in rows:
                logging.info(f"  Query: {row['query'][:100]}...")
                logging.info(f"    Calls: {row['calls']}, Mean time: {row['mean_time']}ms")
        except Exception as e:
            logging.warning(f"[DB-INDEXES] Could not get slow queries (pg_stat_statements not available): {e}")
        
        # Рекомендации по оптимизации
        logging.info("[DB-INDEXES] Optimization recommendations:")
        logging.info("  1. Consider adding composite indexes for frequently used WHERE clauses")
        logging.info("  2. Review queries with high mean_time for optimization")
        logging.info("  3. Consider partitioning large tables if needed")
        
    except Exception as e:
        logging.error(f"[DB-INDEXES] Error optimizing queries: {e}")
        raise
    finally:
        await conn.close()

# Функция для запуска всех оптимизаций
async def optimize_database_performance():
    """
    Запускает полную оптимизацию производительности базы данных
    """
    logging.info("[DB-INDEXES] Starting full database performance optimization")
    
    try:
        # Создаем индексы
        await create_database_indexes()
        
        # Анализируем статистику
        await analyze_table_statistics()
        
        # Получаем статистику использования индексов
        await get_index_usage_statistics()
        
        # Оптимизируем медленные запросы
        await optimize_slow_queries()
        
        logging.info("[DB-INDEXES] Database performance optimization completed successfully")
        
    except Exception as e:
        logging.error(f"[DB-INDEXES] Database optimization failed: {e}")
        raise

if __name__ == "__main__":
    import asyncio
    
    # Запуск оптимизации
    asyncio.run(optimize_database_performance()) 