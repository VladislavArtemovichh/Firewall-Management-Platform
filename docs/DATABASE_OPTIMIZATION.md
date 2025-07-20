## 📊 Созданные индексы

### 1. Таблица `users`
```sql
-- Индекс по username для быстрого поиска пользователей
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);

-- Индекс по role для фильтрации по ролям
CREATE INDEX CONCURRENTLY idx_users_role ON users(role);

-- Составной индекс для аутентификации
CREATE INDEX CONCURRENTLY idx_users_auth ON users(username, password);
```

### 2. Таблица `user_sessions`
```sql
-- Индекс по user_id для быстрого поиска сессий пользователя
CREATE INDEX CONCURRENTLY idx_user_sessions_user_id ON user_sessions(user_id);

-- Индекс по session_token для быстрого поиска сессии
CREATE INDEX CONCURRENTLY idx_user_sessions_token ON user_sessions(session_token);

-- Индекс по is_online для фильтрации онлайн пользователей
CREATE INDEX CONCURRENTLY idx_user_sessions_online ON user_sessions(is_online);

-- Индекс по last_activity для очистки старых сессий
CREATE INDEX CONCURRENTLY idx_user_sessions_last_activity ON user_sessions(last_activity);

-- Индекс по created_at для анализа активности
CREATE INDEX CONCURRENTLY idx_user_sessions_created_at ON user_sessions(created_at);

-- Составной индекс для поиска активных сессий пользователя
CREATE INDEX CONCURRENTLY idx_user_sessions_active ON user_sessions(user_id, is_online, last_activity);
```

### 3. Таблица `firewall_devices`
```sql
-- Индекс по ip для быстрого поиска устройства по IP
CREATE INDEX CONCURRENTLY idx_firewall_devices_ip ON firewall_devices(ip);

-- Индекс по name для поиска по имени устройства
CREATE INDEX CONCURRENTLY idx_firewall_devices_name ON firewall_devices(name);

-- Индекс по type для фильтрации по типу устройства
CREATE INDEX CONCURRENTLY idx_firewall_devices_type ON firewall_devices(type);

-- Индекс по status для фильтрации по статусу
CREATE INDEX CONCURRENTLY idx_firewall_devices_status ON firewall_devices(status);

-- Составной индекс для поиска устройств по типу и статусу
CREATE INDEX CONCURRENTLY idx_firewall_devices_type_status ON firewall_devices(type, status);
```

### 4. Таблица `firewall_rules`
```sql
-- Индекс по enabled для фильтрации активных/неактивных правил
CREATE INDEX CONCURRENTLY idx_firewall_rules_enabled ON firewall_rules(enabled);

-- Индекс по protocol для фильтрации по протоколу
CREATE INDEX CONCURRENTLY idx_firewall_rules_protocol ON firewall_rules(protocol);

-- Индекс по action для фильтрации по действию
CREATE INDEX CONCURRENTLY idx_firewall_rules_action ON firewall_rules(action);

-- Индекс по direction для фильтрации по направлению
CREATE INDEX CONCURRENTLY idx_firewall_rules_direction ON firewall_rules(direction);

-- Индекс по port для поиска правил по порту
CREATE INDEX CONCURRENTLY idx_firewall_rules_port ON firewall_rules(port);

-- Составной индекс для поиска правил по протоколу и порту
CREATE INDEX CONCURRENTLY idx_firewall_rules_protocol_port ON firewall_rules(protocol, port);

-- Составной индекс для поиска активных правил по протоколу
CREATE INDEX CONCURRENTLY idx_firewall_rules_enabled_protocol ON firewall_rules(enabled, protocol);
```

### 5. Таблица `audit_log`
```sql
-- Индекс по username для поиска действий пользователя
CREATE INDEX CONCURRENTLY idx_audit_log_username ON audit_log(username);

-- Индекс по user_role для фильтрации по роли
CREATE INDEX CONCURRENTLY idx_audit_log_user_role ON audit_log(user_role);

-- Индекс по action для фильтрации по типу действия
CREATE INDEX CONCURRENTLY idx_audit_log_action ON audit_log(action);

-- Индекс по time для поиска по времени
CREATE INDEX CONCURRENTLY idx_audit_log_time ON audit_log(time);

-- Составной индекс для поиска действий пользователя по времени
CREATE INDEX CONCURRENTLY idx_audit_log_username_time ON audit_log(username, time);

-- Составной индекс для поиска действий по роли и времени
CREATE INDEX CONCURRENTLY idx_audit_log_role_time ON audit_log(user_role, time);
```

### 6. Таблицы конфигураций устройств
```sql
-- device_configs
CREATE INDEX CONCURRENTLY idx_device_configs_device_id ON device_configs(device_id);
CREATE INDEX CONCURRENTLY idx_device_configs_updated_at ON device_configs(updated_at);
CREATE INDEX CONCURRENTLY idx_device_configs_device_updated ON device_configs(device_id, updated_at DESC);

-- device_config_backups
CREATE INDEX CONCURRENTLY idx_device_config_backups_device_id ON device_config_backups(device_id);
CREATE INDEX CONCURRENTLY idx_device_config_backups_created_at ON device_config_backups(created_at);
CREATE INDEX CONCURRENTLY idx_device_config_backups_device_created ON device_config_backups(device_id, created_at DESC);

-- device_config_audit
CREATE INDEX CONCURRENTLY idx_device_config_audit_device_id ON device_config_audit(device_id);
CREATE INDEX CONCURRENTLY idx_device_config_audit_username ON device_config_audit(username);
CREATE INDEX CONCURRENTLY idx_device_config_audit_action ON device_config_audit(action);
CREATE INDEX CONCURRENTLY idx_device_config_audit_time ON device_config_audit(time);
CREATE INDEX CONCURRENTLY idx_device_config_audit_device_time ON device_config_audit(device_id, time DESC);
```

## 🛠️ Использование

### Автоматическая оптимизация при запуске

Индексы создаются автоматически при запуске приложения в функции `startup_event()`.

### Ручная оптимизация

```bash
# Запуск скрипта оптимизации
python scripts/optimize_database.py
```

### Программное использование

```python
from app.database_indexes import optimize_database_performance

# Запуск полной оптимизации
await optimize_database_performance()

# Создание только индексов
from app.database_indexes import create_database_indexes
await create_database_indexes()

# Анализ статистики
from app.database_indexes import analyze_table_statistics
await analyze_table_statistics()
```

## 📈 Мониторинг производительности

### Получение статистики использования индексов

```python
from app.database_indexes import get_index_usage_statistics

stats = await get_index_usage_statistics()
for stat in stats:
    print(f"Индекс: {stat['indexname']}")
    print(f"Сканирований: {stat['index_scans']}")
    print(f"Прочитано записей: {stat['tuples_read']}")
```

### Анализ медленных запросов

```python
from app.database_indexes import optimize_slow_queries

await optimize_slow_queries()
```

## 🔍 Диагностика проблем

### Проверка производительности индексов

```sql
-- Анализ использования индексов
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
```

### Поиск медленных запросов

```sql
-- Требует расширение pg_stat_statements
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
```

### Анализ размера таблиц

```sql
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'public'
ORDER BY tablename, attname;
```

## 📝 Логирование

Все операции оптимизации логируются с префиксом `[DB-INDEXES]`:

```
2024-01-15 10:30:00 - INFO - [DB-INDEXES] Starting database indexes creation
2024-01-15 10:30:01 - INFO - [DB-INDEXES] Creating indexes for users table
2024-01-15 10:30:02 - INFO - [DB-INDEXES] All database indexes created successfully
```

## 🚨 Важные замечания

1. **Создание индексов**: Используется `CREATE INDEX CONCURRENTLY` для избежания блокировок
2. **Анализ статистики**: Регулярно выполняется `ANALYZE` для обновления статистики
3. **Мониторинг**: Постоянное отслеживание производительности запросов
4. **Резервное копирование**: Всегда делайте бэкап перед массовыми изменениями


При возникновении проблем с производительностью:

1. Проверьте логи приложения
2. Анализируйте медленные запросы
3. Мониторьте использование ресурсов
4. Обратитесь к документации PostgreSQL 