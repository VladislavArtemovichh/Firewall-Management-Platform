# Rate Limiting - Быстрый старт

## Установка

### 1. Установите Redis

**Windows:**
```bash
# Скачайте Redis для Windows с https://github.com/microsoftarchive/redis/releases
# Или используйте WSL2 с Redis

# Через Chocolatey
choco install redis-64

# Запустите Redis
redis-server
```

**Linux/macOS:**
```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis

# Запустите Redis
redis-server
```

### 2. Установите зависимости

```bash
pip install -r requirements.txt
```

### 3. Запустите приложение

```bash
python main.py
```

## Тестирование

### Автоматическое тестирование

```bash
python test_rate_limiting.py
```

### Ручное тестирование

```bash
# Быстрые запросы для тестирования лимита
for i in {1..110}; do
  curl -X GET "http://localhost:8000/api/firewall-rules"
done

# Проверка заголовков Rate Limiting
curl -I -X GET "http://localhost:8000/api/firewall-rules"

# Получение статистики
curl -X GET "http://localhost:8000/api/rate-limit/stats"

# Сброс лимитов
curl -X DELETE "http://localhost:8000/api/rate-limit/reset"
```

## Конфигурации

| Тип | Лимит | Окно | Описание |
|-----|-------|------|----------|
| **default** | 100 | 60 сек | Общий лимит |
| **auth** | 5 | 5 мин | Аутентификация |
| **api** | 1000 | 1 час | API endpoints |
| **admin** | 1000 | 60 сек | Админ функции |
| **monitoring** | 10 | 60 сек | Мониторинг |

## Заголовки ответа

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Ошибка 429

```json
{
  "error": "Too Many Requests",
  "message": "Превышен лимит запросов. Попробуйте позже.",
  "retry_after": 45,
  "rate_limit_info": {
    "limit": 100,
    "remaining": 0,
    "reset": 1640995200,
    "reset_time": "2022-01-01T12:00:00",
    "current_requests": 100
  }
}
```

## API Endpoints

- `GET /api/rate-limit/stats` - Статистика Rate Limiting
- `DELETE /api/rate-limit/reset` - Сброс всех лимитов

## Устранение проблем

### Redis недоступен
```
Rate Limiting error: Connection refused
```

**Решение:**
1. Проверьте, что Redis запущен: `redis-cli ping`
2. Проверьте URL: `redis://localhost:6379`
3. При ошибке Rate Limiting отключается автоматически

### Высокая нагрузка
1. Увеличьте лимиты в `app/rate_limiting.py`
2. Добавьте больше Redis серверов
3. Настройте Redis кластер

## Документация

Подробная документация: `docs/RATE_LIMITING.md` 