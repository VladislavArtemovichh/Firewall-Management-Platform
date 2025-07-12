# Firewall Management Platform

## Запуск проекта (ручной способ)

1. **Клонируйте репозиторий и перейдите в папку проекта:**
   ```bash
   git clone https://github.com/otec2006/Firewall-Management-Platform
   cd Firewall-Management-Platform
   ```

2. **Создайте и активируйте виртуальное окружение (рекомендуется):**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Установите зависимости:**
   ```bash
   pip install -r requirements.txt
   ```

4. Запустите PostgreSQL-сервер.
5. Введите необходимые данные по PostgreSQL-серверу в файл `db_config.py`.

6. **Запустите приложение:**
   ```bash
   uvicorn main:app --reload
   ```
   
   Приложение будет доступно по адресу: http://localhost:8000

## Docker Compose (рекомендуется)

### Быстрый запуск

1. **Запустите все сервисы:**
   ```bash
   docker-compose up --build
   ```

2. **Откройте приложение в браузере:**
   ```
   http://localhost:8000
   ```

### Управление контейнерами

```bash
# Запуск в фоновом режиме
docker-compose up -d

# Остановка
docker-compose down

# Просмотр логов
docker-compose logs app
docker-compose logs db

# Перезапуск
docker-compose restart
```

### Работа с базой данных

**Подключение к PostgreSQL:**
```bash
docker-compose exec db psql -U firewall_user -d firewall_db
```

### Настройка Docker Compose

Перед запуском в продакшене рекомендуется изменить следующие параметры в `docker-compose.yml`:

#### **Безопасность:**
```yaml
# В сервисе db (текущие значения по умолчанию)
environment:
  POSTGRES_USER: firewall_user        # Изменить на уникальное имя
  POSTGRES_PASSWORD: firewall_password # Изменить на сложный пароль
  POSTGRES_DB: firewall_db            # Изменить название БД при необходимости

# В сервисе app (должно совпадать с db)
environment:
  DB_USER: firewall_user              # То же значение, что и POSTGRES_USER
  DB_PASSWORD: firewall_password      # То же значение, что и POSTGRES_PASSWORD
  DB_NAME: firewall_db                # То же значение, что и POSTGRES_DB
```

---
