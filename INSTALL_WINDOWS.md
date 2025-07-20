#  Установка Firewall Management Platform на Windows

##  Важные замечания для Windows

### **Проблемы совместимости:**
- `uvloop` не поддерживается на Windows
- Некоторые сетевые функции могут работать по-разному
- PowerShell требует настройки политики выполнения

## Предварительные требования

### **1. Python 3.8+**
```bash
# Проверка версии Python
python --version
```

### **2. Настройка PowerShell**
```powershell
# Разрешить выполнение скриптов (запустить от администратора)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Проверка политики
Get-ExecutionPolicy
```

### **3. Установка PostgreSQL**
- Скачайте и установите PostgreSQL с официального сайта
- Или используйте Docker:
```bash
docker run --name postgres -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres
```

## 🚀 Установка проекта

### **1. Клонирование репозитория**
```bash
git clone <repository-url>
cd Firewall-Management-Platform
```

### **2. Создание виртуального окружения**
```bash
# Создание виртуального окружения
python -m venv .venv

# Активация (PowerShell)
.venv\Scripts\Activate.ps1

# Активация (Command Prompt)
.venv\Scripts\activate.bat
```

### **3. Установка зависимостей**
```bash
# Установка зависимостей для Windows
pip install -r requirements-windows.txt

# Или установка основных зависимостей
pip install fastapi uvicorn asyncpg netmiko paramiko bcrypt pydantic psutil
```

### **4. Настройка базы данных**
```bash
# Создание файла конфигурации
copy db_config_example.py db_config.py

# Редактирование db_config.py
notepad db_config.py
```

**Содержимое db_config.py:**
```python
# Конфигурация базы данных
DB_USER = "postgres"
DB_PASSWORD = "your_password"
DB_NAME = "firewall_platform"
DB_HOST = "localhost"
DB_PORT = 5432
```

### **5. Создание базы данных**
```sql
-- Подключитесь к PostgreSQL и выполните:
CREATE DATABASE firewall_platform;
CREATE USER firewall_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE firewall_platform TO firewall_user;
```

## 🧪 Запуск тестов

### **Установка тестовых зависимостей**
```bash
pip install pytest pytest-cov pytest-asyncio pytest-benchmark
```

### **Запуск тестов**
```bash
# Все тесты
python -m pytest tests/ -v

# Тесты с покрытием
python -m pytest tests/ --cov=app --cov-report=html

# Быстрые тесты
python -m pytest tests/ -m "not slow"
```

## 🚀 Запуск приложения

### **1. Проверка конфигурации**
```bash
# Проверка подключения к базе данных
python -c "from app.database import startup_event; import asyncio; asyncio.run(startup_event())"
```

### **2. Запуск сервера**
```bash
# Запуск через Python
python main.py

# Или через uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### **3. Проверка работы**
- Откройте браузер: http://localhost:8000
- Документация API: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 🔧 Устранение проблем

### **Проблема 1: Ошибка выполнения скриптов PowerShell**
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### **Проблема 2: Ошибка подключения к PostgreSQL**
```bash
# Проверка статуса PostgreSQL
# Windows Services -> PostgreSQL -> Start

# Или через командную строку
net start postgresql-x64-15
```

### **Проблема 3: Ошибка импорта модулей**
```bash
# Установка в режиме разработки
pip install -e .

# Проверка PYTHONPATH
echo $env:PYTHONPATH
```

### **Проблема 4: Ошибки с сетевыми интерфейсами**
```bash
# На Windows некоторые сетевые функции могут не работать
# Используйте моки для тестирования
python -m pytest tests/ -m "not network"
```

## 📊 Мониторинг и логи

### **Просмотр логов**
```bash
# Логи приложения
Get-Content app.log -Wait

# Логи тестов
python -m pytest tests/ -v --tb=short
```

### **Проверка производительности**
```bash
# Бенчмарк тесты (если установлен pytest-benchmark)
python -m pytest tests/ --benchmark-only
```

## 🔒 Безопасность

### **Проверка безопасности кода**
```bash
# Установка инструментов безопасности
pip install bandit safety

# Проверка кода
bandit -r app/

# Проверка зависимостей
safety check
```

## 📚 Дополнительные ресурсы

### **Полезные команды**
```bash
# Очистка кэша pip
pip cache purge

# Обновление pip
python -m pip install --upgrade pip

# Проверка установленных пакетов
pip list
```

### **Отладка**
```bash
# Запуск с отладкой
python -m pdb main.py

# Или через IDE (PyCharm, VS Code)
```

## 🎯 Проверка установки

### **Тест 1: Проверка зависимостей**
```bash
python -c "import fastapi, uvicorn, asyncpg, netmiko; print('Все зависимости установлены!')"
```

### **Тест 2: Проверка базы данных**
```bash
python -c "from app.database import startup_event; import asyncio; asyncio.run(startup_event()); print('База данных настроена!')"
```

### **Тест 3: Запуск тестов**
```bash
python -m pytest tests/test_models.py -v
```

### **Тест 4: Запуск приложения**
```bash
python main.py
# Откройте http://localhost:8000/docs
```

## ✅ Готово!

Если все тесты прошли успешно, ваша установка готова к работе!

**Следующие шаги:**
1. Настройте firewall устройства
2. Создайте пользователей
3. Настройте правила брандмауэра
4. Запустите мониторинг

## 🆘 Поддержка

При возникновении проблем:
1. Проверьте логи приложения
2. Убедитесь, что PostgreSQL запущен
3. Проверьте настройки сети
4. Обратитесь к документации проекта 