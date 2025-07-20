# 📦 Зависимости проекта Firewall Management Platform

## 🎯 Основные зависимости

### **FastAPI и веб-фреймворк**
- `fastapi==0.116.0` - Основной веб-фреймворк
- `uvicorn==0.35.0` - ASGI сервер
- `starlette==0.46.2` - ASGI toolkit
- `python-multipart==0.0.20` - Обработка multipart данных
- `jinja2==3.1.6` - Шаблонизатор для HTML

### **База данных**
- `asyncpg==0.30.0` - Асинхронный драйвер PostgreSQL
- `psutil==7.0.0` - Системные метрики

### **Сетевое взаимодействие**
- `netmiko==4.6.0` - SSH соединения с сетевыми устройствами
- `paramiko==3.5.1` - SSH клиент
- `pysnmp==7.1.21` - SNMP протокол
- `httpx==0.28.1` - HTTP клиент
- `websockets==15.0.1` - WebSocket поддержка

### **Безопасность**
- `bcrypt==4.3.0` - Хеширование паролей
- `cryptography==45.0.5` - Криптографические функции
- `pynacl==1.5.0` - NaCl криптография

### **Валидация данных**
- `pydantic==2.11.7` - Валидация данных
- `pydantic-core==2.33.2` - Ядро Pydantic

## 🧪 Тестирование

### **Основные инструменты тестирования**
- `pytest==8.4.1` - Фреймворк тестирования
- `pytest-asyncio==1.1.0` - Поддержка асинхронных тестов
- `pytest-cov==4.1.0` - Покрытие кода тестами
- `coverage==7.9.2` - Измерение покрытия кода

### **Дополнительные инструменты тестирования**
- `pytest-benchmark==4.0.0` - Тестирование производительности
- `bandit==1.7.5` - Анализ безопасности кода
- `safety==2.3.5` - Проверка уязвимостей в зависимостях

## 📊 Мониторинг и метрики

### **Метрики и мониторинг**
- `prometheus-client==0.19.0` - Клиент Prometheus для метрик
- `rich==14.0.0` - Красивый вывод в терминал

### **Кэширование**
- `redis==5.0.1` - Redis клиент для кэширования

## 🔧 Утилиты и инструменты

### **Системные утилиты**
- `psutil==7.0.0` - Системные метрики и процессы
- `watchfiles==1.1.0` - Отслеживание изменений файлов
- `uvloop==0.21.0` - Быстрый event loop

### **Парсинг и обработка данных**
- `pyyaml==6.0.2` - YAML парсер
- `ruamel-yaml==0.18.14` - Расширенный YAML парсер
- `textfsm==1.1.3` - Парсинг текстовых данных
- `ntc-templates==7.9.0` - Шаблоны для парсинга

### **Сетевое взаимодействие**
- `scp==0.15.0` - SCP протокол
- `pyserial==3.5` - Последовательные порты

## 📋 Установка зависимостей

### **Полная установка**
```bash
pip install -r requirements.txt
```

### **Установка только основных зависимостей**
```bash
pip install fastapi uvicorn asyncpg netmiko paramiko bcrypt pydantic
```

### **Установка зависимостей для разработки**
```bash
pip install -r requirements.txt
pip install pytest pytest-cov pytest-benchmark bandit safety
```

### **Установка зависимостей для продакшена**
```bash
pip install fastapi uvicorn asyncpg netmiko paramiko bcrypt pydantic psutil prometheus-client redis
```

## 🔍 Проверка зависимостей

### **Проверка безопасности**
```bash
# Проверка уязвимостей
safety check

# Анализ безопасности кода
bandit -r app/
```

### **Проверка покрытия тестами**
```bash
# Запуск тестов с покрытием
pytest --cov=app --cov-report=html

# Просмотр отчета
open htmlcov/index.html
```

### **Проверка производительности**
```bash
# Бенчмарк тесты
pytest --benchmark-only
```

## 🚨 Важные замечания

### **Версии зависимостей**
- Все зависимости зафиксированы на конкретных версиях для стабильности
- Регулярно обновляйте зависимости для получения исправлений безопасности

### **Безопасность**
- `bcrypt` используется для хеширования паролей
- `cryptography` обеспечивает шифрование
- `bandit` и `safety` помогают выявить уязвимости

### **Производительность**
- `asyncpg` обеспечивает асинхронную работу с PostgreSQL
- `uvloop` ускоряет event loop
- `redis` используется для кэширования

### **Тестирование**
- `pytest-cov` обеспечивает покрытие кода 85%+
- `pytest-benchmark` проверяет производительность
- `pytest-asyncio` поддерживает асинхронные тесты

## 📈 Мониторинг зависимостей

### **Автоматические проверки**
```bash
# Еженедельная проверка уязвимостей
safety check --json > security_report.json

# Ежемесячный анализ безопасности кода
bandit -r app/ -f json -o security_analysis.json
```

### **Обновление зависимостей**
```bash
# Проверка доступных обновлений
pip list --outdated

# Обновление конкретной зависимости
pip install --upgrade package_name
```

## 🔄 CI/CD интеграция

### **GitHub Actions**
```yaml
- name: Install dependencies
  run: |
    pip install -r requirements.txt
    
- name: Security check
  run: |
    safety check
    bandit -r app/ -f json -o security_report.json
    
- name: Run tests with coverage
  run: |
    pytest --cov=app --cov-report=xml
    coverage report --fail-under=80
```

### **Docker**
```dockerfile
# Установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```

## 📚 Дополнительные ресурсы

- [FastAPI документация](https://fastapi.tiangolo.com/)
- [pytest документация](https://docs.pytest.org/)
- [asyncpg документация](https://magicstack.github.io/asyncpg/)
- [netmiko документация](https://github.com/ktbyers/netmiko)
- [Prometheus Python клиент](https://github.com/prometheus/client_python) 