# Firewall Management Platform

Платформа для управления брандмауэрами с веб-интерфейсом, мониторингом и аналитикой.

[![Tests](https://img.shields.io/badge/tests-101%20passed-brightgreen)](https://github.com/otec2006/Firewall-Management-Platform)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](https://github.com/otec2006/Firewall-Management-Platform)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://docker.com)


## ✨ Возможности

- 🔐 **Аутентификация и авторизация** - ролевая система доступа
- 🛡️ **Управление правилами брандмауэра** - создание, редактирование, удаление
- 📊 **Мониторинг и метрики** - системные и прикладные метрики ([подробнее](docs/METRICS.md))
- 🌐 **Сетевой мониторинг** - интерфейсы, адаптеры, статистика
- 📝 **Аудит и логирование** - полная история изменений
- 🐳 **Docker поддержка** - легкое развертывание ([подробнее](docs/DOCKER.md))
- 🧪 **Полное тестирование** - 95%+ покрытие кода ([подробнее](docs/TESTING.md))

## 🚀 Быстрый старт

### Запуск проекта (ручной способ)

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