# Firewall Management Platform

Платформа для управления брандмауэрами с веб-интерфейсом, мониторингом и аналитикой.

[![Tests](https://github.com/otec2006/Firewall-Management-Platform/actions/workflows/tests.yml/badge.svg)](https://github.com/otec2006/Firewall-Management-Platform/actions/workflows/tests.yml)
[![Security](https://github.com/otec2006/Firewall-Management-Platform/actions/workflows/security.yml/badge.svg)](https://github.com/otec2006/Firewall-Management-Platform/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/otec2006/Firewall-Management-Platform/branch/main/graph/badge.svg)](https://codecov.io/gh/otec2006/Firewall-Management-Platform)
> Покрытие кода обновляется автоматически из GitHub Actions (workflow [tests.yml](.github/workflows/tests.yml)) после каждого пуша и pull request. Для просмотра подробного отчёта используйте артефакт coverage-html или переходите по ссылке на Codecov.
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://docker.com)

## ✨ Возможности

- 🔐 **Аутентификация и авторизация** — ролевая система доступа
- 🛡️ **Управление правилами брандмауэра** — создание, редактирование, удаление
- 📊 **Мониторинг и метрики** — системные и прикладные метрики ([подробнее](docs/METRICS.md))
- 🌐 **Сетевой мониторинг** — интерфейсы, адаптеры, статистика
- 📝 **Аудит и логирование** — полная история изменений
- 🐳 **Docker поддержка** — легкое развертывание ([подробнее](docs/DOCKER.md))
- 🧪 **Полное тестирование** — 95%+ покрытие кода ([подробнее](docs/TESTING.md))

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

### Запуск с Docker

```bash
docker-compose up -d
```

## 🚦 CI/CD и автоматизация

В проекте используются **GitHub Actions** для автоматизации основных процессов:

- **Тесты (`tests.yml`)** — автоматический запуск unit-тестов с покрытием кода при каждом push и pull request. Используются PostgreSQL и Redis как сервисы, результаты покрытия отправляются в Codecov.
- **Проверка безопасности (`security.yml`)** — статический анализ Python-кода с помощью Bandit при каждом push и pull request.

### 🛠️ Локальная разработка

Для локального запуска тестов и проверки безопасности:

```bash
# Установка зависимостей для разработки
pip install -r requirements.txt
pip install pytest-cov pytest-asyncio pytest-mock ruff bandit

# Запуск тестов с покрытием
python -m pytest tests/ -v --cov=app --cov-report=html

# Линтинг и автоформатирование
ruff check .
ruff format .

# Проверка безопасности (Bandit)
bandit -r app/

# Полный аудит безопасности (Bandit)
make audit
```

### Использование Makefile

Для удобства управления проектом используйте Makefile:

```bash
make help         # Показать все доступные команды
make install      # Установить зависимости
make test         # Запустить тесты
make test-cov     # Запустить тесты с покрытием
make audit        # Запустить аудит безопасности (Bandit)
make docs         # Генерация документации
make clean        # Очистить временные файлы
make dev          # Запустить в режиме разработки
```