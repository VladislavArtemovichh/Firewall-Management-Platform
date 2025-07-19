# Docker для Firewall Management Platform

## 🎯 Обзор

Firewall Management Platform использует **Docker** и **Docker Compose** для контейнеризации:

- **FastAPI приложение** - основной веб-сервис (порт 8000)
- **PostgreSQL база данных** - для хранения данных (порт 5432)
- **Docker Compose** - для оркестрации сервисов

## 🏗️ Архитектура

```
┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │    │   PostgreSQL    │
│   (Port 8000)   │◄──►│   (Port 5432)   │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│           Docker Network                │
└─────────────────────────────────────────┘
```

## 📋 Предварительные требования

### Установка Docker

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install docker.io docker-compose

# Windows/macOS
# Скачать Docker Desktop с https://docker.com

# Проверка
docker --version && docker-compose --version
```

## 🚀 Быстрый старт

```bash
# Запуск
docker-compose up -d

# Проверка
curl http://localhost:8000/
open http://localhost:8000/docs

# Остановка
docker-compose down
```

## 🐳 Основные команды

```bash
# Docker Compose
docker-compose up -d           # Запуск в фоне
docker-compose down            # Остановка
docker-compose logs -f         # Логи в реальном времени
docker-compose ps              # Статус сервисов

# Docker
docker ps                      # Активные контейнеры
docker start/stop/restart <name> # Управление контейнером
docker logs -f <name>          # Логи в реальном времени
docker exec -it <name> bash    # Вход в контейнер
docker stats                   # Статистика ресурсов
```

## 📁 Структура

```
docker-compose.yml    # Основная конфигурация
Dockerfile           # Образ приложения
.env                 # Переменные окружения (создать)
```

## 🔧 Переменные окружения

Создайте файл `.env`:

```bash
DB_USER=ilya
DB_PASSWORD=ilya
DB_NAME=test
DB_HOST=db
DB_PORT=5432
DEBUG=true
```

## 🐛 Устранение неполадок

```bash
# Пересборка
docker-compose up --build

# Очистка
docker-compose down -v
docker system prune -a

# Проверка логов
docker-compose logs app
docker-compose logs db
```
