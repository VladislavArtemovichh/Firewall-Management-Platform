# Firewall Management Platform

## Запуск проекта

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

4. **Запустите приложение:**
   ```bash
   uvicorn main:app --reload
   ```
   
   Приложение будет доступно по адресу: http://127.0.0.1:8000

---

- Все HTML-файлы находятся в папке `templates/`.
- Основная логика приложения — в папке `app/`.
- Точка входа — файл `main.py` в корне.

## Docker (опционально)

1. **Соберите образ:**
   ```bash
   docker build -t firewall-platform .
   ```
2. **Запустите контейнер:**
   ```bash
   docker run -p 8000:8000 firewall-platform
   ```

---