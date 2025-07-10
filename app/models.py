from collections import defaultdict
import time

# Конфигурация безопасности
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 900  # 15 минут в секундах

# Хранилище попыток входа
login_attempts = defaultdict(list)

# Тестовые пользователи (в продакшене должны быть в базе данных)
users = {
    "admin": "admin",
    "user1": "pass1",
    "user2": "pass2"
} 