from collections import defaultdict
import time
from enum import Enum

# Конфигурация безопасности
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 60  #  минута в секундах

# Хранилище попыток входа
login_attempts = defaultdict(list)

class UserRole(str, Enum):
    FIREWALL_ADMIN = "firewall-admin"
    POLICY_DEV = "policy-dev"
    NETWORK_AUDITOR = "network-auditor"
    USER = "user"

# Тестовые пользователи с ролями (в продакшене должны быть в базе данных)
users = {
    "admin": {"password": "admin123", "role": UserRole.FIREWALL_ADMIN},
    "developer": {"password": "dev123", "role": UserRole.POLICY_DEV},
    "auditor": {"password": "auditor123", "role": UserRole.NETWORK_AUDITOR}
}

# Счетчик ID для новых пользователей
next_user_id = 4

def get_role_name(role: UserRole) -> str:
    """Возвращает читаемое название роли"""
    role_names = {
        UserRole.FIREWALL_ADMIN: "Администратор брандмауэра",
        UserRole.POLICY_DEV: "Разработчик политик",
        UserRole.NETWORK_AUDITOR: "Сетевой аудитор",
        UserRole.USER: "Пользователь"
    }
    return role_names.get(role, str(role)) 
