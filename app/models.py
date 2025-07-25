from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel

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

@dataclass
class FirewallRule:
    id: int
    name: str
    protocol: str  # any, tcp, udp, icmp, etc.
    port: str | None  # может быть диапазон или None
    direction: str  # inbound, outbound, any
    action: str  # allow, deny
    enabled: bool
    comment: str | None = ""

# Временное хранилище правил (в будущем будет БД)
firewall_rules: list[FirewallRule] = [
    FirewallRule(id=1, name="DHCP", protocol="udp", port="67-68", direction="any", action="allow", enabled=True, comment="DHCP service"),
    FirewallRule(id=2, name="DNS", protocol="udp", port="53", direction="outbound", action="allow", enabled=False, comment="DNS queries")
]

next_rule_id = 3

# Pydantic-модель для создания firewall-устройства (только нужные поля)
class FirewallDeviceCreate(BaseModel):
    name: str
    ip: str
    type: str
    username: str
    password: str

# Pydantic-модель для вывода firewall-устройства
class FirewallDeviceModel(BaseModel):
    id: int
    name: str
    ip: str
    type: str
    username: str
    password: str
    status: str | None = "Неизвестно"
    last_poll: str | None = "-"

def get_role_name(role: UserRole) -> str:
    """Возвращает читаемое название роли"""
    role_names = {
        UserRole.FIREWALL_ADMIN: "Администратор брандмауэра",
        UserRole.POLICY_DEV: "Разработчик политик",
        UserRole.NETWORK_AUDITOR: "Сетевой аудитор",
        UserRole.USER: "Пользователь"
    }
    return role_names.get(role, str(role)) 
