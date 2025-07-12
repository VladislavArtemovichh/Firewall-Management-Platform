from collections import defaultdict
import time
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass, field

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
    port: Optional[str]  # может быть диапазон или None
    direction: str  # inbound, outbound, any
    action: str  # allow, deny
    enabled: bool
    comment: Optional[str] = ""

# Временное хранилище правил (в будущем будет БД)
firewall_rules: List[FirewallRule] = [
    FirewallRule(id=1, name="DHCP", protocol="udp", port="67-68", direction="any", action="allow", enabled=True, comment="DHCP service"),
    FirewallRule(id=2, name="DNS", protocol="udp", port="53", direction="outbound", action="allow", enabled=False, comment="DNS queries")
]

next_rule_id = 3

def get_role_name(role: UserRole) -> str:
    """Возвращает читаемое название роли"""
    role_names = {
        UserRole.FIREWALL_ADMIN: "Администратор брандмауэра",
        UserRole.POLICY_DEV: "Разработчик политик",
        UserRole.NETWORK_AUDITOR: "Сетевой аудитор",
        UserRole.USER: "Пользователь"
    }
    return role_names.get(role, str(role)) 
