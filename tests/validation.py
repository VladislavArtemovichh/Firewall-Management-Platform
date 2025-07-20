from pydantic import BaseModel, field_validator, Field
from typing import Optional, List
import re
import ipaddress
from enum import Enum

class ProtocolType(str, Enum):
    """Поддерживаемые протоколы"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

class ActionType(str, Enum):
    """Типы действий для правил"""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"

class UserRole(str, Enum):
    """Роли пользователей"""
    ADMIN = "admin"
    USER = "user"
    OPERATOR = "operator"

class FirewallRuleCreate(BaseModel):
    """Модель для создания правила брандмауэра с валидацией"""
    name: str = Field(..., min_length=1, max_length=100, description="Название правила")
    protocol: ProtocolType = Field(..., description="Протокол (tcp, udp, icmp, any)")
    source_ip: Optional[str] = Field(None, description="IP адрес источника")
    source_port: Optional[str] = Field(None, description="Порт источника")
    destination_ip: Optional[str] = Field(None, description="IP адрес назначения")
    destination_port: Optional[str] = Field(None, description="Порт назначения")
    action: ActionType = Field(..., description="Действие (allow, deny, drop)")
    enabled: bool = Field(True, description="Активно ли правило")
    description: Optional[str] = Field(None, max_length=500, description="Описание правила")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Валидация названия правила"""
        if not v.strip():
            raise ValueError('Название правила не может быть пустым')
        
        # Проверка на XSS
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Название содержит недопустимые символы')
        
        return v.strip()
    
    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip_address(cls, v):
        """Валидация IP адресов"""
        if v is None:
            return v
        
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f'Неверный IP адрес: {v}')
        
        return v
    
    @field_validator('source_port', 'destination_port')
    @classmethod
    def validate_port(cls, v):
        """Валидация портов"""
        if v is None:
            return v
        
        # Поддержка диапазонов портов (например, "80-90")
        if '-' in v:
            try:
                start, end = map(int, v.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError()
            except ValueError:
                raise ValueError(f'Неверный диапазон портов: {v}')
        else:
            try:
                port = int(v)
                if port < 1 or port > 65535:
                    raise ValueError()
            except ValueError:
                raise ValueError(f'Неверный порт: {v}')
        
        return v
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        """Валидация описания"""
        if v is None:
            return v
        
        # Проверка на XSS в описании
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Описание содержит недопустимые символы')
        
        return v.strip()

class FirewallRuleUpdate(BaseModel):
    """Модель для обновления правила брандмауэра"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    protocol: Optional[ProtocolType] = None
    source_ip: Optional[str] = None
    source_port: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    action: Optional[ActionType] = None
    enabled: Optional[bool] = None
    description: Optional[str] = Field(None, max_length=500)
    
    # Используем те же валидаторы (исправлено для Pydantic V2)
    @field_validator('name')
    @classmethod
    def _validate_name(cls, v):
        return FirewallRuleCreate.validate_name(cls, v)
    
    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def _validate_ip(cls, v):
        return FirewallRuleCreate.validate_ip_address(cls, v)
    
    @field_validator('source_port', 'destination_port')
    @classmethod
    def _validate_port(cls, v):
        return FirewallRuleCreate.validate_port(cls, v)
    
    @field_validator('description')
    @classmethod
    def _validate_description(cls, v):
        return FirewallRuleCreate.validate_description(cls, v)

class FirewallDeviceCreate(BaseModel):
    """Модель для создания firewall устройства"""
    name: str = Field(..., min_length=1, max_length=100)
    ip_address: str = Field(..., description="IP адрес устройства")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH порт")
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    device_type: str = Field(..., description="Тип устройства (cisco, juniper, etc.)")
    description: Optional[str] = Field(None, max_length=500)
    
    @field_validator('name')
    @classmethod
    def validate_device_name(cls, v):
        """Валидация названия устройства"""
        if not v.strip():
            raise ValueError('Название устройства не может быть пустым')
        
        # Проверка на XSS
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Название содержит недопустимые символы')
        
        return v.strip()
    
    @field_validator('ip_address')
    @classmethod
    def validate_device_ip(cls, v):
        """Валидация IP адреса устройства"""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f'Неверный IP адрес устройства: {v}')
        
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        """Валидация сложности пароля"""
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        
        if not re.search(r'\d', v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Пароль должен содержать хотя бы один специальный символ')
        
        return v

class UserCreate(BaseModel):
    """Модель для создания пользователя"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    role: UserRole = Field(UserRole.USER, description="Роль пользователя")
    email: Optional[str] = Field(None, description="Email пользователя")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Валидация имени пользователя"""
        if not v.strip():
            raise ValueError('Имя пользователя не может быть пустым')
        
        # Проверка на SQL инъекции
        if re.search(r'[\'";]', v):
            raise ValueError('Имя пользователя содержит недопустимые символы')
        
        # Проверка на XSS
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Имя пользователя содержит недопустимые символы')
        
        return v.strip().lower()
    
    @field_validator('password')
    @classmethod
    def validate_user_password(cls, v):
        """Валидация пароля пользователя"""
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        
        if not re.search(r'\d', v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        """Валидация email"""
        if v is None:
            return v
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Неверный формат email')
        
        return v.lower()

class LoginRequest(BaseModel):
    """Модель для запроса входа"""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)
    
    @field_validator('username')
    @classmethod
    def validate_login_username(cls, v):
        """Валидация имени пользователя при входе"""
        if not v.strip():
            raise ValueError('Имя пользователя не может быть пустым')
        
        # Проверка на SQL инъекции
        if re.search(r'[\'";]', v):
            raise ValueError('Имя пользователя содержит недопустимые символы')
        
        return v.strip().lower()

class IPBlockRequest(BaseModel):
    """Модель для блокировки IP адреса"""
    ip_address: str = Field(..., description="IP адрес для блокировки")
    reason: str = Field(..., min_length=1, max_length=200, description="Причина блокировки")
    duration_hours: Optional[int] = Field(24, ge=1, le=8760, description="Длительность блокировки в часах")
    
    @field_validator('ip_address')
    @classmethod
    def validate_block_ip(cls, v):
        """Валидация IP адреса для блокировки"""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f'Неверный IP адрес: {v}')
        
        return v
    
    @field_validator('reason')
    @classmethod
    def validate_block_reason(cls, v):
        """Валидация причины блокировки"""
        if not v.strip():
            raise ValueError('Причина блокировки не может быть пустой')
        
        # Проверка на XSS
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Причина содержит недопустимые символы')
        
        return v.strip()

class DNSBlockRequest(BaseModel):
    """Модель для блокировки домена"""
    domain: str = Field(..., description="Домен для блокировки")
    reason: str = Field(..., min_length=1, max_length=200, description="Причина блокировки")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        """Валидация домена"""
        if not v.strip():
            raise ValueError('Домен не может быть пустым')
        
        # Простая проверка формата домена
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, v):
            raise ValueError(f'Неверный формат домена: {v}')
        
        return v.strip().lower()
    
    @field_validator('reason')
    @classmethod
    def validate_dns_block_reason(cls, v):
        """Валидация причины блокировки домена"""
        if not v.strip():
            raise ValueError('Причина блокировки не может быть пустой')
        
        # Проверка на XSS
        if re.search(r'<script|javascript:|on\w+\s*=', v, re.IGNORECASE):
            raise ValueError('Причина содержит недопустимые символы')
        
        return v.strip()

def validate_rule_conflicts(existing_rules: List[dict], new_rule: FirewallRuleCreate) -> List[str]:
    """Проверка конфликтов между правилами"""
    conflicts = []
    
    for rule in existing_rules:
        # Проверка на дублирование
        if (rule['protocol'] == new_rule.protocol and
            rule['source_ip'] == new_rule.source_ip and
            rule['source_port'] == new_rule.source_port and
            rule['destination_ip'] == new_rule.destination_ip and
            rule['destination_port'] == new_rule.destination_port):
            conflicts.append(f"Правило дублирует существующее правило ID: {rule['id']}")
        
        # Проверка на противоречия
        if (rule['protocol'] == new_rule.protocol and
            rule['source_ip'] == new_rule.source_ip and
            rule['source_port'] == new_rule.source_port and
            rule['destination_ip'] == new_rule.destination_ip and
            rule['destination_port'] == new_rule.destination_port and
            rule['action'] != new_rule.action):
            conflicts.append(f"Противоречие с правилом ID: {rule['id']} (разные действия)")
    
    return conflicts

def sanitize_input(input_string: str) -> str:
    """Очистка входных данных от потенциально опасных символов"""
    if not input_string:
        return input_string
    
    # Удаление HTML тегов
    cleaned = re.sub(r'<[^>]+>', '', input_string)
    
    # Удаление JavaScript
    cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
    
    # Удаление событий
    cleaned = re.sub(r'on\w+\s*=', '', cleaned, flags=re.IGNORECASE)
    
    # Удаление SQL инъекций
    cleaned = re.sub(r'[\'";]', '', cleaned)
    
    return cleaned.strip()

def validate_ip_range(ip_range: str) -> bool:
    """Валидация диапазона IP адресов"""
    try:
        if '/' in ip_range:
            # CIDR нотация
            ipaddress.ip_network(ip_range, strict=False)
        elif '-' in ip_range:
            # Диапазон IP
            start_ip, end_ip = ip_range.split('-')
            ipaddress.ip_address(start_ip.strip())
            ipaddress.ip_address(end_ip.strip())
        else:
            # Одиночный IP
            ipaddress.ip_address(ip_range)
        return True
    except ValueError:
        return False 