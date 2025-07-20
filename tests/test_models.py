import pytest
from app.models import (
    UserRole, 
    FirewallRule, 
    FirewallDeviceCreate, 
    FirewallDeviceModel,
    get_role_name,
    users,
    firewall_rules,
    next_rule_id
)

class TestUserRole:
    """Тесты для перечисления ролей пользователей"""
    
    def test_user_role_values(self):
        """Тест проверяет, что все роли имеют правильные значения"""
        assert UserRole.FIREWALL_ADMIN == "firewall-admin"
        assert UserRole.POLICY_DEV == "policy-dev"
        assert UserRole.NETWORK_AUDITOR == "network-auditor"
        assert UserRole.USER == "user"
    
    def test_user_role_enumeration(self):
        """Тест проверяет, что все роли являются строками"""
        for role in UserRole:
            assert isinstance(role.value, str)

class TestFirewallRule:
    """Тесты для класса FirewallRule"""
    
    def test_firewall_rule_creation(self, sample_firewall_rule):
        """Тест создания правила брандмауэра"""
        rule = sample_firewall_rule
        
        assert rule.id == 1
        assert rule.name == "Test Rule"
        assert rule.protocol == "tcp"
        assert rule.port == "80"
        assert rule.direction == "inbound"
        assert rule.action == "allow"
        assert rule.enabled is True
        assert rule.comment == "Test comment"
    
    def test_firewall_rule_without_comment(self):
        """Тест создания правила без комментария"""
        rule = FirewallRule(
            id=2,
            name="Simple Rule",
            protocol="udp",
            port="53",
            direction="outbound",
            action="deny",
            enabled=False
        )
        
        assert rule.comment == ""  # Значение по умолчанию
    
    def test_firewall_rule_with_port_range(self):
        """Тест создания правила с диапазоном портов"""
        rule = FirewallRule(
            id=3,
            name="Port Range Rule",
            protocol="tcp",
            port="80-90",
            direction="inbound",
            action="allow",
            enabled=True
        )
        
        assert rule.port == "80-90"
    
    def test_firewall_rule_without_port(self):
        """Тест создания правила без порта"""
        rule = FirewallRule(
            id=4,
            name="ICMP Rule",
            protocol="icmp",
            port=None,
            direction="inbound",
            action="allow",
            enabled=True
        )
        
        assert rule.port is None

class TestFirewallDeviceCreate:
    """Тесты для Pydantic модели FirewallDeviceCreate"""
    
    def test_firewall_device_create_validation(self):
        """Тест валидации создания устройства"""
        device = FirewallDeviceCreate(
            name="Test Device",
            ip="192.168.1.100",
            type="cisco",
            username="admin",
            password="secret123"
        )
        
        assert device.name == "Test Device"
        assert device.ip == "192.168.1.100"
        assert device.type == "cisco"
        assert device.username == "admin"
        assert device.password == "secret123"
    
    def test_firewall_device_create_from_dict(self):
        """Тест создания устройства из словаря"""
        device_data = {
            "name": "Test Device",
            "ip": "10.0.0.1",
            "type": "fortinet",
            "username": "root",
            "password": "password123"
        }
        
        device = FirewallDeviceCreate(**device_data)
        
        assert device.name == device_data["name"]
        assert device.ip == device_data["ip"]
        assert device.type == device_data["type"]
        assert device.username == device_data["username"]
        assert device.password == device_data["password"]

class TestFirewallDeviceModel:
    """Тесты для Pydantic модели FirewallDeviceModel"""
    
    def test_firewall_device_model_creation(self, sample_firewall_device_model):
        """Тест создания модели устройства"""
        device = sample_firewall_device_model
        
        assert device.id == 1
        assert device.name == "Test Firewall"
        assert device.ip == "192.168.1.1"
        assert device.type == "cisco"
        assert device.username == "admin"
        assert device.password == "password123"
        assert device.status == "Online"
        assert device.last_poll == "2024-01-01 12:00:00"
    
    def test_firewall_device_model_defaults(self):
        """Тест создания модели с значениями по умолчанию"""
        device = FirewallDeviceModel(
            id=1,
            name="Test Device",
            ip="192.168.1.1",
            type="cisco",
            username="admin",
            password="password123"
        )
        
        assert device.status == "Неизвестно"
        assert device.last_poll == "-"

class TestGetRoleName:
    """Тесты для функции get_role_name"""
    
    def test_get_role_name_all_roles(self):
        """Тест получения названий для всех ролей"""
        role_names = {
            UserRole.FIREWALL_ADMIN: "Администратор брандмауэра",
            UserRole.POLICY_DEV: "Разработчик политик",
            UserRole.NETWORK_AUDITOR: "Сетевой аудитор",
            UserRole.USER: "Пользователь"
        }
        
        for role, expected_name in role_names.items():
            assert get_role_name(role) == expected_name
    
    def test_get_role_name_unknown_role(self):
        """Тест для неизвестной роли"""
        # Создаем неизвестную роль
        unknown_role = "unknown-role"
        result = get_role_name(unknown_role)
        assert result == unknown_role

class TestUsersData:
    """Тесты для данных пользователей"""
    
    def test_users_structure(self):
        """Тест структуры данных пользователей"""
        assert "admin" in users
        assert "developer" in users
        assert "auditor" in users
        
        for username, user_data in users.items():
            assert "password" in user_data
            assert "role" in user_data
            assert isinstance(user_data["role"], UserRole)
    
    def test_admin_user(self):
        """Тест данных администратора"""
        admin = users["admin"]
        assert admin["password"] == "admin123"
        assert admin["role"] == UserRole.FIREWALL_ADMIN
    
    def test_developer_user(self):
        """Тест данных разработчика"""
        developer = users["developer"]
        assert developer["password"] == "dev123"
        assert developer["role"] == UserRole.POLICY_DEV
    
    def test_auditor_user(self):
        """Тест данных аудитора"""
        auditor = users["auditor"]
        assert auditor["password"] == "auditor123"
        assert auditor["role"] == UserRole.NETWORK_AUDITOR

class TestFirewallRulesData:
    """Тесты для данных правил брандмауэра"""
    
    def test_firewall_rules_structure(self):
        """Тест структуры данных правил"""
        assert len(firewall_rules) >= 2
        
        for rule in firewall_rules:
            assert isinstance(rule, FirewallRule)
            assert hasattr(rule, 'id')
            assert hasattr(rule, 'name')
            assert hasattr(rule, 'protocol')
            assert hasattr(rule, 'port')
            assert hasattr(rule, 'direction')
            assert hasattr(rule, 'action')
            assert hasattr(rule, 'enabled')
    
    def test_dhcp_rule(self):
        """Тест правила DHCP"""
        dhcp_rule = next((rule for rule in firewall_rules if rule.name == "DHCP"), None)
        assert dhcp_rule is not None
        assert dhcp_rule.protocol == "udp"
        assert dhcp_rule.port == "67-68"
        assert dhcp_rule.direction == "any"
        assert dhcp_rule.action == "allow"
        assert dhcp_rule.enabled is True
        assert dhcp_rule.comment == "DHCP service"
    
    def test_dns_rule(self):
        """Тест правила DNS"""
        dns_rule = next((rule for rule in firewall_rules if rule.name == "DNS"), None)
        assert dns_rule is not None
        assert dns_rule.protocol == "udp"
        assert dns_rule.port == "53"
        assert dns_rule.direction == "outbound"
        assert dns_rule.action == "allow"
        assert dns_rule.enabled is False
        assert dns_rule.comment == "DNS queries" 