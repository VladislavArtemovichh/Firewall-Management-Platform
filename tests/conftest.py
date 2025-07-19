import pytest
import sys
import os
import asyncio
from pathlib import Path

# Добавляем корневую директорию проекта в PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Настройка для async тестов
pytest_plugins = ['pytest_asyncio']

from app.models import UserRole, FirewallRule, FirewallDeviceCreate, FirewallDeviceModel
from app.security import login_attempts

@pytest.fixture
def sample_firewall_rule():
    """Фикстура для тестового правила брандмауэра"""
    return FirewallRule(
        id=1,
        name="Test Rule",
        protocol="tcp",
        port="80",
        direction="inbound",
        action="allow",
        enabled=True,
        comment="Test comment"
    )

@pytest.fixture
def sample_firewall_device():
    """Фикстура для тестового устройства брандмауэра"""
    return FirewallDeviceCreate(
        name="Test Firewall",
        ip="192.168.1.1",
        type="cisco",
        username="admin",
        password="password123"
    )

@pytest.fixture
def sample_firewall_device_model():
    """Фикстура для модели устройства брандмауэра"""
    return FirewallDeviceModel(
        id=1,
        name="Test Firewall",
        ip="192.168.1.1",
        type="cisco",
        username="admin",
        password="password123",
        status="Online",
        last_poll="2024-01-01 12:00:00"
    )

@pytest.fixture
def clear_login_attempts():
    """Фикстура для очистки попыток входа перед каждым тестом"""
    yield
    login_attempts.clear()

@pytest.fixture
def mock_time(monkeypatch):
    """Фикстура для мокирования времени"""
    class MockTime:
        def __init__(self):
            self.current_time = 1000.0
        
        def time(self):
            return self.current_time
        
        def set_time(self, time_value):
            self.current_time = time_value
    
    mock_time_obj = MockTime()
    monkeypatch.setattr("time.time", mock_time_obj.time)
    return mock_time_obj 