import pytest
import sys
import os
import asyncio
import signal
from pathlib import Path

# Добавляем корневую директорию проекта в PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Настройка для async тестов
pytest_plugins = ['pytest_asyncio']

from app.models import UserRole, FirewallRule, FirewallDeviceCreate, FirewallDeviceModel
from app.security import login_attempts
from app.database import (
    create_users_table,
    create_user_sessions_table,
    create_firewall_devices_table,
    create_firewall_rules_table,
    create_device_configs_table,
)
from app.database_indexes import create_database_indexes, analyze_table_statistics

@pytest.fixture(scope="session", autouse=True)
def init_db_schema():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(create_users_table())
    loop.run_until_complete(create_user_sessions_table())
    loop.run_until_complete(create_firewall_devices_table())
    loop.run_until_complete(create_firewall_rules_table())
    loop.run_until_complete(create_device_configs_table())
    loop.run_until_complete(create_database_indexes())
    loop.run_until_complete(analyze_table_statistics())

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

# Настройка таймаута для тестов
def pytest_configure(config):
    """Настройка pytest для добавления таймаутов"""
    # Добавляем таймаут 30 секунд для всех тестов
    config.addinivalue_line(
        "addopts", 
        "--timeout=30"
    )

@pytest.fixture(autouse=True)
def timeout_handler():
    """Фикстура для обработки таймаутов в тестах"""
    def timeout_handler(signum, frame):
        raise TimeoutError("Test timeout")
    
    # Устанавливаем обработчик сигнала SIGALRM (только для Unix)
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)  # 30 секунд таймаут
    
    yield
    
    # Отменяем таймаут
    if hasattr(signal, 'SIGALRM'):
        signal.alarm(0) 