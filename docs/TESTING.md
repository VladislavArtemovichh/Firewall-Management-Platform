# Руководство по тестированию Firewall Management Platform

## 📋 Содержание

- [Обзор](#обзор)
- [Структура тестов](#структура-тестов)
- [Установка и настройка](#установка-и-настройка)
- [Запуск тестов](#запуск-тестов)
- [Покрытие кода](#покрытие-кода)
- [Типы тестов](#типы-тестов)
- [Написание тестов](#написание-тестов)
- [Моки и фикстуры](#моки-и-фикстуры)
- [Отладка тестов](#отладка-тестов)
- [CI/CD интеграция](#cicd-интеграция)
- [Лучшие практики](#лучшие-практики)
- [Устранение неполадок](#устранение-неполадок)

---

## 🎯 Обзор

Firewall Management Platform использует **pytest** как основной фреймворк для тестирования. Проект включает в себя:

- **Unit тесты** - для тестирования отдельных функций и классов
- **Integration тесты** - для тестирования взаимодействия между компонентами
- **API тесты** - для тестирования REST API endpoints
- **Database тесты** - для тестирования работы с базой данных
- **Mock тесты** - для тестирования с использованием моков внешних зависимостей

### Текущая статистика покрытия

| Метрика | Значение |
|---------|----------|
| **Общее покрытие** | 64% |
| **Количество тестов** | 50+ |
| **Модули с покрытием >90%** | 7 из 11 |
| **Модули с покрытием <60%** | 2 из 11 |

---

## 📁 Структура тестов

```
tests/
├── __init__.py
├── conftest.py                 # Общие фикстуры pytest
├── test_connections_api.py     # Тесты API сетевых соединений
├── test_database.py           # Тесты базы данных
├── test_firewall_devices_api.py # Тесты API устройств
├── test_middleware.py         # Тесты middleware
├── test_models.py             # Тесты Pydantic моделей
├── test_network_monitor.py    # Тесты мониторинга сети
├── test_routes.py             # Тесты маршрутов
├── test_security.py           # Тесты безопасности
└── test_utils.py              # Тесты утилит
```

---

## 🚀 Установка и настройка

### Предварительные требования

```bash
# Python 3.8+
python --version

# Установка зависимостей
pip install -r requirements.txt
```

### Зависимости для тестирования

```bash
# Основные зависимости для тестирования
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
httpx>=0.24.0
```

### Настройка окружения

```bash
# Создание виртуального окружения
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# или
.venv\Scripts\activate     # Windows

# Установка зависимостей
pip install -r requirements.txt
```

---

## 🏃‍♂️ Запуск тестов

### Базовые команды

```bash
# Запуск всех тестов
pytest

# Запуск с подробным выводом
pytest -v

# Запуск с выводом print() statements
pytest -s

# Запуск конкретного теста
pytest tests/test_database.py::test_connection

# Запуск тестов по паттерну
pytest -k "test_connection"
```

### Запуск с покрытием

```bash
# Запуск с отчетом о покрытии
pytest --cov=app

# Запуск с детальным отчетом о покрытии
pytest --cov=app --cov-report=term-missing

# Генерация HTML отчета
pytest --cov=app --cov-report=html

# Генерация XML отчета (для CI/CD)
pytest --cov=app --cov-report=xml
```

### Специальные команды

```bash
# Запуск только быстрых тестов
pytest -m "not slow"

# Запуск только интеграционных тестов
pytest -m "integration"

# Запуск тестов в параллельном режиме
pytest -n auto

# Запуск с остановкой при первой ошибке
pytest -x

# Запуск с максимальным количеством ошибок
pytest --maxfail=5
```

### Использование Makefile

```bash
# Запуск всех тестов
make test

# Запуск тестов с покрытием
make test-coverage

# Очистка кэша и перезапуск тестов
make test-clean
```

---

## 📊 Покрытие кода

### Текущее состояние покрытия

| Модуль | Покрытие | Статус |
|--------|----------|--------|
| `app/__init__.py` | 100% | ✅ |
| `app/middleware.py` | 100% | ✅ |
| `app/models.py` | 100% | ✅ |
| `app/security.py` | 100% | ✅ |
| `app/utils.py` | 100% | ✅ |
| `app/metrics.py` | 98% | ✅ |
| `app/network_monitor.py` | 96% | ✅ |
| `app/firewall_devices_api.py` | 66% | 🟡 |
| `app/database.py` | 62% | 🟡 |
| `app/routes.py` | 57% | 🔴 |
| `app/connections_api.py` | 40% | 🔴 |

### Цели покрытия

- **Минимальное покрытие:** 75%
- **Целевое покрытие:** 85%
- **Критические модули:** 90%+

### Анализ покрытия

```bash
# Генерация отчета о покрытии
pytest --cov=app --cov-report=html --cov-report=term-missing

# Просмотр HTML отчета
open htmlcov/index.html  # Mac
start htmlcov/index.html # Windows
xdg-open htmlcov/index.html  # Linux
```

---

## 🧪 Типы тестов

### 1. Unit тесты

Тестирование отдельных функций и методов:

```python
def test_parse_connection_data():
    """Тест парсинга данных соединения"""
    data = "tcp 192.168.1.1:80 10.0.0.1:12345 ESTABLISHED"
    result = parse_connection_data(data)
    
    assert result['protocol'] == 'tcp'
    assert result['local_ip'] == '192.168.1.1'
    assert result['local_port'] == 80
```

### 2. Integration тесты

Тестирование взаимодействия компонентов:

```python
async def test_database_connection_integration():
    """Тест интеграции с базой данных"""
    async with get_database_connection() as conn:
        result = await conn.fetch("SELECT 1")
        assert result[0][0] == 1
```

### 3. API тесты

Тестирование REST API endpoints:

```python
def test_get_connections_api(client):
    """Тест API получения соединений"""
    response = client.get("/api/connections")
    assert response.status_code == 200
    assert "connections" in response.json()
```

### 4. Mock тесты

Тестирование с использованием моков:

```python
@patch('subprocess.run')
def test_execute_command_mock(mock_run):
    """Тест выполнения команды с моком"""
    mock_run.return_value = Mock(returncode=0, stdout=b"success")
    
    result = execute_command("test_command")
    assert result == "success"
```

---

## ✍️ Написание тестов

### Структура теста

```python
import pytest
from unittest.mock import Mock, patch
from app.module import function_to_test

class TestModuleName:
    """Тесты для модуля ModuleName"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.test_data = {...}
    
    def test_function_name(self):
        """Описание теста"""
        # Arrange
        input_data = self.test_data
        
        # Act
        result = function_to_test(input_data)
        
        # Assert
        assert result == expected_value
    
    def test_function_name_edge_case(self):
        """Тест граничного случая"""
        # Тест с пустыми данными
        result = function_to_test({})
        assert result is None
    
    def test_function_name_error_handling(self):
        """Тест обработки ошибок"""
        with pytest.raises(ValueError):
            function_to_test(invalid_data)
```

### Async тесты

```python
import pytest
import asyncio

@pytest.mark.asyncio
async def test_async_function():
    """Тест асинхронной функции"""
    result = await async_function()
    assert result == expected_value

@pytest.mark.asyncio
async def test_async_function_with_mock():
    """Тест асинхронной функции с моком"""
    with patch('app.module.async_dependency') as mock_dep:
        mock_dep.return_value = Mock()
        result = await async_function()
        assert result == expected_value
```

### Фикстуры

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    """Фикстура для тестового клиента"""
    return TestClient(app)

@pytest.fixture
def mock_database():
    """Фикстура для мока базы данных"""
    with patch('app.database.get_connection') as mock:
        yield mock

@pytest.fixture
def sample_connection_data():
    """Фикстура с тестовыми данными соединения"""
    return {
        "protocol": "tcp",
        "local_ip": "192.168.1.1",
        "local_port": 80,
        "remote_ip": "10.0.0.1",
        "remote_port": 12345,
        "state": "ESTABLISHED"
    }
```

---

## 🎭 Моки и фикстуры

### Основные типы моков

#### 1. Мок subprocess

```python
@patch('subprocess.run')
def test_system_command(mock_run):
    mock_run.return_value = Mock(
        returncode=0,
        stdout=b"command output",
        stderr=b""
    )
    
    result = execute_system_command("test")
    assert result == "command output"
```

#### 2. Мок базы данных

```python
@patch('asyncpg.connect')
async def test_database_operation(mock_connect):
    mock_conn = Mock()
    mock_conn.fetch.return_value = [{'id': 1, 'name': 'test'}]
    mock_connect.return_value.__aenter__.return_value = mock_conn
    
    result = await get_data_from_db()
    assert result[0]['name'] == 'test'
```

#### 3. Мок сетевых соединений

```python
@patch('socket.create_connection')
def test_network_connection(mock_socket):
    mock_socket.return_value = Mock()
    
    result = test_connection("localhost", 8080)
    assert result is True
```

#### 4. Мок файловой системы

```python
@patch('builtins.open', mock_open(read_data="file content"))
def test_file_reading():
    content = read_file("test.txt")
    assert content == "file content"
```

### Контекстные менеджеры

```python
@patch('socket.create_connection')
def test_socket_context_manager(mock_socket):
    mock_socket_instance = Mock()
    mock_socket_instance.__enter__ = Mock(return_value=mock_socket_instance)
    mock_socket_instance.__exit__ = Mock(return_value=None)
    mock_socket.return_value = mock_socket_instance
    
    with create_socket_connection() as sock:
        result = sock.send(b"data")
        assert result == 4
```

---

## 🐛 Отладка тестов

### Полезные флаги pytest

```bash
# Остановка при первой ошибке
pytest -x

# Показать локальные переменные при ошибке
pytest -l

# Запуск с отладчиком
pytest --pdb

# Запуск с отладчиком только при ошибках
pytest --pdbcls=IPython.terminal.debugger:Pdb

# Показать медленные тесты
pytest --durations=10
```

### Отладка с print()

```python
def test_debug_with_print():
    data = complex_calculation()
    print(f"Debug: data = {data}")  # Будет показано с флагом -s
    assert data > 0
```

### Отладка с pdb

```python
def test_debug_with_pdb():
    import pdb; pdb.set_trace()  # Точка останова
    result = function_to_test()
    assert result == expected
```

### Логирование в тестах

```python
import logging

def test_with_logging():
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    
    logger.debug("Debug message")
    logger.info("Info message")
    
    result = function_to_test()
    assert result is not None
```

---

## 🔄 CI/CD интеграция

### GitHub Actions

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run tests
      run: |
        pytest --cov=app --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v1
```

### GitLab CI

```yaml
test:
  stage: test
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - pytest --cov=app --cov-report=xml
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'pytest --cov=app --cov-report=xml'
            }
        }
        stage('Coverage') {
            steps {
                publishCoverage adapters: [coberturaAdapter('coverage.xml')]
            }
        }
    }
}
```

---

## 📋 Лучшие практики

### 1. Именование тестов

```python
# ✅ Хорошо
def test_parse_connection_data_with_valid_input():
def test_parse_connection_data_with_empty_input():
def test_parse_connection_data_with_invalid_format():

# ❌ Плохо
def test_parse():
def test_1():
def test_something():
```

### 2. Структура тестов

```python
# ✅ Хорошо - AAA pattern
def test_function():
    # Arrange - подготовка данных
    input_data = {...}
    expected = {...}
    
    # Act - выполнение действия
    result = function_to_test(input_data)
    
    # Assert - проверка результата
    assert result == expected
```

### 3. Изоляция тестов

```python
# ✅ Хорошо - каждый тест независим
def test_function_1():
    result = function_to_test(data1)
    assert result == expected1

def test_function_2():
    result = function_to_test(data2)
    assert result == expected2

# ❌ Плохо - тесты зависят друг от друга
def test_function_1():
    global shared_data
    shared_data = data1
    result = function_to_test(shared_data)
    assert result == expected1

def test_function_2():
    global shared_data
    result = function_to_test(shared_data)  # Зависит от test_function_1
    assert result == expected2
```

### 4. Использование фикстур

```python
# ✅ Хорошо - переиспользование кода
@pytest.fixture
def sample_data():
    return {"key": "value"}

def test_function_1(sample_data):
    result = function_to_test(sample_data)
    assert result is not None

def test_function_2(sample_data):
    result = another_function(sample_data)
    assert result is not None
```

### 5. Обработка исключений

```python
# ✅ Хорошо - тестирование исключений
def test_function_raises_exception():
    with pytest.raises(ValueError, match="Invalid input"):
        function_to_test(invalid_data)

def test_function_does_not_raise():
    try:
        result = function_to_test(valid_data)
        assert result is not None
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")
```

---

## 🔧 Устранение неполадок

### Частые проблемы

#### 1. Тесты зависают

```bash
# Запуск с таймаутом
pytest --timeout=30

# Запуск с отладкой
pytest -s --tb=short
```

#### 2. Проблемы с async тестами

```python
# ✅ Правильно
@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result == expected

# ❌ Неправильно
def test_async_function():
    result = await async_function()  # Ошибка!
    assert result == expected
```

#### 3. Проблемы с моками

```python
# ✅ Правильно - мок на уровне модуля
@patch('app.module.external_function')
def test_with_mock(mock_function):
    mock_function.return_value = "mocked"
    result = function_to_test()
    assert result == "mocked"

# ❌ Неправильно - мок на уровне объекта
def test_with_mock():
    with patch.object(instance, 'method') as mock:
        # Это может не работать
        pass
```

#### 4. Проблемы с базой данных

```python
# ✅ Правильно - использование транзакций
@pytest.fixture
def db_session():
    with get_database_session() as session:
        yield session
        session.rollback()

def test_database_operation(db_session):
    # Тест с автоматическим откатом
    pass
```

### Отладка медленных тестов

```bash
# Найти медленные тесты
pytest --durations=10

# Профилирование
pytest --profile

# Запуск только быстрых тестов
pytest -m "not slow"
```

### Очистка кэша

```bash
# Очистка кэша pytest
pytest --cache-clear

# Очистка Python кэша
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -name "*.pyc" -delete

# Очистка coverage
rm -rf .coverage htmlcov/
```

---

## 📚 Дополнительные ресурсы

### Документация

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [pytest-mock](https://pytest-mock.readthedocs.io/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)

### Полезные плагины

```bash
# Установка дополнительных плагинов
pip install pytest-xdist      # Параллельное выполнение
pip install pytest-benchmark  # Бенчмаркинг
pip install pytest-html       # HTML отчеты
pip install pytest-json-report # JSON отчеты
```

### Команды для разработки

```bash
# Запуск тестов в режиме разработки
pytest --lf  # Последние неудачные тесты
pytest --ff  # Сначала неудачные тесты
pytest -x    # Остановка при первой ошибке
pytest -k    # Фильтрация по имени теста
```

---

## 📞 Поддержка

При возникновении проблем с тестированием:

1. Проверьте раздел [Устранение неполадок](#устранение-неполадок)
2. Изучите логи pytest с флагом `-v` или `-s`
3. Используйте отладчик с флагом `--pdb`
4. Обратитесь к документации pytest
5. Создайте issue в репозитории проекта

---

*Последнее обновление: $(date)* 