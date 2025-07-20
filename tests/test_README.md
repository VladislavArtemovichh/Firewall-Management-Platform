# 🧪 Тесты для Firewall Management Platform

Этот каталог содержит полный набор тестов для платформы управления брандмауэрами.

## 📁 Структура тестов

```
tests/
├── __init__.py                              # Пакет тестов
├── conftest.py                              # Конфигурация pytest и фикстуры
├── test_models.py                           # Тесты моделей данных
├── test_utils.py                            # Тесты утилит
├── test_security.py                         # Тесты безопасности
├── test_api.py                              # Тесты API эндпоинтов
├── test_metrics.py                          # Тесты метрик
├── test_middleware.py                       # Тесты middleware
├── test_network_monitor.py                  # Тесты сетевого мониторинга
├── test_database.py                         # Тесты базы данных
├── test_connections_api.py                  # Базовые тесты connections API
├── test_firewall_devices_api.py             # Базовые тесты firewall devices API
├── test_routes_improved.py                  # Тесты routes
├── test_connections_api_improved.py         # Тесты connections API
├── test_firewall_devices_api_improved.py    # Тесты firewall devices API
├── validation.py                            # Тесты валидации
└── README.md                                # Этот файл
```

## 🚀 Быстрый старт

### Установка зависимостей

```bash
pip install -r requirements.txt
```

### Запуск всех тестов

```bash
# Используя скрипт
python run_tests.py all

# Или напрямую
python -m pytest tests/ -v --cov=app --cov-report=html:htmlcov
```

### Запуск отдельных групп тестов

```bash
# Только unit тесты
python run_tests.py unit

# Только integration тесты
python run_tests.py integration

# Быстрые тесты (без медленных)
python run_tests.py fast

# С детальным отчетом покрытия
python run_tests.py coverage

# Запуск улучшенных тестов
python -m pytest tests/test_routes_improved.py -v
python -m pytest tests/test_connections_api_improved.py -v
python -m pytest tests/test_firewall_devices_api_improved.py -v
```

## 📊 Покрытие кода

Тесты обеспечивают покрытие следующих модулей:

- **models.py** - Модели данных и перечисления
- **utils.py** - Утилиты для парсинга сетевых интерфейсов
- **security.py** - Аутентификация и безопасность
- **metrics.py** - Сбор и анализ метрик
- **routes.py** - API эндпоинты
- **connections_api.py** - API для сетевых соединений
- **firewall_devices_api.py** - API для управления устройствами
- **validation.py** - Валидация входных данных

### 🎯 Текущее покрытие

| Модуль | Покрытие | Статус |
|--------|----------|--------|
| **routes.py** | 85%+ | ✅ Улучшено |
| **connections_api.py** | 80%+ | ✅ Улучшено |
| **firewall_devices_api.py** | 85%+ | ✅ Улучшено |
| **Общее покрытие** | 85%+ | ✅ Достигнуто |

### Требования к покрытию

- **Минимальное покрытие**: 80%
- **Целевое покрытие**: 90%
- **Текущее покрытие**: 85%+ ✅

### Просмотр отчетов покрытия

После запуска тестов с покрытием:

1. **HTML отчет**: `htmlcov/index.html`
2. **Консольный отчет**: выводится в терминал
3. **XML отчет**: `coverage.xml` (для CI/CD)

## 🧪 Типы тестов

### Unit тесты

Тестируют отдельные функции и классы в изоляции:

- `test_models.py` - Тесты моделей данных
- `test_utils.py` - Тесты утилит
- `test_security.py` - Тесты безопасности
- `test_metrics.py` - Тесты метрик
- `test_validation.py` - Тесты валидации

### Integration тесты

Тестируют взаимодействие между компонентами:

- `test_api.py` - Тесты API эндпоинтов
- `test_database.py` - Тесты базы данных
- `test_middleware.py` - Тесты middleware

### Улучшенные тесты

#### `test_routes_improved.py` - Тесты маршрутов

**Категории тестов:**
- **Аутентификация**: login, logout, rate limiting
- **Дашборд**: доступ, метрики, авторизация
- **Управление пользователями**: CRUD операции, роли
- **Правила брандмауэра**: создание, обновление, удаление
- **Производительность**: время ответа < 200ms
- **Безопасность**: SQL инъекции, XSS, CSRF
- **Обработка ошибок**: 404, 500, валидация
- **Middleware**: CORS, security headers, логирование

#### `test_connections_api_improved.py` - Тесты API соединений

**Категории тестов:**
- **Парсинг соединений**: TCP, UDP, hostname
- **Фильтрация**: по протоколу, IP, порту, состоянию
- **Статистика**: по протоколам, состояниям
- **Мониторинг**: запуск/остановка, статус, история
- **Алерты**: создание, получение, обновление, удаление
- **Производительность**: большие объемы данных
- **Валидация**: входные данные, диапазоны портов

#### `test_firewall_devices_api_improved.py` - Тесты API устройств

**Категории тестов:**
- **Управление устройствами**: CRUD операции
- **SSH соединения**: тестирование, статус, ошибки
- **Блокировка IP**: создание, удаление, получение списка
- **Блокировка DNS**: домены, валидация
- **Конфигурация устройств**: получение, резервное копирование, восстановление
- **Производительность**: время ответа, таймауты SSH
- **Безопасность**: SQL инъекции, неавторизованный доступ
- **Обработка ошибок**: устройство не найдено, ошибки SSH

### Фикстуры

В `conftest.py` определены общие фикстуры:

- `sample_firewall_rule` - Тестовое правило брандмауэра
- `sample_firewall_device` - Тестовое устройство
- `clear_login_attempts` - Очистка попыток входа
- `mock_time` - Мокирование времени

## 🏷️ Маркеры тестов

Используйте маркеры для выборочного запуска тестов:

```bash
# Только медленные тесты
pytest -m slow

# Исключить медленные тесты
pytest -m "not slow"

# Только integration тесты
pytest -m integration

# Только unit тесты
pytest -m "not integration"

# 🆕 Только улучшенные тесты
pytest -m improved

# 🆕 Только security тесты
pytest -m security

# 🆕 Только performance тесты
pytest -m performance
```

## 🔧 Конфигурация

### pytest.ini

Основные настройки pytest:

- Автоматическое обнаружение тестов
- Покрытие кода по умолчанию
- Маркеры для категоризации тестов
- Настройки отчетов

### .coveragerc

Настройки покрытия кода:

- Исключение тестовых файлов
- Исключение служебных строк
- Настройки отчетов

## 📝 Написание новых тестов

### Структура теста

```python
import pytest
from app.module import function

class TestFunction:
    """Тесты для функции function"""
    
    def test_function_success(self):
        """Тест успешного выполнения"""
        result = function("test_input")
        assert result == "expected_output"
    
    def test_function_error(self):
        """Тест обработки ошибки"""
        with pytest.raises(ValueError):
            function("invalid_input")
```

### Использование фикстур

```python
def test_with_fixture(sample_firewall_rule):
    """Тест с использованием фикстуры"""
    assert sample_firewall_rule.name == "Test Rule"
```

### Мокирование

```python
from unittest.mock import patch, Mock

def test_with_mock():
    """Тест с мокированием"""
    with patch('app.module.external_function') as mock_func:
        mock_func.return_value = "mocked_result"
        result = function_under_test()
        assert result == "mocked_result"
```

## 🚨 Обработка ошибок

### Типичные проблемы

1. **Импорт ошибки**: Убедитесь, что PYTHONPATH настроен правильно
2. **База данных**: Используйте моки для тестов, не требующих реальной БД
3. **Внешние API**: Всегда мокируйте внешние вызовы

### Отладка тестов

```bash
# Запуск с подробным выводом
pytest -v -s

# Запуск конкретного теста
pytest tests/test_module.py::TestClass::test_method

# Запуск с отладчиком
pytest --pdb

# 🆕 Запуск с детальным покрытием
pytest --cov=app --cov-report=term-missing
```

## 🔄 CI/CD интеграция

### GitHub Actions

```yaml
- name: Run tests
  run: |
    python -m pytest tests/ --cov=app --cov-report=xml
    coverage report --fail-under=80
```

### GitLab CI

```yaml
test:
  script:
    - python -m pytest tests/ --cov=app --cov-report=xml
    - coverage report --fail-under=80
```

## 📈 Метрики качества

### Покрытие кода

- **Цель**: >80%
- **Текущее**: 85%+ ✅

### Время выполнения

- **Unit тесты**: <30 секунд
- **Integration тесты**: <2 минут
- **Полный набор**: <5 минут
- **Улучшенные тесты**: <3 минут

### Стабильность

- **Цель**: 100% прохождение
- **Повторяемость**: Все тесты должны быть детерминированными

## Новые возможности тестирования

### Security Testing

```python
def test_sql_injection_prevention(self):
    """Тест защиты от SQL инъекций"""
    malicious_input = "'; DROP TABLE users; --"
    response = client.post("/api/users", json={"username": malicious_input})
    assert response.status_code == 422  # Ошибка валидации

def test_xss_prevention(self):
    """Тест защиты от XSS атак"""
    xss_input = "<script>alert('XSS')</script>"
    response = client.post("/api/firewall-rules", json={"name": xss_input})
    assert response.status_code == 422
```

### Performance Testing

```python
def test_api_response_time(self):
    """Тест времени ответа API"""
    start_time = time.time()
    response = client.get("/api/dashboard")
    response_time = time.time() - start_time
    
    assert response_time < 0.2  # < 200ms
    assert response.status_code == 200

def test_concurrent_requests(self):
    """Тест одновременных запросов"""
    import threading
    
    def make_request():
        response = client.get("/api/dashboard")
        assert response.status_code == 200
    
    threads = [threading.Thread(target=make_request) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
```

### Validation Testing

```python
def test_input_validation(self):
    """Тест валидации входных данных"""
    invalid_data = {
        "username": "",  # Пустое имя
        "password": "weak",  # Слабый пароль
        "ip_address": "invalid_ip"  # Неверный IP
    }
    
    response = client.post("/api/users", json=invalid_data)
    assert response.status_code == 422
    
    errors = response.json()["detail"]
    assert len(errors) > 0  # Должны быть ошибки валидации
```

## 🤝 Вклад в тесты

1. Создайте тест для новой функциональности
2. Убедитесь, что покрытие не снижается
3. Запустите полный набор тестов
4. Обновите документацию при необходимости
5. Добавьте security и performance тесты для новых API

## 📚 Дополнительные ресурсы

- [pytest документация](https://docs.pytest.org/)
- [pytest-cov документация](https://pytest-cov.readthedocs.io/)
- [unittest.mock документация](https://docs.python.org/3/library/unittest.mock.html)
- [FastAPI testing guide](https://fastapi.tiangolo.com/tutorial/testing/)
- [Security testing best practices](https://owasp.org/www-project-web-security-testing-guide/)
