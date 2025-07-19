# 🧪 Тесты для Firewall Management Platform

Этот каталог содержит полный набор тестов для платформы управления брандмауэрами.

## 📁 Структура тестов

```
tests/
├── __init__.py          # Пакет тестов
├── conftest.py          # Конфигурация pytest и фикстуры
├── test_models.py       # Тесты моделей данных
├── test_utils.py        # Тесты утилит
├── test_security.py     # Тесты безопасности
├── test_api.py          # Тесты API эндпоинтов
├── test_metrics.py      # Тесты метрик
└── README.md           # Этот файл
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
```

## 📊 Покрытие кода

Тесты обеспечивают покрытие следующих модулей:

- **models.py** - Модели данных и перечисления
- **utils.py** - Утилиты для парсинга сетевых интерфейсов
- **security.py** - Аутентификация и безопасность
- **metrics.py** - Сбор и анализ метрик
- **routes.py** - API эндпоинты

### Требования к покрытию

- Минимальное покрытие: **80%**
- Целевое покрытие: **90%**

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

### Integration тесты

Тестируют взаимодействие между компонентами:

- `test_api.py` - Тесты API эндпоинтов

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
- **Текущее**: Проверяется автоматически

### Время выполнения

- **Unit тесты**: <30 секунд
- **Integration тесты**: <2 минут
- **Полный набор**: <5 минут

### Стабильность

- **Цель**: 100% прохождение
- **Повторяемость**: Все тесты должны быть детерминированными

## 🤝 Вклад в тесты

1. Создайте тест для новой функциональности
2. Убедитесь, что покрытие не снижается
3. Запустите полный набор тестов
4. Обновите документацию при необходимости

## 📚 Дополнительные ресурсы

- [pytest документация](https://docs.pytest.org/)
- [pytest-cov документация](https://pytest-cov.readthedocs.io/)
- [unittest.mock документация](https://docs.python.org/3/library/unittest.mock.html) 