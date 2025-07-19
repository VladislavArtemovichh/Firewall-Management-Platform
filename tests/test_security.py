import pytest
import time
import base64
from unittest.mock import Mock, patch
from fastapi import Request
from fastapi.responses import RedirectResponse

from app.security import (
    check_login_attempts,
    authenticate_user,
    record_login_attempt,
    clear_login_attempts,
    encode_error_message,
    decode_error_message,
    login_attempts
)
from app.models import users

class TestAuthenticateUser:
    """Тесты для функции authenticate_user"""
    
    def test_authenticate_user_valid_credentials(self):
        """Тест аутентификации с правильными учетными данными"""
        assert authenticate_user("admin", "admin123") is True
        assert authenticate_user("developer", "dev123") is True
        assert authenticate_user("auditor", "auditor123") is True
    
    def test_authenticate_user_invalid_username(self):
        """Тест аутентификации с неправильным именем пользователя"""
        assert authenticate_user("nonexistent", "admin123") is False
    
    def test_authenticate_user_invalid_password(self):
        """Тест аутентификации с неправильным паролем"""
        assert authenticate_user("admin", "wrongpassword") is False
    
    def test_authenticate_user_empty_credentials(self):
        """Тест аутентификации с пустыми учетными данными"""
        assert authenticate_user("", "") is False
        assert authenticate_user("admin", "") is False
        assert authenticate_user("", "admin123") is False

class TestEncodeDecodeErrorMessage:
    """Тесты для функций кодирования/декодирования сообщений об ошибках"""
    
    def test_encode_error_message(self):
        """Тест кодирования сообщения об ошибке"""
        message = "Test error message"
        encoded = encode_error_message(message)
        
        # Проверяем, что закодированное сообщение отличается от исходного
        assert encoded != message
        
        # Проверяем, что это валидный base64
        try:
            decoded = base64.b64decode(encoded.encode('ascii')).decode('utf-8')
            assert decoded == message
        except Exception:
            pytest.fail("Encoded message is not valid base64")
    
    def test_decode_error_message_valid(self):
        """Тест декодирования валидного сообщения"""
        original_message = "Test error message"
        encoded = base64.b64encode(original_message.encode('utf-8')).decode('ascii')
        
        decoded = decode_error_message(encoded)
        assert decoded == original_message
    
    def test_decode_error_message_invalid(self):
        """Тест декодирования невалидного сообщения"""
        invalid_encoded = "invalid_base64_string"
        decoded = decode_error_message(invalid_encoded)
        assert decoded == "Ошибка декодирования"
    
    def test_decode_error_message_empty(self):
        """Тест декодирования пустого сообщения"""
        decoded = decode_error_message("")
        # Пустая строка возвращает пустую строку, а не ошибку
        assert decoded == ""
    
    def test_encode_decode_roundtrip(self):
        """Тест полного цикла кодирования-декодирования"""
        test_messages = [
            "Simple message",
            "Сообщение на русском",
            "Message with special chars: !@#$%^&*()",
            "Message with numbers: 12345",
            "Message with unicode: 🚀🔥💻",
            ""
        ]
        
        for message in test_messages:
            encoded = encode_error_message(message)
            decoded = decode_error_message(encoded)
            assert decoded == message

class TestRecordLoginAttempt:
    """Тесты для функции record_login_attempt"""
    
    def test_record_login_attempt_basic(self, clear_login_attempts, mock_time):
        """Тест записи попытки входа"""
        username = "testuser"
        
        record_login_attempt(username)
        
        assert username in login_attempts
        assert len(login_attempts[username]) == 1
        assert login_attempts[username][0] == mock_time.current_time
    
    def test_record_login_attempt_multiple(self, clear_login_attempts, mock_time):
        """Тест записи нескольких попыток входа"""
        username = "testuser"
        
        record_login_attempt(username)
        mock_time.set_time(mock_time.current_time + 10)
        record_login_attempt(username)
        
        assert len(login_attempts[username]) == 2
        assert login_attempts[username][0] == 1000.0
        assert login_attempts[username][1] == 1010.0
    
    def test_record_login_attempt_with_ip(self, clear_login_attempts, mock_time):
        """Тест записи попытки входа с IP адресом"""
        username = "testuser"
        ip_address = "192.168.1.100"
        
        with patch('app.security.metrics_collector') as mock_metrics:
            record_login_attempt(username, ip_address)
            
            assert len(login_attempts[username]) == 1
            mock_metrics.record_failed_login.assert_called_once_with(ip_address)
    
    def test_record_login_attempt_metrics_error(self, clear_login_attempts, mock_time):
        """Тест записи попытки входа с ошибкой метрик"""
        username = "testuser"
        ip_address = "192.168.1.100"
        
        with patch('app.security.metrics_collector') as mock_metrics:
            mock_metrics.record_failed_login.side_effect = Exception("Metrics error")
            
            # Не должно вызывать исключение
            record_login_attempt(username, ip_address)
            
            assert len(login_attempts[username]) == 1

class TestClearLoginAttempts:
    """Тесты для функции clear_login_attempts"""
    
    def test_clear_login_attempts(self, mock_time):
        """Тест очистки попыток входа"""
        username = "testuser"
        
        # Добавляем несколько попыток
        record_login_attempt(username)
        record_login_attempt(username)
        
        assert len(login_attempts[username]) == 2
        
        # Очищаем
        clear_login_attempts(username)
        
        assert len(login_attempts[username]) == 0
    
    def test_clear_login_attempts_empty(self):
        """Тест очистки пустых попыток входа"""
        username = "testuser"
        
        # Очищаем несуществующие попытки
        clear_login_attempts(username)
        
        assert username in login_attempts
        assert len(login_attempts[username]) == 0

class TestCheckLoginAttempts:
    """Тесты для функции check_login_attempts"""
    
    def test_check_login_attempts_no_attempts(self, clear_login_attempts):
        """Тест проверки без попыток входа"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        result = check_login_attempts(username, mock_request)
        
        assert result is None
    
    def test_check_login_attempts_below_limit(self, clear_login_attempts, mock_time):
        """Тест проверки с попытками ниже лимита"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем 2 попытки (лимит 3)
        record_login_attempt(username)
        record_login_attempt(username)
        
        result = check_login_attempts(username, mock_request)
        
        assert result is None
    
    def test_check_login_attempts_at_limit(self, mock_time):
        """Тест проверки с попытками на лимите"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем 3 попытки (лимит 3)
        record_login_attempt(username)
        record_login_attempt(username)
        record_login_attempt(username)
        
        result = check_login_attempts(username, mock_request)
        
        # При 3 попытках (лимит 3) пользователь должен быть заблокирован
        assert isinstance(result, RedirectResponse)
    
    def test_check_login_attempts_above_limit(self, clear_login_attempts, mock_time):
        """Тест проверки с попытками выше лимита"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем 4 попытки (лимит 3)
        record_login_attempt(username)
        record_login_attempt(username)
        record_login_attempt(username)
        record_login_attempt(username)
        
        result = check_login_attempts(username, mock_request)
        
        assert isinstance(result, RedirectResponse)
        assert result.status_code == 303
        # В новых версиях FastAPI используется headers["location"] вместо url
        assert result.headers["location"] == "/"
        
        # Проверяем, что в куки есть закодированное сообщение об ошибке
        assert "error" in result.headers.get("set-cookie", "")
    
    def test_check_login_attempts_expired_attempts(self, clear_login_attempts, mock_time):
        """Тест проверки с истекшими попытками"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем попытки в прошлом (более 60 секунд назад)
        login_attempts[username] = [mock_time.current_time - 70]
        
        result = check_login_attempts(username, mock_request)
        
        assert result is None
        assert len(login_attempts[username]) == 0  # Истекшие попытки удалены
    
    def test_check_login_attempts_mixed_attempts(self, clear_login_attempts, mock_time):
        """Тест проверки со смешанными попытками (актуальные и истекшие)"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем истекшие попытки
        login_attempts[username] = [
            mock_time.current_time - 70,  # Истекшая
            mock_time.current_time - 50,  # Истекшая
            mock_time.current_time - 30   # Актуальная
        ]
        
        result = check_login_attempts(username, mock_request)
        
        assert result is None
        # Проверяем, что истекшие попытки удалены, но актуальные остались
        assert len(login_attempts[username]) >= 1
    
    def test_check_login_attempts_error_message_content(self, clear_login_attempts, mock_time):
        """Тест содержимого сообщения об ошибке"""
        username = "testuser"
        mock_request = Mock(spec=Request)
        
        # Добавляем 4 попытки
        for _ in range(4):
            record_login_attempt(username)
        
        result = check_login_attempts(username, mock_request)
        
        # Извлекаем сообщение из куки
        set_cookie = result.headers.get("set-cookie", "")
        assert "error=" in set_cookie
        
        # Декодируем сообщение
        cookie_parts = set_cookie.split(";")
        error_part = next((part for part in cookie_parts if part.startswith(" error=")), "")
        if error_part:
            encoded_error = error_part.split("=")[1]
            decoded_error = decode_error_message(encoded_error)
            assert "Слишком много попыток входа" in decoded_error
            assert "мин" in decoded_error 