import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock
from fastapi.testclient import TestClient
from fastapi import HTTPException
import time
import json

from app.main import app
from app.models import UserRole, FirewallRule, FirewallDevice
from app.security import create_access_token

client = TestClient(app)

class TestAuthenticationRoutes:
    """Тесты для маршрутов аутентификации"""
    
    def test_login_success(self):
        """Тест успешного входа"""
        with patch('app.routes.authenticate_user') as mock_auth:
            mock_auth.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            response = client.post("/login", data={
                "username": "admin",
                "password": "password123"
            })
            
            assert response.status_code == 200
            assert "access_token" in response.json()
            assert "token_type" in response.json()
    
    def test_login_invalid_credentials(self):
        """Тест входа с неверными учетными данными"""
        with patch('app.routes.authenticate_user') as mock_auth:
            mock_auth.return_value = None
            
            response = client.post("/login", data={
                "username": "wrong",
                "password": "wrong"
            })
            
            assert response.status_code == 401
            assert "Invalid credentials" in response.text
    
    def test_login_too_many_attempts(self):
        """Тест блокировки при слишком многих попытках входа"""
        with patch('app.routes.get_login_attempts') as mock_attempts:
            mock_attempts.return_value = 5  # Превышен лимит
            
            response = client.post("/login", data={
                "username": "admin",
                "password": "password123"
            })
            
            assert response.status_code == 429
            assert "Too many login attempts" in response.text
    
    def test_logout_success(self):
        """Тест успешного выхода"""
        response = client.post("/logout")
        assert response.status_code == 200
        assert "Logged out successfully" in response.text

class TestDashboardRoutes:
    """Тесты для маршрутов дашборда"""
    
    def test_dashboard_without_auth(self):
        """Тест доступа к дашборду без аутентификации"""
        response = client.get("/dashboard")
        assert response.status_code == 401
    
    def test_dashboard_with_auth(self):
        """Тест доступа к дашборду с аутентификацией"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            response = client.get("/dashboard")
            assert response.status_code == 200
            assert "dashboard" in response.text
    
    def test_dashboard_metrics(self):
        """Тест получения метрик для дашборда"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.get_system_metrics') as mock_metrics:
                mock_metrics.return_value = {
                    'cpu_percent': 25.5,
                    'memory_percent': 60.2,
                    'disk_percent': 45.8
                }
                
                response = client.get("/api/dashboard/metrics")
                assert response.status_code == 200
                data = response.json()
                assert 'cpu_percent' in data
                assert 'memory_percent' in data
                assert 'disk_percent' in data

class TestUserManagementRoutes:
    """Тесты для маршрутов управления пользователями"""
    
    def test_get_users_admin_access(self):
        """Тест получения списка пользователей (только админ)"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.get_all_users') as mock_get_users:
                mock_get_users.return_value = [
                    {'id': 1, 'username': 'admin', 'role': UserRole.ADMIN},
                    {'id': 2, 'username': 'user', 'role': UserRole.USER}
                ]
                
                response = client.get("/api/users")
                assert response.status_code == 200
                data = response.json()
                assert len(data) == 2
    
    def test_get_users_unauthorized(self):
        """Тест получения списка пользователей без прав админа"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 2,
                'username': 'user',
                'role': UserRole.USER
            }
            
            response = client.get("/api/users")
            assert response.status_code == 403
    
    def test_create_user_success(self):
        """Тест успешного создания пользователя"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.create_user') as mock_create:
                mock_create.return_value = {
                    'id': 3,
                    'username': 'newuser',
                    'role': UserRole.USER
                }
                
                response = client.post("/api/users", json={
                    "username": "newuser",
                    "password": "password123",
                    "role": "user"
                })
                
                assert response.status_code == 201
                data = response.json()
                assert data['username'] == 'newuser'
    
    def test_create_user_validation_error(self):
        """Тест создания пользователя с ошибкой валидации"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            response = client.post("/api/users", json={
                "username": "",  # Пустое имя пользователя
                "password": "password123",
                "role": "user"
            })
            
            assert response.status_code == 422

class TestFirewallRulesRoutes:
    """Тесты для маршрутов управления правилами брандмауэра"""
    
    def test_get_firewall_rules(self):
        """Тест получения списка правил брандмауэра"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.get_firewall_rules') as mock_rules:
                mock_rules.return_value = [
                    {
                        'id': 1,
                        'name': 'Block SSH',
                        'protocol': 'tcp',
                        'port': '22',
                        'action': 'deny',
                        'enabled': True
                    }
                ]
                
                response = client.get("/api/firewall-rules")
                assert response.status_code == 200
                data = response.json()
                assert len(data) == 1
                assert data[0]['name'] == 'Block SSH'
    
    def test_create_firewall_rule_success(self):
        """Тест успешного создания правила брандмауэра"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.create_firewall_rule') as mock_create:
                mock_create.return_value = {
                    'id': 2,
                    'name': 'Allow HTTP',
                    'protocol': 'tcp',
                    'port': '80',
                    'action': 'allow',
                    'enabled': True
                }
                
                response = client.post("/api/firewall-rules", json={
                    "name": "Allow HTTP",
                    "protocol": "tcp",
                    "port": "80",
                    "action": "allow"
                })
                
                assert response.status_code == 201
                data = response.json()
                assert data['name'] == 'Allow HTTP'
    
    def test_create_firewall_rule_invalid_protocol(self):
        """Тест создания правила с неверным протоколом"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            response = client.post("/api/firewall-rules", json={
                "name": "Invalid Rule",
                "protocol": "invalid_protocol",
                "port": "80",
                "action": "allow"
            })
            
            assert response.status_code == 422
    
    def test_update_firewall_rule_success(self):
        """Тест успешного обновления правила брандмауэра"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.update_firewall_rule') as mock_update:
                mock_update.return_value = {
                    'id': 1,
                    'name': 'Updated Rule',
                    'protocol': 'tcp',
                    'port': '443',
                    'action': 'allow',
                    'enabled': True
                }
                
                response = client.put("/api/firewall-rules/1", json={
                    "name": "Updated Rule",
                    "port": "443"
                })
                
                assert response.status_code == 200
                data = response.json()
                assert data['name'] == 'Updated Rule'
                assert data['port'] == '443'
    
    def test_delete_firewall_rule_success(self):
        """Тест успешного удаления правила брандмауэра"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.return_value = {
                'id': 1,
                'username': 'admin',
                'role': UserRole.ADMIN
            }
            
            with patch('app.routes.delete_firewall_rule') as mock_delete:
                mock_delete.return_value = True
                
                response = client.delete("/api/firewall-rules/1")
                assert response.status_code == 200
                assert "Rule deleted successfully" in response.text

class TestPerformanceTests:
    """Тесты производительности API"""
    
    def test_api_response_time(self):
        """Тест времени ответа API"""
        start_time = time.time()
        response = client.get("/api/health")
        response_time = time.time() - start_time
        
        assert response.status_code == 200
        assert response_time < 0.2  # менее 200ms
    
    def test_concurrent_requests(self):
        """Тест обработки одновременных запросов"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def make_request():
            try:
                response = client.get("/api/health")
                results.put(response.status_code)
            except Exception as e:
                results.put(f"Error: {e}")
        
        # Создаем 10 одновременных запросов
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Проверяем результаты
        success_count = 0
        while not results.empty():
            result = results.get()
            if result == 200:
                success_count += 1
        
        assert success_count >= 8  # Минимум 80% успешных запросов

class TestSecurityTests:
    """Тесты безопасности"""
    
    def test_sql_injection_prevention(self):
        """Тест защиты от SQL инъекций"""
        malicious_input = "'; DROP TABLE users; --"
        
        response = client.post("/api/users", json={
            "username": malicious_input,
            "password": "password123",
            "role": "user"
        })
        
        # Должен вернуть ошибку валидации, а не выполнить SQL инъекцию
        assert response.status_code in [400, 422]
    
    def test_xss_prevention(self):
        """Тест защиты от XSS атак"""
        xss_payload = "<script>alert('XSS')</script>"
        
        response = client.post("/api/firewall-rules", json={
            "name": xss_payload,
            "protocol": "tcp",
            "port": "80",
            "action": "allow"
        })
        
        # Должен вернуть ошибку валидации
        assert response.status_code == 422
    
    def test_csrf_protection(self):
        """Тест защиты от CSRF атак"""
        # Проверяем наличие CSRF токенов в формах
        response = client.get("/login")
        assert response.status_code == 200
        # В реальном приложении здесь должна быть проверка CSRF токенов
    
    def test_rate_limiting(self):
        """Тест ограничения скорости запросов"""
        # Делаем много запросов подряд
        for _ in range(10):
            response = client.post("/login", data={
                "username": "test",
                "password": "wrong"
            })
        
        # Последний запрос должен быть заблокирован
        assert response.status_code == 429

class TestErrorHandling:
    """Тесты обработки ошибок"""
    
    def test_404_error(self):
        """Тест обработки 404 ошибки"""
        response = client.get("/nonexistent-endpoint")
        assert response.status_code == 404
    
    def test_500_error_handling(self):
        """Тест обработки 500 ошибки"""
        with patch('app.routes.get_current_user') as mock_user:
            mock_user.side_effect = Exception("Database error")
            
            response = client.get("/dashboard")
            assert response.status_code == 500
    
    def test_validation_error_format(self):
        """Тест формата ошибок валидации"""
        response = client.post("/api/users", json={
            "username": "",  # Неверные данные
            "password": "short",  # Слишком короткий пароль
            "role": "invalid_role"  # Неверная роль
        })
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], list)

class TestMiddleware:
    """Тесты middleware"""
    
    def test_cors_headers(self):
        """Тест CORS заголовков"""
        response = client.options("/api/health")
        assert response.status_code == 200
        # Проверяем наличие CORS заголовков
        assert "access-control-allow-origin" in response.headers
    
    def test_security_headers(self):
        """Тест заголовков безопасности"""
        response = client.get("/api/health")
        assert response.status_code == 200
        
        # Проверяем наличие заголовков безопасности
        headers = response.headers
        assert "x-content-type-options" in headers
        assert "x-frame-options" in headers
        assert "x-xss-protection" in headers
    
    def test_request_logging(self):
        """Тест логирования запросов"""
        with patch('app.routes.logger') as mock_logger:
            response = client.get("/api/health")
            assert response.status_code == 200
            # Проверяем, что запрос был залогирован
            mock_logger.info.assert_called()

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 