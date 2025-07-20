"""
Улучшенные тесты для app/firewall_devices_api.py
Цель: повысить покрытие с 66% до 85%+
"""

import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import json
import time
from datetime import datetime, timedelta

from app.main import app
from app.validation import FirewallDeviceCreate, IPBlockRequest, DNSBlockRequest

client = TestClient(app)

class TestFirewallDevicesAPI:
    """Тесты для API управления firewall устройствами"""
    
    def test_get_firewall_devices_success(self):
        """Тест успешного получения списка устройств"""
        with patch('app.firewall_devices_api.get_firewall_devices') as mock_devices:
            mock_devices.return_value = [
                {
                    'id': 1,
                    'name': 'Router-01',
                    'ip_address': '192.168.1.1',
                    'ssh_port': 22,
                    'device_type': 'cisco',
                    'status': 'online'
                }
            ]
            
            response = client.get("/api/firewall-devices")
            assert response.status_code == 200
            data = response.json()
            assert 'devices' in data
            assert len(data['devices']) == 1
            assert data['devices'][0]['name'] == 'Router-01'
    
    def test_get_firewall_devices_empty(self):
        """Тест получения пустого списка устройств"""
        with patch('app.firewall_devices_api.get_firewall_devices') as mock_devices:
            mock_devices.return_value = []
            
            response = client.get("/api/firewall-devices")
            assert response.status_code == 200
            data = response.json()
            assert 'devices' in data
            assert len(data['devices']) == 0
    
    def test_get_firewall_device_by_id_success(self):
        """Тест получения устройства по ID"""
        with patch('app.firewall_devices_api.get_firewall_device') as mock_device:
            mock_device.return_value = {
                'id': 1,
                'name': 'Router-01',
                'ip_address': '192.168.1.1',
                'ssh_port': 22,
                'device_type': 'cisco',
                'status': 'online'
            }
            
            response = client.get("/api/firewall-devices/1")
            assert response.status_code == 200
            data = response.json()
            assert data['id'] == 1
            assert data['name'] == 'Router-01'
    
    def test_get_firewall_device_not_found(self):
        """Тест получения несуществующего устройства"""
        with patch('app.firewall_devices_api.get_firewall_device') as mock_device:
            mock_device.return_value = None
            
            response = client.get("/api/firewall-devices/999")
            assert response.status_code == 404
            assert "Device not found" in response.text
    
    def test_create_firewall_device_success(self):
        """Тест успешного создания устройства"""
        device_data = {
            "name": "New Router",
            "ip_address": "192.168.1.10",
            "ssh_port": 22,
            "username": "admin",
            "password": "SecurePass123!",
            "device_type": "cisco",
            "description": "New firewall device"
        }
        
        with patch('app.firewall_devices_api.create_firewall_device') as mock_create:
            mock_create.return_value = {
                'id': 2,
                'name': 'New Router',
                'ip_address': '192.168.1.10',
                'ssh_port': 22,
                'device_type': 'cisco',
                'status': 'offline'
            }
            
            response = client.post("/api/firewall-devices", json=device_data)
            assert response.status_code == 201
            data = response.json()
            assert data['name'] == 'New Router'
            assert data['ip_address'] == '192.168.1.10'
    
    def test_create_firewall_device_validation_error(self):
        """Тест создания устройства с ошибкой валидации"""
        invalid_device_data = {
            "name": "",  # Пустое имя
            "ip_address": "invalid_ip",
            "ssh_port": 22,
            "username": "admin",
            "password": "weak",  # Слабый пароль
            "device_type": "cisco"
        }
        
        response = client.post("/api/firewall-devices", json=invalid_device_data)
        assert response.status_code == 422
    
    def test_create_firewall_device_xss_protection(self):
        """Тест защиты от XSS при создании устройства"""
        xss_device_data = {
            "name": "<script>alert('XSS')</script>",
            "ip_address": "192.168.1.1",
            "ssh_port": 22,
            "username": "admin",
            "password": "SecurePass123!",
            "device_type": "cisco"
        }
        
        response = client.post("/api/firewall-devices", json=xss_device_data)
        assert response.status_code == 422
    
    def test_update_firewall_device_success(self):
        """Тест успешного обновления устройства"""
        update_data = {
            "name": "Updated Router",
            "description": "Updated description"
        }
        
        with patch('app.firewall_devices_api.update_firewall_device') as mock_update:
            mock_update.return_value = {
                'id': 1,
                'name': 'Updated Router',
                'ip_address': '192.168.1.1',
                'ssh_port': 22,
                'device_type': 'cisco',
                'description': 'Updated description'
            }
            
            response = client.put("/api/firewall-devices/1", json=update_data)
            assert response.status_code == 200
            data = response.json()
            assert data['name'] == 'Updated Router'
            assert data['description'] == 'Updated description'
    
    def test_delete_firewall_device_success(self):
        """Тест успешного удаления устройства"""
        with patch('app.firewall_devices_api.delete_firewall_device') as mock_delete:
            mock_delete.return_value = True
            
            response = client.delete("/api/firewall-devices/1")
            assert response.status_code == 200
            assert "Device deleted successfully" in response.text
    
    def test_delete_firewall_device_not_found(self):
        """Тест удаления несуществующего устройства"""
        with patch('app.firewall_devices_api.delete_firewall_device') as mock_delete:
            mock_delete.return_value = False
            
            response = client.delete("/api/firewall-devices/999")
            assert response.status_code == 404
            assert "Device not found" in response.text

class TestSSHConnections:
    """Тесты для SSH соединений"""
    
    def test_test_ssh_connection_success(self):
        """Тест успешного SSH соединения"""
        with patch('app.firewall_devices_api.test_ssh_connection') as mock_test:
            mock_test.return_value = {
                'success': True,
                'message': 'Connection successful',
                'device_info': {
                    'hostname': 'Router-01',
                    'version': 'Cisco IOS 15.2'
                }
            }
            
            response = client.post("/api/firewall-devices/1/test-connection")
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'Connection successful' in data['message']
    
    def test_test_ssh_connection_failure(self):
        """Тест неудачного SSH соединения"""
        with patch('app.firewall_devices_api.test_ssh_connection') as mock_test:
            mock_test.return_value = {
                'success': False,
                'message': 'Connection failed: Authentication failed',
                'error': 'SSH_AUTH_FAILED'
            }
            
            response = client.post("/api/firewall-devices/1/test-connection")
            assert response.status_code == 400
            data = response.json()
            assert data['success'] == False
            assert 'Authentication failed' in data['message']
    
    def test_get_device_status_success(self):
        """Тест получения статуса устройства"""
        with patch('app.firewall_devices_api.get_device_status') as mock_status:
            mock_status.return_value = {
                'status': 'online',
                'uptime': '5 days, 2 hours',
                'cpu_usage': 25.5,
                'memory_usage': 60.2,
                'last_seen': '2024-01-01T10:00:00Z'
            }
            
            response = client.get("/api/firewall-devices/1/status")
            assert response.status_code == 200
            data = response.json()
            assert data['status'] == 'online'
            assert 'cpu_usage' in data
            assert 'memory_usage' in data

class TestIPBlocking:
    """Тесты для блокировки IP адресов"""
    
    def test_block_ip_address_success(self):
        """Тест успешной блокировки IP адреса"""
        block_data = {
            "ip_address": "192.168.1.100",
            "reason": "Suspicious activity detected",
            "duration_hours": 24
        }
        
        with patch('app.firewall_devices_api.block_ip_address') as mock_block:
            mock_block.return_value = {
                'success': True,
                'message': 'IP address blocked successfully',
                'rule_id': 123
            }
            
            response = client.post("/api/firewall-devices/1/block-ip", json=block_data)
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'blocked successfully' in data['message']
    
    def test_block_ip_address_invalid_ip(self):
        """Тест блокировки неверного IP адреса"""
        invalid_block_data = {
            "ip_address": "invalid_ip",
            "reason": "Test reason",
            "duration_hours": 24
        }
        
        response = client.post("/api/firewall-devices/1/block-ip", json=invalid_block_data)
        assert response.status_code == 422
    
    def test_block_ip_address_xss_protection(self):
        """Тест защиты от XSS при блокировке IP"""
        xss_block_data = {
            "ip_address": "192.168.1.100",
            "reason": "<script>alert('XSS')</script>",
            "duration_hours": 24
        }
        
        response = client.post("/api/firewall-devices/1/block-ip", json=xss_block_data)
        assert response.status_code == 422
    
    def test_unblock_ip_address_success(self):
        """Тест успешной разблокировки IP адреса"""
        with patch('app.firewall_devices_api.unblock_ip_address') as mock_unblock:
            mock_unblock.return_value = {
                'success': True,
                'message': 'IP address unblocked successfully'
            }
            
            response = client.delete("/api/firewall-devices/1/block-ip/192.168.1.100")
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'unblocked successfully' in data['message']
    
    def test_get_blocked_ips_success(self):
        """Тест получения списка заблокированных IP"""
        with patch('app.firewall_devices_api.get_blocked_ips') as mock_blocked:
            mock_blocked.return_value = [
                {
                    'ip_address': '192.168.1.100',
                    'reason': 'Suspicious activity',
                    'blocked_at': '2024-01-01T10:00:00Z',
                    'expires_at': '2024-01-02T10:00:00Z'
                }
            ]
            
            response = client.get("/api/firewall-devices/1/blocked-ips")
            assert response.status_code == 200
            data = response.json()
            assert 'blocked_ips' in data
            assert len(data['blocked_ips']) == 1
            assert data['blocked_ips'][0]['ip_address'] == '192.168.1.100'

class TestDNSBlocking:
    """Тесты для блокировки доменов"""
    
    def test_block_domain_success(self):
        """Тест успешной блокировки домена"""
        block_data = {
            "domain": "malicious-site.com",
            "reason": "Known malicious domain"
        }
        
        with patch('app.firewall_devices_api.block_domain') as mock_block:
            mock_block.return_value = {
                'success': True,
                'message': 'Domain blocked successfully',
                'rule_id': 456
            }
            
            response = client.post("/api/firewall-devices/1/block-domain", json=block_data)
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'blocked successfully' in data['message']
    
    def test_block_domain_invalid_domain(self):
        """Тест блокировки неверного домена"""
        invalid_block_data = {
            "domain": "invalid-domain-",
            "reason": "Test reason"
        }
        
        response = client.post("/api/firewall-devices/1/block-domain", json=invalid_block_data)
        assert response.status_code == 422
    
    def test_unblock_domain_success(self):
        """Тест успешной разблокировки домена"""
        with patch('app.firewall_devices_api.unblock_domain') as mock_unblock:
            mock_unblock.return_value = {
                'success': True,
                'message': 'Domain unblocked successfully'
            }
            
            response = client.delete("/api/firewall-devices/1/block-domain/malicious-site.com")
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'unblocked successfully' in data['message']
    
    def test_get_blocked_domains_success(self):
        """Тест получения списка заблокированных доменов"""
        with patch('app.firewall_devices_api.get_blocked_domains') as mock_blocked:
            mock_blocked.return_value = [
                {
                    'domain': 'malicious-site.com',
                    'reason': 'Known malicious domain',
                    'blocked_at': '2024-01-01T10:00:00Z'
                }
            ]
            
            response = client.get("/api/firewall-devices/1/blocked-domains")
            assert response.status_code == 200
            data = response.json()
            assert 'blocked_domains' in data
            assert len(data['blocked_domains']) == 1
            assert data['blocked_domains'][0]['domain'] == 'malicious-site.com'

class TestDeviceConfiguration:
    """Тесты для конфигурации устройств"""
    
    def test_get_device_config_success(self):
        """Тест получения конфигурации устройства"""
        with patch('app.firewall_devices_api.get_device_config') as mock_config:
            mock_config.return_value = {
                'config': 'interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown',
                'last_updated': '2024-01-01T10:00:00Z',
                'version': '1.0'
            }
            
            response = client.get("/api/firewall-devices/1/config")
            assert response.status_code == 200
            data = response.json()
            assert 'config' in data
            assert 'interface GigabitEthernet0/0' in data['config']
    
    def test_backup_device_config_success(self):
        """Тест резервного копирования конфигурации"""
        with patch('app.firewall_devices_api.backup_device_config') as mock_backup:
            mock_backup.return_value = {
                'success': True,
                'message': 'Configuration backed up successfully',
                'backup_file': 'router-01-config-20240101-100000.txt'
            }
            
            response = client.post("/api/firewall-devices/1/backup-config")
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'backed up successfully' in data['message']
    
    def test_restore_device_config_success(self):
        """Тест восстановления конфигурации"""
        restore_data = {
            "backup_file": "router-01-config-20240101-100000.txt"
        }
        
        with patch('app.firewall_devices_api.restore_device_config') as mock_restore:
            mock_restore.return_value = {
                'success': True,
                'message': 'Configuration restored successfully'
            }
            
            response = client.post("/api/firewall-devices/1/restore-config", json=restore_data)
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            assert 'restored successfully' in data['message']

class TestPerformanceTests:
    """Тесты производительности API устройств"""
    
    def test_device_api_response_time(self):
        """Тест времени ответа API устройств"""
        start_time = time.time()
        response = client.get("/api/firewall-devices")
        response_time = time.time() - start_time
        
        assert response.status_code == 200
        assert response_time < 0.5  # менее 500ms для API устройств
    
    def test_ssh_connection_timeout(self):
        """Тест таймаута SSH соединения"""
        with patch('app.firewall_devices_api.test_ssh_connection') as mock_test:
            mock_test.side_effect = Exception("Connection timeout")
            
            start_time = time.time()
            response = client.post("/api/firewall-devices/1/test-connection")
            response_time = time.time() - start_time
            
            assert response.status_code == 500
            assert response_time < 1.0  # менее 1 секунды при ошибке

class TestSecurityTests:
    """Тесты безопасности для API устройств"""
    
    def test_sql_injection_protection_devices(self):
        """Тест защиты от SQL инъекций в API устройств"""
        malicious_input = "'; DROP TABLE firewall_devices; --"
        
        response = client.get(f"/api/firewall-devices?name={malicious_input}")
        # Должен вернуть ошибку валидации, а не выполнить SQL инъекцию
        assert response.status_code in [400, 422]
    
    def test_unauthorized_access_protection(self):
        """Тест защиты от неавторизованного доступа"""
        # Тест без аутентификации
        response = client.post("/api/firewall-devices", json={})
        assert response.status_code in [401, 403]
    
    def test_input_validation_strength(self):
        """Тест силы валидации входных данных"""
        # Тест с различными неверными данными
        invalid_inputs = [
            {"name": "", "ip_address": "192.168.1.1"},  # Пустое имя
            {"name": "Test", "ip_address": "invalid_ip"},  # Неверный IP
            {"name": "Test", "ip_address": "192.168.1.1", "ssh_port": 70000},  # Неверный порт
            {"name": "<script>alert('XSS')</script>", "ip_address": "192.168.1.1"}  # XSS
        ]
        
        for invalid_input in invalid_inputs:
            response = client.post("/api/firewall-devices", json=invalid_input)
            assert response.status_code == 422

class TestErrorHandling:
    """Тесты обработки ошибок для API устройств"""
    
    def test_device_not_found_error(self):
        """Тест обработки ошибки 'устройство не найдено'"""
        with patch('app.firewall_devices_api.get_firewall_device') as mock_device:
            mock_device.return_value = None
            
            response = client.get("/api/firewall-devices/999")
            assert response.status_code == 404
            data = response.json()
            assert "not found" in data.get("detail", "").lower()
    
    def test_ssh_connection_error(self):
        """Тест обработки ошибки SSH соединения"""
        with patch('app.firewall_devices_api.test_ssh_connection') as mock_test:
            mock_test.side_effect = Exception("SSH connection failed")
            
            response = client.post("/api/firewall-devices/1/test-connection")
            assert response.status_code == 500
            data = response.json()
            assert "error" in data
    
    def test_validation_error_format(self):
        """Тест формата ошибок валидации"""
        invalid_data = {
            "name": "",  # Пустое имя
            "ip_address": "invalid_ip",  # Неверный IP
            "ssh_port": 70000  # Неверный порт
        }
        
        response = client.post("/api/firewall-devices", json=invalid_data)
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 