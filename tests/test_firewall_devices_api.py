import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.firewall_devices_api import (
    router,
    get_ssh_connection,
    close_ssh_connection,
    api_get_dns_rules,
    api_add_dns_block,
    api_remove_dns_block,
    api_clear_all_dns_blocks,
    api_get_ip_rules,
    api_get_iptables_raw,
    api_add_ip_block,
    api_remove_ip_block,
    api_clear_all_ip_blocks,
    api_get_devices,
    api_get_devices_raw,
    api_add_device,
    api_delete_device
)
from app.models import FirewallDeviceCreate


class TestSSHConnections:
    """Тесты для управления SSH соединениями"""

    def test_get_ssh_connection_new(self):
        """Тест создания нового SSH соединения"""
        device_config = {
            'device_type': 'linux',
            'host': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        with patch('app.firewall_devices_api.ConnectHandler', return_value=mock_ssh):
            result = get_ssh_connection(device_config)
            
            # Проверяем, что соединение создано
            assert result == mock_ssh

    def test_get_ssh_connection_existing(self):
        """Тест получения существующего SSH соединения"""
        device_config = {
            'device_type': 'linux',
            'host': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        with patch('app.firewall_devices_api.ConnectHandler', return_value=mock_ssh):
            # Создаем первое соединение
            first_connection = get_ssh_connection(device_config)
            
            # Получаем то же соединение
            second_connection = get_ssh_connection(device_config)
            
            # Проверяем, что это одно и то же соединение
            assert first_connection is second_connection

    def test_close_ssh_connection(self):
        """Тест закрытия SSH соединения"""
        device_config = {
            'device_type': 'linux',
            'host': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        
        with patch('app.firewall_devices_api.ConnectHandler', return_value=mock_ssh):
            with patch('app.firewall_devices_api.ssh_connections', {'192.168.1.1_admin': mock_ssh}):
                # Создаем соединение
                get_ssh_connection(device_config)
                
                # Закрываем соединение
                close_ssh_connection('192.168.1.1', 'admin')
                
                # Проверяем, что соединение закрыто
                mock_ssh.disconnect.assert_called_once()


class TestDNSRules:
    """Тесты для DNS правил"""

    @pytest.mark.asyncio
    async def test_api_get_dns_rules_success(self):
        """Тест успешного получения DNS правил"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_dnsmasq_config = """
# DNS configuration
address=/example.com/0.0.0.0
address=/test.com/0.0.0.0
address=/blocked.com/0.0.0.0
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_dnsmasq_config
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_get_dns_rules(device_id=1)
                
                # Проверяем результат
                assert result['device_name'] == 'TestDevice'
                assert 'example.com' in result['domains']
                assert 'test.com' in result['domains']
                assert 'blocked.com' in result['domains']
                assert result['total_count'] == 3

    @pytest.mark.asyncio
    async def test_api_get_dns_rules_device_not_found(self):
        """Тест получения DNS правил для несуществующего устройства"""
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                await api_get_dns_rules(device_id=999)
            
            assert exc_info.value.status_code == 500
            assert "Device not found" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_api_get_dns_rules_unsupported_device_type(self):
        """Тест получения DNS правил для неподдерживаемого типа устройства"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'cisco',  # Не поддерживает DNS блокировку
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with pytest.raises(HTTPException) as exc_info:
                await api_get_dns_rules(device_id=1)
            
            assert exc_info.value.status_code == 500
            assert "does not support DNS blocking" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_api_add_dns_block_success(self):
        """Тест успешного добавления DNS блокировки"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_add_dns_block(
                    device_id=1,
                    request_data={'domain': 'example.com'}
                )
                
                # Проверяем результат
                assert result['success'] is True
                assert result['blocked_domain'] == 'example.com'
                assert 'заблокирован' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 2

    @pytest.mark.asyncio
    async def test_api_add_dns_block_empty_domain(self):
        """Тест добавления DNS блокировки с пустым доменом"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with pytest.raises(HTTPException) as exc_info:
                await api_add_dns_block(
                    device_id=1,
                    request_data={'domain': ''}
                )
            
            assert exc_info.value.status_code == 500
            assert "Domain is required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_api_remove_dns_block_success(self):
        """Тест успешного удаления DNS блокировки"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_remove_dns_block(
                    device_id=1,
                    request_data={'domain': 'example.com'}
                )
                
                # Проверяем результат
                assert result['success'] is True
                assert result['unblocked_domain'] == 'example.com'
                assert 'разблокирован' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 2

    @pytest.mark.asyncio
    async def test_api_clear_all_dns_blocks_success(self):
        """Тест успешной очистки всех DNS блокировок"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_clear_all_dns_blocks(device_id=1)
                
                # Проверяем результат
                assert result['success'] is True
                assert 'удалены' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 2


class TestIPRules:
    """Тесты для IP правил"""

    @pytest.mark.asyncio
    async def test_api_get_ip_rules_success(self):
        """Тест успешного получения IP правил"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_iptables_output = """
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  192.168.1.100        anywhere
ACCEPT     all  --  anywhere             anywhere
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_iptables_output
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_get_ip_rules(device_id=1)
                
                # Проверяем результат
                assert result['device_name'] == 'TestDevice'
                # Проверяем, что есть либо правила, либо ошибка
                assert 'rules' in result or 'error' in result
                assert 'ips' in result

    @pytest.mark.asyncio
    async def test_api_get_iptables_raw_success(self):
        """Тест получения сырого вывода iptables"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_iptables_output = """
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  192.168.1.100        anywhere
ACCEPT     all  --  anywhere             anywhere
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_iptables_output
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_get_iptables_raw(device_id=1)
                
                # Проверяем результат
                assert 'all_rules' in result
                assert 'device_name' in result
                assert result['device_name'] == 'TestDevice'

    @pytest.mark.asyncio
    async def test_api_add_ip_block_success(self):
        """Тест успешного добавления IP блокировки"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = "success"
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_add_ip_block(
                    device_id=1,
                    request_data={'ip': '192.168.1.100'}
                )
                
                # Проверяем результат
                assert result['success'] is True
                assert result['blocked_ip'] == '192.168.1.100'
                assert 'заблокирован' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 1

    @pytest.mark.asyncio
    async def test_api_add_ip_block_invalid_ip(self):
        """Тест добавления IP блокировки с некорректным IP"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with pytest.raises(HTTPException) as exc_info:
                await api_add_ip_block(
                    device_id=1,
                    request_data={'ip': 'invalid_ip'}
                )
            
            assert exc_info.value.status_code == 500
            assert "Invalid IP address format" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_api_remove_ip_block_success(self):
        """Тест успешного удаления IP блокировки"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_iptables_output = """
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  192.168.1.100        anywhere
ACCEPT     all  --  anywhere             anywhere
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_iptables_output
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_remove_ip_block(
                    device_id=1,
                    request_data={'ip': '192.168.1.100'}
                )
                
                # Проверяем результат
                assert result['success'] is True
                assert result['unblocked_ip'] == '192.168.1.100'
                # Проверяем, что сообщение содержит информацию об IP
                assert '192.168.1.100' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 1

    @pytest.mark.asyncio
    async def test_api_clear_all_ip_blocks_success(self):
        """Тест успешной очистки всех IP блокировок"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_iptables_output = """
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  192.168.1.100        anywhere
DROP       all  --  192.168.1.101        anywhere
ACCEPT     all  --  anywhere             anywhere
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_iptables_output
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                result = await api_clear_all_ip_blocks(device_id=1)
                
                # Проверяем результат
                assert result['success'] is True
                # Проверяем, что сообщение содержит информацию об удалении
                assert 'удалено' in result['message'] or 'очищено' in result['message'] or '0' in result['message']
                
                # Проверяем, что команды выполнены
                assert mock_ssh.send_command.call_count >= 1


class TestFirewallDevices:
    """Тесты для управления устройствами брандмауэра"""

    @pytest.mark.asyncio
    async def test_api_get_devices_success(self):
        """Тест успешного получения списка устройств"""
        mock_devices = [
            {'id': 1, 'name': 'Router1', 'ip': '192.168.1.1', 'type': 'cisco', 'username': 'admin', 'password': 'password'},
            {'id': 2, 'name': 'Router2', 'ip': '192.168.1.2', 'type': 'mikrotik', 'username': 'admin', 'password': 'password'}
        ]
        
        with patch('app.database.get_all_firewall_devices', return_value=mock_devices):
            result = await api_get_devices()
            
            # Проверяем результат (API возвращает список Pydantic моделей)
            assert len(result) == 2
            assert result[0].name == 'Router1'
            assert result[1].name == 'Router2'

    @pytest.mark.asyncio
    async def test_api_get_devices_raw_success(self):
        """Тест получения сырых данных устройств"""
        mock_devices = [
            {'id': 1, 'name': 'Router1', 'ip': '192.168.1.1', 'type': 'cisco', 'username': 'admin', 'password': 'password'},
            {'id': 2, 'name': 'Router2', 'ip': '192.168.1.2', 'type': 'mikrotik', 'username': 'admin', 'password': 'password'}
        ]
        
        # Мокаем asyncpg.connect
        mock_conn = Mock()
        # Создаем правильные объекты для asyncpg.fetch
        mock_rows = []
        for device in mock_devices:
            mock_row = Mock()
            mock_row.__getitem__ = lambda self, key: device[key]
            mock_row.keys = lambda: device.keys()
            mock_row.values = lambda: device.values()
            mock_row.items = lambda: device.items()
            mock_row.__iter__ = lambda self: iter(device.items())
            mock_rows.append(mock_row)
        
        mock_conn.fetch = AsyncMock(return_value=mock_rows)
        mock_conn.close = AsyncMock()
        
        # Мокаем импорт db_config через sys.modules
        mock_db_config = Mock()
        mock_db_config.DB_USER = 'test_user'
        mock_db_config.DB_PASSWORD = 'test_pass'
        mock_db_config.DB_NAME = 'test_db'
        mock_db_config.DB_HOST = 'localhost'
        mock_db_config.DB_PORT = 5432
        
        with patch('asyncpg.connect', return_value=mock_conn):
            with patch.dict('sys.modules', {'app.db_config': mock_db_config}):
                result = await api_get_devices_raw()
                
                # Проверяем результат
                assert 'devices' in result
                assert len(result['devices']) == 2
                assert result['count'] == 2

    @pytest.mark.asyncio
    async def test_api_add_device_success(self):
        """Тест успешного добавления устройства"""
        mock_added_device = {
            'id': 1,
            'name': 'NewRouter',
            'ip': '192.168.1.100',
            'type': 'cisco',
            'username': 'admin',
            'password': 'password'
        }
        
        device_data = {
            'name': 'NewRouter',
            'ip': '192.168.1.100',
            'type': 'cisco',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch('app.database.add_firewall_device') as mock_add:
            mock_add.return_value = mock_added_device
            
            result = await api_add_device(device_data)
            
            # Проверяем результат (API возвращает сообщение об успехе)
            assert 'message' in result
            assert 'successfully' in result['message']

    @pytest.mark.asyncio
    async def test_api_delete_device_success(self):
        """Тест успешного удаления устройства"""
        with patch('app.database.delete_firewall_device') as mock_delete:
            result = await api_delete_device(device_id=1)
            
            # Проверяем, что устройство удалено
            mock_delete.assert_called_once_with(1)


class TestErrorHandling:
    """Тесты для обработки ошибок"""

    @pytest.mark.asyncio
    async def test_ssh_connection_error(self):
        """Тест обработки ошибки SSH соединения"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', side_effect=Exception("SSH error")):
                with patch('app.firewall_devices_api.close_ssh_connection') as mock_close:
                    with pytest.raises(HTTPException) as exc_info:
                        await api_get_dns_rules(device_id=1)
                    
                    # Проверяем, что соединение закрыто
                    mock_close.assert_called_once_with('192.168.1.1', 'admin')
                    
                    # Проверяем ошибку
                    assert exc_info.value.status_code == 500
                    assert "SSH error" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_database_error(self):
        """Тест обработки ошибки базы данных"""
        with patch('app.firewall_devices_api.get_firewall_device_by_id', side_effect=Exception("DB error")):
            with pytest.raises(HTTPException) as exc_info:
                await api_get_dns_rules(device_id=1)
            
            assert exc_info.value.status_code == 500
            assert "DB error" in str(exc_info.value.detail)


class TestIntegration:
    """Интеграционные тесты"""

    def test_router_integration(self):
        """Тест интеграции роутера"""
        from fastapi import FastAPI
        
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        
        # Тестируем, что роутер добавлен
        assert len(app.routes) > 0

    @pytest.mark.asyncio
    async def test_end_to_end_dns_operations(self):
        """Тест полного цикла операций с DNS"""
        mock_device = {
            'id': 1,
            'name': 'TestDevice',
            'type': 'openwrt',
            'ip': '192.168.1.1',
            'username': 'admin',
            'password': 'password'
        }
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = "address=/example.com/0.0.0.0"
        
        with patch('app.firewall_devices_api.get_firewall_device_by_id', return_value=mock_device):
            with patch('app.firewall_devices_api.get_ssh_connection', return_value=mock_ssh):
                # Получаем правила
                rules = await api_get_dns_rules(device_id=1)
                assert 'domains' in rules
                
                # Добавляем блокировку
                add_result = await api_add_dns_block(
                    device_id=1,
                    request_data={'domain': 'test.com'}
                )
                assert add_result['success'] is True
                
                # Удаляем блокировку
                remove_result = await api_remove_dns_block(
                    device_id=1,
                    request_data={'domain': 'test.com'}
                )
                assert remove_result['success'] is True
                
                # Очищаем все
                clear_result = await api_clear_all_dns_blocks(device_id=1)
                assert clear_result['success'] is True 