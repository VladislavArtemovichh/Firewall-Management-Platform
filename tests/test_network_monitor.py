import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi import HTTPException
from app.network_monitor import device_bandwidth


class TestDeviceBandwidth:
    """Тесты для функции device_bandwidth"""


    @pytest.mark.asyncio
    async def test_device_bandwidth_mikrotik_success(self):
        """Тест успешного получения пропускной способности Mikrotik устройства"""
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = """
Flags: X - disabled, I - invalid, D - dynamic, R - running, S - slave
Columns: NAME, TYPE, ACTUAL-MTU, L2MTU, MAX-L2MTU, MAC-ADDRESS, LAST-LINK-DOWN, LAST-LINK-UP
0 ether1 ether 1500  1500  1500  00:0C:29:12:34:56  jan/01/1970 00:00:00  jan/01/1970 00:00:00 rx-byte=1234567 tx-byte=9876543 rx-packet=1234 tx-packet=5678
1 ether2 ether 1500  1500  1500  00:0C:29:12:34:57  jan/01/1970 00:00:00  jan/01/1970 00:00:00 rx-byte=7654321 tx-byte=1234567 rx-packet=5678 tx-packet=1234
        """
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password', 'mikrotik_routeros')
            
            # Проверяем результат
            assert isinstance(result, dict)
            assert 'interfaces' in result
            assert len(result['interfaces']) == 2

    @pytest.mark.asyncio
    async def test_device_bandwidth_unknown_device_type(self):
        """Тест обработки неизвестного типа устройства"""
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = """
Interface              IHQ   IQD  OHQ   OQD   RXBS  RXPS  TXBS  TXPS  TRTL
GigabitEthernet0/0     0     0    0     0     1000000  567   500000  234   0
        """
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password', 'unknown_device')
            
            # Проверяем, что используется fallback команда
            assert isinstance(result, dict)
            assert 'interfaces' in result
            assert len(result['interfaces']) == 1

    @pytest.mark.asyncio
    async def test_device_bandwidth_empty_output(self):
        """Тест обработки пустого вывода команды"""
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = ""
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password', 'cisco_ios')
            
            # Проверяем результат
            assert isinstance(result, dict)
            assert 'interfaces' in result
            assert len(result['interfaces']) == 0

    @pytest.mark.asyncio
    async def test_device_bandwidth_no_interfaces_found(self):
        """Тест обработки случая, когда интерфейсы не найдены"""
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = """
Interface              IHQ   IQD  OHQ   OQD   RXBS  RXPS  TXBS  TXPS  TRTL
Serial0/0/0           0     0    0     0     0     0     0     0     0
        """
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password', 'cisco_ios')
            
            # Проверяем результат
            assert isinstance(result, dict)
            assert 'interfaces' in result
            assert len(result['interfaces']) == 0

    @pytest.mark.asyncio
    async def test_device_bandwidth_mikrotik_parse_error(self):
        """Тест обработки ошибки парсинга Mikrotik вывода"""
        mock_output = """
Flags: X - disabled, I - invalid, D - dynamic, R - running, S - slave
Columns: NAME, TYPE, ACTUAL-MTU, L2MTU, MAX-L2MTU, MAC-ADDRESS, LAST-LINK-DOWN, LAST-LINK-UP
0 ether1 ether 1500  1500  1500  00:0C:29:12:34:56  jan/01/1970 00:00:00  jan/01/1970 00:00:00
invalid_line_without_rx_tx_data
1 ether2 ether 1500  1500  1500  00:0C:29:12:34:57  jan/01/1970 00:00:00  jan/01/1970 00:00:00 rx-byte=7654321 tx-byte=1234567 rx-packet=5678 tx-packet=1234
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_output
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password', 'mikrotik_routeros')
            
            # Проверяем, что только валидные интерфейсы обработаны
            assert 'interfaces' in result
            # ether1 будет добавлен с дефолтными значениями '0', ether2 с реальными значениями
            assert len(result['interfaces']) == 2
            # Проверяем, что ether2 имеет правильные значения
            ether2_interface = next((i for i in result['interfaces'] if i['name'] == 'ether2'), None)
            assert ether2_interface is not None
            assert ether2_interface['in_traffic'] == '7654321'
            assert ether2_interface['out_traffic'] == '1234567'

    @pytest.mark.asyncio
    async def test_device_bandwidth_connection_error(self):
        """Тест обработки ошибки подключения"""
        mock_connect_handler = Mock()
        mock_connect_handler.side_effect = Exception("Connection failed")
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            with pytest.raises(HTTPException) as exc_info:
                await device_bandwidth('192.168.1.1', 'admin', 'password', 'cisco_ios')
            
            # Проверяем, что исключение правильного типа
            assert exc_info.value.status_code == 500
            assert "Connection failed" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_device_bandwidth_ssh_error(self):
        """Тест обработки ошибки SSH команды"""
        mock_ssh = Mock()
        mock_ssh.send_command.side_effect = Exception("SSH command failed")
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            with pytest.raises(HTTPException) as exc_info:
                await device_bandwidth('192.168.1.1', 'admin', 'password', 'cisco_ios')
            
            # Проверяем, что исключение правильного типа
            assert exc_info.value.status_code == 500
            assert "SSH command failed" in str(exc_info.value.detail)


    @pytest.mark.asyncio
    async def test_device_bandwidth_default_parameters(self):
        """Тест с параметрами по умолчанию"""
        mock_output = """
Interface              IHQ   IQD  OHQ   OQD   RXBS  RXPS  TXBS  TXPS  TRTL
GigabitEthernet0/0     0     0    0     0     1234  567   8901  234   0
        """
        
        mock_ssh = Mock()
        mock_ssh.send_command.return_value = mock_output
        
        # Создаем правильный мок для контекстного менеджера
        mock_context = Mock()
        mock_context.__enter__ = Mock(return_value=mock_ssh)
        mock_context.__exit__ = Mock(return_value=None)
        
        mock_connect_handler = Mock()
        mock_connect_handler.return_value = mock_context
        
        with patch('app.network_monitor.ConnectHandler', mock_connect_handler):
            result = await device_bandwidth('192.168.1.1', 'admin', 'password')
            # device_type по умолчанию = 'cisco_ios'
            
            # Проверяем, что используется cisco_ios по умолчанию
            mock_connect_handler.assert_called_once_with(
                device_type="cisco_ios",
                host="192.168.1.1",
                username="admin",
                password="password"
            )
            
            assert 'interfaces' in result 
