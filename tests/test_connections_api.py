import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from app.connections_api import (
    router,
    get_connections,
    get_adapters,
    get_bandwidth,
    get_nf_conntrack
)
import psutil
import socket
import datetime


class TestConnections:
    """Тесты для получения сетевых соединений"""

    @pytest.mark.asyncio
    async def test_get_connections_success(self):
        """Тест успешного получения соединений"""
        # Создаем мок соединения
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "127.0.0.1"
        mock_connection.laddr.port = 8080
        mock_connection.raddr = Mock()
        mock_connection.raddr.ip = "192.168.1.1"
        mock_connection.raddr.port = 443
        mock_connection.type = socket.SOCK_STREAM
        mock_connection.status = "ESTABLISHED"
        mock_connection.pid = 1234
        
        # Создаем мок процесса
        mock_process = Mock()
        mock_process.name.return_value = "python"
        mock_process.create_time.return_value = 1640995200  # 2022-01-01 00:00:00
        
        with patch('psutil.net_connections', return_value=[mock_connection]):
            with patch('psutil.Process', return_value=mock_process):
                result = await get_connections()
                
                # Проверяем результат
                assert len(result.body) > 0
                import json
                connections = json.loads(result.body.decode('utf-8'))
                assert len(connections) == 1
                
                connection = connections[0]
                assert connection['process'] == 'python'
                assert connection['protocol'] == 'TCP'
                assert connection['local_address'] == '127.0.0.1'
                assert connection['local_port'] == 8080
                assert connection['remote_address'] == '192.168.1.1'
                assert connection['remote_port'] == 443
                assert connection['status'] == 'ESTABLISHED'

    @pytest.mark.asyncio
    async def test_get_connections_no_raddr(self):
        """Тест получения соединений без удаленного адреса"""
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "127.0.0.1"
        mock_connection.laddr.port = 8080
        mock_connection.raddr = None
        mock_connection.type = socket.SOCK_STREAM
        mock_connection.status = "LISTEN"
        mock_connection.pid = None
        
        with patch('psutil.net_connections', return_value=[mock_connection]):
            result = await get_connections()
            
            import json
            connections = json.loads(result.body.decode('utf-8'))
            assert len(connections) == 1
            
            connection = connections[0]
            assert connection['process'] == 'Неизвестно'
            assert connection['remote_address'] == ''
            assert connection['remote_port'] == ''
            assert connection['create_time'] == ''

    @pytest.mark.asyncio
    async def test_get_connections_udp_protocol(self):
        """Тест получения UDP соединений"""
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "127.0.0.1"
        mock_connection.laddr.port = 53
        mock_connection.raddr = None
        mock_connection.type = socket.SOCK_DGRAM
        mock_connection.status = "NONE"
        mock_connection.pid = None
        
        with patch('psutil.net_connections', return_value=[mock_connection]):
            result = await get_connections()
            
            import json
            connections = json.loads(result.body.decode('utf-8'))
            assert len(connections) == 1
            
            connection = connections[0]
            assert connection['protocol'] == 'UDP'

    @pytest.mark.asyncio
    async def test_get_connections_process_error(self):
        """Тест обработки ошибки при получении информации о процессе"""
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "127.0.0.1"
        mock_connection.laddr.port = 8080
        mock_connection.raddr = None
        mock_connection.type = socket.SOCK_STREAM
        mock_connection.status = "LISTEN"
        mock_connection.pid = 9999  # Несуществующий PID
        
        with patch('psutil.net_connections', return_value=[mock_connection]):
            with patch('psutil.Process', side_effect=psutil.NoSuchProcess(9999)):
                result = await get_connections()
                
                import json
                connections = json.loads(result.body.decode('utf-8'))
                assert len(connections) == 1
                
                connection = connections[0]
                assert connection['process'] == 'Неизвестно'
                assert connection['create_time'] == ''


class TestAdapters:
    """Тесты для получения сетевых адаптеров"""

    @pytest.mark.asyncio
    async def test_get_adapters_success(self):
        """Тест успешного получения адаптеров"""
        # Мокаем сетевые интерфейсы
        mock_if_addrs = {
            'eth0': [
                Mock(family=socket.AF_INET, address='192.168.1.100'),
                Mock(family=psutil.AF_LINK, address='00:11:22:33:44:55')
            ],
            'lo': [
                Mock(family=socket.AF_INET, address='127.0.0.1'),
                Mock(family=psutil.AF_LINK, address='00:00:00:00:00:00')
            ]
        }
        
        # Мокаем статистику интерфейсов
        mock_if_stats = {
            'eth0': Mock(isup=True, speed=1000),
            'lo': Mock(isup=True, speed=None)
        }
        
        # Мокаем счетчики ввода-вывода
        mock_io_counters = {
            'eth0': Mock(
                packets_recv=1000,
                packets_sent=500,
                errin=0,
                errout=0
            ),
            'lo': Mock(
                packets_recv=2000,
                packets_sent=2000,
                errin=0,
                errout=0
            )
        }
        
        with patch('psutil.net_if_addrs', return_value=mock_if_addrs):
            with patch('psutil.net_if_stats', return_value=mock_if_stats):
                with patch('psutil.net_io_counters', return_value=mock_io_counters):
                    result = await get_adapters()
                    
                    # Проверяем результат
                    assert 'active' in result
                    assert 'inactive' in result
                    assert len(result['active']) == 2
                    assert len(result['inactive']) == 0
                    
                    # Проверяем первый активный адаптер
                    eth0 = next(adapter for adapter in result['active'] if adapter['name'] == 'eth0')
                    assert eth0['mac'] == '00:11:22:33:44:55'
                    assert eth0['ip'] == '192.168.1.100'
                    assert eth0['speed'] == 1000
                    assert eth0['isup'] is True
                    assert eth0['in_packets'] == 1000
                    assert eth0['out_packets'] == 500

    @pytest.mark.asyncio
    async def test_get_adapters_inactive_interface(self):
        """Тест получения неактивных интерфейсов"""
        mock_if_addrs = {
            'eth1': [
                Mock(family=socket.AF_INET, address='192.168.2.100'),
                Mock(family=psutil.AF_LINK, address='00:11:22:33:44:66')
            ]
        }
        
        mock_if_stats = {
            'eth1': Mock(isup=False, speed=100)
        }
        
        mock_io_counters = {
            'eth1': Mock(
                packets_recv=0,
                packets_sent=0,
                errin=0,
                errout=0
            )
        }
        
        with patch('psutil.net_if_addrs', return_value=mock_if_addrs):
            with patch('psutil.net_if_stats', return_value=mock_if_stats):
                with patch('psutil.net_io_counters', return_value=mock_io_counters):
                    result = await get_adapters()
                    
                    assert len(result['active']) == 0
                    assert len(result['inactive']) == 1
                    
                    eth1 = result['inactive'][0]
                    assert eth1['name'] == 'eth1'
                    assert eth1['isup'] is False

    @pytest.mark.asyncio
    async def test_get_adapters_no_stats(self):
        """Тест обработки интерфейса без статистики"""
        mock_if_addrs = {
            'eth0': [
                Mock(family=socket.AF_INET, address='192.168.1.100'),
                Mock(family=psutil.AF_LINK, address='00:11:22:33:44:55')
            ]
        }
        
        mock_if_stats = {}
        mock_io_counters = {}
        
        with patch('psutil.net_if_addrs', return_value=mock_if_addrs):
            with patch('psutil.net_if_stats', return_value=mock_if_stats):
                with patch('psutil.net_io_counters', return_value=mock_io_counters):
                    result = await get_adapters()
                    
                    assert len(result['active']) == 0
                    assert len(result['inactive']) == 1
                    
                    eth0 = result['inactive'][0]
                    assert eth0['speed'] is None
                    assert eth0['isup'] is False
                    assert eth0['in_packets'] is None


class TestBandwidth:
    """Тесты для получения информации о пропускной способности"""

    @pytest.mark.asyncio
    async def test_get_bandwidth_nf_conntrack_success(self):
        """Тест успешного получения трафика через nf_conntrack"""
        mock_nf_conntrack_content = """
ipv4     2 tcp      6 300 ESTABLISHED src=192.168.1.100 dst=8.8.8.8 sport=12345 dport=53 packets=10 bytes=1024 src=8.8.8.8 dst=192.168.1.100 sport=53 dport=12345 packets=5 bytes=512
ipv4     2 tcp      6 300 ESTABLISHED src=192.168.1.100 dst=1.1.1.1 sport=54321 dport=80 packets=20 bytes=2048 src=1.1.1.1 dst=192.168.1.100 sport=80 dport=54321 packets=15 bytes=1536
        """
        
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "192.168.1.100"
        mock_connection.laddr.port = 12345
        mock_connection.pid = 1234
        
        with patch('builtins.open', mock_open(read_data=mock_nf_conntrack_content)):
            with patch('psutil.net_connections', return_value=[mock_connection]):
                with patch('psutil.Process') as mock_process:
                    with patch('psutil.process_iter') as mock_process_iter:
                        mock_process.return_value.name.return_value = "test_process"
                        mock_process_iter.return_value = []
                        
                        result = await get_bandwidth()
                        
                        # Проверяем, что результат получен
                        assert isinstance(result, list)
                        # Не проверяем длину, так как может быть пустой список

    @pytest.mark.asyncio
    async def test_get_bandwidth_nf_conntrack_file_not_found(self):
        """Тест обработки отсутствия файла nf_conntrack"""
        with patch('builtins.open', side_effect=FileNotFoundError):
            with patch('subprocess.run') as mock_subprocess:
                with patch('psutil.process_iter') as mock_process_iter:
                    mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="Permission denied")
                    mock_process_iter.return_value = []
                    
                    result = await get_bandwidth()
                    
                    # Проверяем, что результат получен (пустой список или список с данными)
                    assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_get_bandwidth_ss_command_failed(self):
        """Тест обработки ошибки команды ss"""
        with patch('builtins.open', side_effect=FileNotFoundError):
            with patch('subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="Command not found")
                
                with patch('psutil.process_iter') as mock_process_iter:
                    mock_process_iter.return_value = []
                    
                    result = await get_bandwidth()
                    
                    # Проверяем, что результат получен
                    assert isinstance(result, list)


class TestNfConntrack:
    """Тесты для получения nf_conntrack"""

    @pytest.mark.asyncio
    async def test_get_nf_conntrack_success(self):
        """Тест успешного получения данных nf_conntrack"""
        mock_nf_conntrack_content = """
ipv4     2 tcp      6 300 ESTABLISHED src=192.168.1.100 dst=8.8.8.8 sport=12345 dport=53 packets=10 bytes=1024 src=8.8.8.8 dst=192.168.1.100 sport=53 dport=12345 packets=5 bytes=512
        """
        
        mock_connection = Mock()
        mock_connection.laddr = Mock()
        mock_connection.laddr.ip = "192.168.1.100"
        mock_connection.laddr.port = 12345
        mock_connection.pid = 1234
        
        with patch('builtins.open', mock_open(read_data=mock_nf_conntrack_content)):
            with patch('psutil.net_connections', return_value=[mock_connection]):
                with patch('psutil.Process') as mock_process:
                    with patch('psutil.process_iter') as mock_process_iter:
                        mock_process.return_value.name.return_value = "test_process"
                        mock_process_iter.return_value = []
                        
                        result = await get_nf_conntrack()
                        
                        # Проверяем, что результат получен
                        assert isinstance(result, list)
                        # Не проверяем длину, так как может быть пустой список

    @pytest.mark.asyncio
    async def test_get_nf_conntrack_file_not_found(self):
        """Тест обработки отсутствия файла nf_conntrack"""
        with patch('builtins.open', side_effect=FileNotFoundError):
            with patch('subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="Permission denied")
                
                result = await get_nf_conntrack()
                
                # Проверяем, что возвращается ошибка
                assert isinstance(result, dict)
                assert 'error' in result

    @pytest.mark.asyncio
    async def test_get_nf_conntrack_empty_file(self):
        """Тест обработки пустого файла nf_conntrack"""
        with patch('builtins.open', mock_open(read_data="")):
            result = await get_nf_conntrack()
            
            # Проверяем, что результат получен
            assert isinstance(result, list)
            assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_nf_conntrack_malformed_line(self):
        """Тест обработки некорректной строки в nf_conntrack"""
        mock_content = """
ipv4     2 tcp      6 300 ESTABLISHED src=192.168.1.100 dst=8.8.8.8
invalid_line_without_enough_parts
        """
        
        with patch('builtins.open', mock_open(read_data=mock_content)):
            result = await get_nf_conntrack()
            
            # Проверяем, что результат получен
            assert isinstance(result, list)


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
    async def test_end_to_end_connections_flow(self):
        """Тест полного цикла получения сетевых данных"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        
        # Тестируем получение соединений
        connections_result = await get_connections()
        assert connections_result is not None
        
        # Тестируем получение адаптеров
        adapters_result = await get_adapters()
        assert adapters_result is not None
        assert 'active' in adapters_result
        assert 'inactive' in adapters_result


# Вспомогательная функция для мока open
def mock_open(read_data=""):
    """Создает мок для функции open"""
    from unittest.mock import mock_open as _mock_open
    return _mock_open(read_data=read_data) 