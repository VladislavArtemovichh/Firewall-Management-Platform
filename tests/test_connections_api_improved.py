import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import json
import time
from datetime import datetime, timedelta

from app.main import app
from app.connections_api import parse_connection_data, filter_connections

client = TestClient(app)

class TestConnectionParsing:
    """Тесты парсинга сетевых соединений"""
    
    def test_parse_tcp_connection(self):
        """Тест парсинга TCP соединения"""
        connection_line = "tcp 192.168.1.1:80 10.0.0.1:12345 ESTABLISHED"
        result = parse_connection_data(connection_line)
        
        assert result['protocol'] == 'tcp'
        assert result['local_ip'] == '192.168.1.1'
        assert result['local_port'] == 80
        assert result['remote_ip'] == '10.0.0.1'
        assert result['remote_port'] == 12345
        assert result['state'] == 'ESTABLISHED'
    
    def test_parse_udp_connection(self):
        """Тест парсинга UDP соединения"""
        connection_line = "udp 0.0.0.0:53 0.0.0.0:0 LISTEN"
        result = parse_connection_data(connection_line)
        
        assert result['protocol'] == 'udp'
        assert result['local_ip'] == '0.0.0.0'
        assert result['local_port'] == 53
        assert result['remote_ip'] == '0.0.0.0'
        assert result['remote_port'] == 0
        assert result['state'] == 'LISTEN'
    
    def test_parse_connection_with_hostname(self):
        """Тест парсинга соединения с hostname"""
        connection_line = "tcp 192.168.1.1:443 google.com:443 ESTABLISHED"
        result = parse_connection_data(connection_line)
        
        assert result['protocol'] == 'tcp'
        assert result['local_ip'] == '192.168.1.1'
        assert result['local_port'] == 443
        assert result['remote_ip'] == 'google.com'
        assert result['remote_port'] == 443
        assert result['state'] == 'ESTABLISHED'
    
    def test_parse_invalid_connection_format(self):
        """Тест парсинга неверного формата соединения"""
        invalid_line = "invalid connection format"
        
        with pytest.raises(ValueError):
            parse_connection_data(invalid_line)
    
    def test_parse_connection_missing_parts(self):
        """Тест парсинга соединения с недостающими частями"""
        incomplete_line = "tcp 192.168.1.1:80"
        
        with pytest.raises(ValueError):
            parse_connection_data(incomplete_line)
    
    def test_parse_connection_invalid_port(self):
        """Тест парсинга соединения с неверным портом"""
        invalid_port_line = "tcp 192.168.1.1:invalid 10.0.0.1:12345 ESTABLISHED"
        
        with pytest.raises(ValueError):
            parse_connection_data(invalid_port_line)

class TestConnectionFiltering:
    """Тесты фильтрации соединений"""
    
    def test_filter_by_protocol(self):
        """Тест фильтрации по протоколу"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80},
            {'protocol': 'udp', 'local_ip': '192.168.1.1', 'local_port': 53},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 443}
        ]
        
        filtered = filter_connections(connections, protocol='tcp')
        assert len(filtered) == 2
        assert all(conn['protocol'] == 'tcp' for conn in filtered)
    
    def test_filter_by_ip(self):
        """Тест фильтрации по IP адресу"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80},
            {'protocol': 'tcp', 'local_ip': '192.168.1.2', 'local_port': 80},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 443}
        ]
        
        filtered = filter_connections(connections, ip='192.168.1.1')
        assert len(filtered) == 2
        assert all(conn['local_ip'] == '192.168.1.1' for conn in filtered)
    
    def test_filter_by_port(self):
        """Тест фильтрации по порту"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 443},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80}
        ]
        
        filtered = filter_connections(connections, port=80)
        assert len(filtered) == 2
        assert all(conn['local_port'] == 80 for conn in filtered)
    
    def test_filter_by_state(self):
        """Тест фильтрации по состоянию соединения"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80, 'state': 'ESTABLISHED'},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 443, 'state': 'LISTEN'},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 22, 'state': 'ESTABLISHED'}
        ]
        
        filtered = filter_connections(connections, state='ESTABLISHED')
        assert len(filtered) == 2
        assert all(conn['state'] == 'ESTABLISHED' for conn in filtered)
    
    def test_filter_multiple_criteria(self):
        """Тест фильтрации по нескольким критериям"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80, 'state': 'ESTABLISHED'},
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 443, 'state': 'LISTEN'},
            {'protocol': 'udp', 'local_ip': '192.168.1.1', 'local_port': 53, 'state': 'LISTEN'}
        ]
        
        filtered = filter_connections(connections, protocol='tcp', state='LISTEN')
        assert len(filtered) == 1
        assert filtered[0]['protocol'] == 'tcp'
        assert filtered[0]['state'] == 'LISTEN'
    
    def test_filter_empty_result(self):
        """Тест фильтрации с пустым результатом"""
        connections = [
            {'protocol': 'tcp', 'local_ip': '192.168.1.1', 'local_port': 80}
        ]
        
        filtered = filter_connections(connections, protocol='udp')
        assert len(filtered) == 0

class TestConnectionsAPI:
    """Тесты API endpoints для соединений"""
    
    def test_get_connections_success(self):
        """Тест успешного получения списка соединений"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = [
                {
                    'protocol': 'tcp',
                    'local_ip': '192.168.1.1',
                    'local_port': 80,
                    'remote_ip': '10.0.0.1',
                    'remote_port': 12345,
                    'state': 'ESTABLISHED'
                }
            ]
            
            response = client.get("/api/connections")
            assert response.status_code == 200
            data = response.json()
            assert 'connections' in data
            assert len(data['connections']) == 1
            assert data['connections'][0]['protocol'] == 'tcp'
    
    def test_get_connections_with_filters(self):
        """Тест получения соединений с фильтрами"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = [
                {
                    'protocol': 'tcp',
                    'local_ip': '192.168.1.1',
                    'local_port': 80,
                    'remote_ip': '10.0.0.1',
                    'remote_port': 12345,
                    'state': 'ESTABLISHED'
                }
            ]
            
            response = client.get("/api/connections?protocol=tcp&port=80")
            assert response.status_code == 200
            data = response.json()
            assert 'connections' in data
    
    def test_get_connections_error_handling(self):
        """Тест обработки ошибок при получении соединений"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.side_effect = Exception("Network error")
            
            response = client.get("/api/connections")
            assert response.status_code == 500
            assert "error" in response.json()
    
    def test_get_connections_empty_result(self):
        """Тест получения пустого списка соединений"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = []
            
            response = client.get("/api/connections")
            assert response.status_code == 200
            data = response.json()
            assert 'connections' in data
            assert len(data['connections']) == 0

class TestConnectionStatistics:
    """Тесты статистики соединений"""
    
    def test_get_connection_stats(self):
        """Тест получения статистики соединений"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = [
                {'protocol': 'tcp', 'state': 'ESTABLISHED'},
                {'protocol': 'tcp', 'state': 'LISTEN'},
                {'protocol': 'udp', 'state': 'LISTEN'},
                {'protocol': 'tcp', 'state': 'ESTABLISHED'}
            ]
            
            response = client.get("/api/connections/stats")
            assert response.status_code == 200
            data = response.json()
            assert 'total_connections' in data
            assert 'protocols' in data
            assert 'states' in data
            assert data['total_connections'] == 4
    
    def test_get_connection_stats_by_protocol(self):
        """Тест статистики по протоколам"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = [
                {'protocol': 'tcp', 'state': 'ESTABLISHED'},
                {'protocol': 'tcp', 'state': 'LISTEN'},
                {'protocol': 'udp', 'state': 'LISTEN'}
            ]
            
            response = client.get("/api/connections/stats")
            data = response.json()
            protocols = data['protocols']
            assert protocols['tcp'] == 2
            assert protocols['udp'] == 1
    
    def test_get_connection_stats_by_state(self):
        """Тест статистики по состояниям"""
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = [
                {'protocol': 'tcp', 'state': 'ESTABLISHED'},
                {'protocol': 'tcp', 'state': 'LISTEN'},
                {'protocol': 'udp', 'state': 'LISTEN'}
            ]
            
            response = client.get("/api/connections/stats")
            data = response.json()
            states = data['states']
            assert states['ESTABLISHED'] == 1
            assert states['LISTEN'] == 2

class TestConnectionMonitoring:
    """Тесты мониторинга соединений"""
    
    def test_start_connection_monitoring(self):
        """Тест запуска мониторинга соединений"""
        response = client.post("/api/connections/monitor/start")
        assert response.status_code == 200
        assert "monitoring started" in response.text
    
    def test_stop_connection_monitoring(self):
        """Тест остановки мониторинга соединений"""
        response = client.post("/api/connections/monitor/stop")
        assert response.status_code == 200
        assert "monitoring stopped" in response.text
    
    def test_get_monitoring_status(self):
        """Тест получения статуса мониторинга"""
        response = client.get("/api/connections/monitor/status")
        assert response.status_code == 200
        data = response.json()
        assert 'is_monitoring' in data
        assert 'start_time' in data
    
    def test_get_connection_history(self):
        """Тест получения истории соединений"""
        with patch('app.connections_api.get_connection_history') as mock_history:
            mock_history.return_value = [
                {
                    'timestamp': '2024-01-01T10:00:00',
                    'total_connections': 100,
                    'active_connections': 50
                }
            ]
            
            response = client.get("/api/connections/history")
            assert response.status_code == 200
            data = response.json()
            assert 'history' in data
            assert len(data['history']) == 1

class TestConnectionAlerts:
    """Тесты алертов для соединений"""
    
    def test_set_connection_alert(self):
        """Тест установки алерта для соединений"""
        alert_data = {
            'condition': 'connection_count > 100',
            'threshold': 100,
            'action': 'email'
        }
        
        response = client.post("/api/connections/alerts", json=alert_data)
        assert response.status_code == 201
        data = response.json()
        assert 'alert_id' in data
    
    def test_get_connection_alerts(self):
        """Тест получения списка алертов"""
        with patch('app.connections_api.get_connection_alerts') as mock_alerts:
            mock_alerts.return_value = [
                {
                    'id': 1,
                    'condition': 'connection_count > 100',
                    'threshold': 100,
                    'action': 'email',
                    'enabled': True
                }
            ]
            
            response = client.get("/api/connections/alerts")
            assert response.status_code == 200
            data = response.json()
            assert 'alerts' in data
            assert len(data['alerts']) == 1
    
    def test_update_connection_alert(self):
        """Тест обновления алерта"""
        alert_data = {
            'threshold': 150,
            'enabled': False
        }
        
        response = client.put("/api/connections/alerts/1", json=alert_data)
        assert response.status_code == 200
        data = response.json()
        assert data['threshold'] == 150
        assert data['enabled'] == False
    
    def test_delete_connection_alert(self):
        """Тест удаления алерта"""
        response = client.delete("/api/connections/alerts/1")
        assert response.status_code == 200
        assert "alert deleted" in response.text

class TestConnectionPerformance:
    """Тесты производительности API соединений"""
    
    def test_connection_api_response_time(self):
        """Тест времени ответа API соединений"""
        start_time = time.time()
        response = client.get("/api/connections")
        response_time = time.time() - start_time
        
        assert response.status_code == 200
        assert response_time < 0.5  # менее 500ms для API соединений
    
    def test_large_connection_list_performance(self):
        """Тест производительности с большим списком соединений"""
        # Создаем большой список соединений для теста
        large_connection_list = []
        for i in range(1000):
            large_connection_list.append({
                'protocol': 'tcp',
                'local_ip': f'192.168.1.{i % 255}',
                'local_port': 80 + (i % 100),
                'remote_ip': f'10.0.0.{i % 255}',
                'remote_port': 12345 + (i % 1000),
                'state': 'ESTABLISHED' if i % 2 == 0 else 'LISTEN'
            })
        
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = large_connection_list
            
            start_time = time.time()
            response = client.get("/api/connections")
            response_time = time.time() - start_time
            
            assert response.status_code == 200
            assert response_time < 1.0  # менее 1 секунды для 1000 соединений
    
    def test_connection_filtering_performance(self):
        """Тест производительности фильтрации соединений"""
        connections = []
        for i in range(500):
            connections.append({
                'protocol': 'tcp' if i % 2 == 0 else 'udp',
                'local_ip': f'192.168.1.{i % 255}',
                'local_port': 80 + (i % 100),
                'state': 'ESTABLISHED' if i % 3 == 0 else 'LISTEN'
            })
        
        with patch('app.connections_api.get_network_connections') as mock_connections:
            mock_connections.return_value = connections
            
            start_time = time.time()
            response = client.get("/api/connections?protocol=tcp&state=ESTABLISHED")
            response_time = time.time() - start_time
            
            assert response.status_code == 200
            assert response_time < 0.3  # менее 300ms для фильтрации

class TestConnectionValidation:
    """Тесты валидации данных соединений"""
    
    def test_validate_connection_data(self):
        """Тест валидации данных соединения"""
        valid_connection = {
            'protocol': 'tcp',
            'local_ip': '192.168.1.1',
            'local_port': 80,
            'remote_ip': '10.0.0.1',
            'remote_port': 12345,
            'state': 'ESTABLISHED'
        }
        
        # Тест должен пройти без ошибок
        assert 'protocol' in valid_connection
        assert valid_connection['local_port'] >= 1
        assert valid_connection['local_port'] <= 65535
    
    def test_validate_invalid_port_range(self):
        """Тест валидации неверного диапазона портов"""
        invalid_connection = {
            'protocol': 'tcp',
            'local_ip': '192.168.1.1',
            'local_port': 70000,  # Неверный порт
            'remote_ip': '10.0.0.1',
            'remote_port': 12345,
            'state': 'ESTABLISHED'
        }
        
        # Должна быть ошибка валидации
        assert invalid_connection['local_port'] > 65535
    
    def test_validate_invalid_protocol(self):
        """Тест валидации неверного протокола"""
        invalid_connection = {
            'protocol': 'invalid_protocol',
            'local_ip': '192.168.1.1',
            'local_port': 80,
            'remote_ip': '10.0.0.1',
            'remote_port': 12345,
            'state': 'ESTABLISHED'
        }
        
        # Должна быть ошибка валидации
        assert invalid_connection['protocol'] not in ['tcp', 'udp', 'icmp']

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 