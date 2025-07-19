import pytest
import time
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from app.metrics import (
    MetricsCollector,
    SystemMetrics,
    ApplicationMetrics,
    SecurityMetrics,
    start_metrics_collection
)

class TestSystemMetrics:
    """Тесты для класса SystemMetrics"""
    
    def test_system_metrics_creation(self):
        """Тест создания системных метрик"""
        timestamp = datetime.now()
        metrics = SystemMetrics(
            timestamp=timestamp,
            cpu_percent=25.5,
            memory_percent=60.2,
            disk_usage_percent=45.8,
            network_bytes_sent=1024,
            network_bytes_recv=2048
        )
        
        assert metrics.timestamp == timestamp
        assert metrics.cpu_percent == 25.5
        assert metrics.memory_percent == 60.2
        assert metrics.disk_usage_percent == 45.8
        assert metrics.network_bytes_sent == 1024
        assert metrics.network_bytes_recv == 2048

class TestApplicationMetrics:
    """Тесты для класса ApplicationMetrics"""
    
    def test_application_metrics_creation(self):
        """Тест создания метрик приложения"""
        timestamp = datetime.now()
        metrics = ApplicationMetrics(
            timestamp=timestamp,
            active_users=10,
            total_requests=1000,
            error_requests=50,
            avg_response_time=0.15,
            firewall_rules_count=25,
            active_sessions=8
        )
        
        assert metrics.timestamp == timestamp
        assert metrics.active_users == 10
        assert metrics.total_requests == 1000
        assert metrics.error_requests == 50
        assert metrics.avg_response_time == 0.15
        assert metrics.firewall_rules_count == 25
        assert metrics.active_sessions == 8

class TestSecurityMetrics:
    """Тесты для класса SecurityMetrics"""
    
    def test_security_metrics_creation(self):
        """Тест создания метрик безопасности"""
        timestamp = datetime.now()
        metrics = SecurityMetrics(
            timestamp=timestamp,
            failed_login_attempts=15,
            blocked_ips=5,
            suspicious_activities=3,
            firewall_blocks=12
        )
        
        assert metrics.timestamp == timestamp
        assert metrics.failed_login_attempts == 15
        assert metrics.blocked_ips == 5
        assert metrics.suspicious_activities == 3
        assert metrics.firewall_blocks == 12

class TestMetricsCollector:
    """Тесты для класса MetricsCollector"""
    
    def test_metrics_collector_initialization(self):
        """Тест инициализации сборщика метрик"""
        collector = MetricsCollector(max_history=500)
        
        assert collector.max_history == 500
        assert len(collector.system_metrics) == 0
        assert len(collector.app_metrics) == 0
        assert len(collector.security_metrics) == 0
        assert collector.request_count == 0
        assert collector.error_count == 0
        assert collector.failed_logins == 0
        assert len(collector.blocked_ips) == 0
        assert collector.suspicious_activities == 0
        assert collector.firewall_blocks == 0
    
    @patch('app.metrics.psutil')
    def test_collect_system_metrics_success(self, mock_psutil):
        """Тест успешного сбора системных метрик"""
        # Настраиваем моки
        mock_cpu = Mock(return_value=25.5)
        mock_memory = Mock()
        mock_memory.percent = 60.2
        mock_disk = Mock()
        mock_disk.percent = 45.8
        mock_network = Mock()
        mock_network.bytes_sent = 1024
        mock_network.bytes_recv = 2048
        
        mock_psutil.cpu_percent = mock_cpu
        mock_psutil.virtual_memory = Mock(return_value=mock_memory)
        mock_psutil.disk_usage = Mock(return_value=mock_disk)
        mock_psutil.net_io_counters = Mock(return_value=mock_network)
        
        collector = MetricsCollector()
        metrics = collector.collect_system_metrics()
        
        assert metrics is not None
        assert metrics.cpu_percent == 25.5
        assert metrics.memory_percent == 60.2
        assert metrics.disk_usage_percent == 45.8
        assert metrics.network_bytes_sent == 1024
        assert metrics.network_bytes_recv == 2048
        assert len(collector.system_metrics) == 1
    
    @patch('app.metrics.psutil')
    def test_collect_system_metrics_with_previous_network_stats(self, mock_psutil):
        """Тест сбора системных метрик с предыдущими сетевыми статистиками"""
        # Настраиваем моки
        mock_cpu = Mock(return_value=25.5)
        mock_memory = Mock()
        mock_memory.percent = 60.2
        mock_disk = Mock()
        mock_disk.percent = 45.8
        
        # Первый вызов
        mock_network1 = Mock()
        mock_network1.bytes_sent = 1000
        mock_network1.bytes_recv = 2000
        
        # Второй вызов
        mock_network2 = Mock()
        mock_network2.bytes_sent = 1500
        mock_network2.bytes_recv = 2500
        
        mock_psutil.cpu_percent = mock_cpu
        mock_psutil.virtual_memory = Mock(return_value=mock_memory)
        mock_psutil.disk_usage = Mock(return_value=mock_disk)
        mock_psutil.net_io_counters = Mock(side_effect=[mock_network1, mock_network2])
        
        collector = MetricsCollector()
        
        # Первый сбор
        metrics1 = collector.collect_system_metrics()
        assert metrics1.network_bytes_sent == 1000
        assert metrics1.network_bytes_recv == 2000
        
        # Второй сбор
        metrics2 = collector.collect_system_metrics()
        assert metrics2.network_bytes_sent == 500  # 1500 - 1000
        assert metrics2.network_bytes_recv == 500  # 2500 - 2000
    
    @patch('app.metrics.psutil')
    def test_collect_system_metrics_exception(self, mock_psutil):
        """Тест обработки исключения при сборе системных метрик"""
        mock_psutil.cpu_percent.side_effect = Exception("CPU error")
        
        collector = MetricsCollector()
        metrics = collector.collect_system_metrics()
        
        assert metrics is None
        assert len(collector.system_metrics) == 0
    
    def test_collect_app_metrics(self):
        """Тест сбора метрик приложения"""
        collector = MetricsCollector()
        
        # Добавляем время ответа
        collector.response_times.append(0.1)
        collector.response_times.append(0.2)
        collector.request_count = 100
        collector.error_count = 10
        
        metrics = collector.collect_app_metrics(
            active_users=5,
            firewall_rules_count=20,
            active_sessions=3
        )
        
        assert metrics.active_users == 5
        assert metrics.total_requests == 100
        assert metrics.error_requests == 10
        assert metrics.avg_response_time == pytest.approx(0.15)  # (0.1 + 0.2) / 2
        assert metrics.firewall_rules_count == 20
        assert metrics.active_sessions == 3
        assert len(collector.app_metrics) == 1
    
    def test_collect_app_metrics_no_response_times(self):
        """Тест сбора метрик приложения без времени ответа"""
        collector = MetricsCollector()
        
        metrics = collector.collect_app_metrics(
            active_users=5,
            firewall_rules_count=20,
            active_sessions=3
        )
        
        assert metrics.avg_response_time == 0
        assert len(collector.app_metrics) == 1
    
    def test_collect_security_metrics(self):
        """Тест сбора метрик безопасности"""
        collector = MetricsCollector()
        
        # Устанавливаем значения
        collector.failed_logins = 15
        collector.blocked_ips.add("192.168.1.100")
        collector.blocked_ips.add("192.168.1.101")
        collector.suspicious_activities = 3
        collector.firewall_blocks = 12
        
        metrics = collector.collect_security_metrics()
        
        assert metrics.failed_login_attempts == 15
        assert metrics.blocked_ips == 2
        assert metrics.suspicious_activities == 3
        assert metrics.firewall_blocks == 12
        assert len(collector.security_metrics) == 1
    
    def test_record_request_success(self):
        """Тест записи успешного запроса"""
        collector = MetricsCollector()
        
        collector.record_request(response_time=0.1, is_error=False)
        
        assert collector.request_count == 1
        assert collector.error_count == 0
        assert len(collector.response_times) == 1
        assert collector.response_times[0] == 0.1
    
    def test_record_request_error(self):
        """Тест записи запроса с ошибкой"""
        collector = MetricsCollector()
        
        collector.record_request(response_time=0.5, is_error=True, error_code=500)
        
        assert collector.request_count == 1
        assert collector.error_count == 1
        assert len(collector.response_times) == 1
        assert collector.response_times[0] == 0.5
        assert len(collector.error_codes) == 1
        assert collector.error_codes[0] == 500
    
    def test_record_failed_login(self):
        """Тест записи неудачной попытки входа"""
        collector = MetricsCollector()
        
        collector.record_failed_login("192.168.1.100")
        collector.record_failed_login("192.168.1.101")
        collector.record_failed_login("192.168.1.100")  # Дубликат
        
        assert collector.failed_logins == 3
        assert len(collector.blocked_ips) == 2  # Уникальные IP
        assert "192.168.1.100" in collector.blocked_ips
        assert "192.168.1.101" in collector.blocked_ips
    
    def test_record_suspicious_activity(self):
        """Тест записи подозрительной активности"""
        collector = MetricsCollector()
        
        collector.record_suspicious_activity()
        collector.record_suspicious_activity()
        
        assert collector.suspicious_activities == 2
    
    def test_record_firewall_block(self):
        """Тест записи блокировки брандмауэра"""
        collector = MetricsCollector()
        
        collector.record_firewall_block()
        collector.record_firewall_block()
        collector.record_firewall_block()
        
        assert collector.firewall_blocks == 3
    
    def test_get_metrics_summary_no_data(self):
        """Тест получения сводки метрик без данных"""
        collector = MetricsCollector()
        
        summary = collector.get_metrics_summary(hours=24)
        
        assert "system" in summary
        assert "application" in summary
        assert "trends" in summary
        assert "errors_detail" in summary
        
        # Проверяем, что все значения равны 0
        assert summary["system"]["avg_cpu_percent"] == 0
        assert summary["system"]["avg_memory_percent"] == 0
        assert summary["application"]["total_requests"] == 0
        assert summary["application"]["error_rate"] == 0
    
    def test_get_metrics_summary_with_data(self):
        """Тест получения сводки метрик с данными"""
        collector = MetricsCollector()
        
        # Добавляем системные метрики
        now = datetime.now()
        metrics1 = SystemMetrics(
            timestamp=now - timedelta(hours=1),
            cpu_percent=20.0,
            memory_percent=50.0,
            disk_usage_percent=40.0,
            network_bytes_sent=1000,
            network_bytes_recv=2000
        )
        metrics2 = SystemMetrics(
            timestamp=now - timedelta(minutes=30),
            cpu_percent=30.0,
            memory_percent=60.0,
            disk_usage_percent=50.0,
            network_bytes_sent=2000,
            network_bytes_recv=4000
        )
        
        collector.system_metrics.append(metrics1)
        collector.system_metrics.append(metrics2)
        
        # Добавляем данные запросов
        collector.request_count = 100
        collector.error_count = 10
        collector.response_times.append(0.1)
        collector.response_times.append(0.2)
        
        # Добавляем данные безопасности
        collector.failed_logins = 5
        collector.blocked_ips.add("192.168.1.100")
        collector.suspicious_activities = 2
        collector.firewall_blocks = 8
        
        summary = collector.get_metrics_summary(hours=24)
        
        # Проверяем системные метрики
        assert summary["system"]["avg_cpu_percent"] == 25.0  # (20 + 30) / 2
        assert summary["system"]["avg_memory_percent"] == 55.0  # (50 + 60) / 2
        assert summary["system"]["avg_disk_percent"] == 45.0  # (40 + 50) / 2
        
        # Проверяем метрики приложения
        assert summary["application"]["total_requests"] == 100
        assert summary["application"]["error_rate"] == 10.0  # 10 / 100 * 100
        assert summary["application"]["avg_response_time"] == 0.15  # (0.1 + 0.2) / 2
        assert summary["application"]["failed_logins"] == 5
        assert summary["application"]["blocked_ips"] == 1
        assert summary["application"]["suspicious_activities"] == 2
        assert summary["application"]["firewall_blocks"] == 8
    
    def test_get_metrics_summary_old_data_filtered(self):
        """Тест фильтрации старых данных в сводке метрик"""
        collector = MetricsCollector()
        
        # Добавляем старые метрики (более 24 часов назад)
        old_metrics = SystemMetrics(
            timestamp=datetime.now() - timedelta(hours=25),
            cpu_percent=10.0,
            memory_percent=30.0,
            disk_usage_percent=20.0,
            network_bytes_sent=500,
            network_bytes_recv=1000
        )
        
        # Добавляем новые метрики
        new_metrics = SystemMetrics(
            timestamp=datetime.now() - timedelta(hours=1),
            cpu_percent=50.0,
            memory_percent=70.0,
            disk_usage_percent=60.0,
            network_bytes_sent=1500,
            network_bytes_recv=3000
        )
        
        collector.system_metrics.append(old_metrics)
        collector.system_metrics.append(new_metrics)
        
        summary = collector.get_metrics_summary(hours=24)
        
        # Должны учитываться только новые метрики
        assert summary["system"]["avg_cpu_percent"] == 50.0
        assert summary["system"]["avg_memory_percent"] == 70.0
        assert summary["system"]["avg_disk_percent"] == 60.0
    
    def test_metrics_history_limit(self):
        """Тест ограничения истории метрик"""
        collector = MetricsCollector(max_history=2)
        
        # Добавляем больше метрик, чем лимит
        for i in range(5):
            metrics = SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=float(i),
                memory_percent=float(i),
                disk_usage_percent=float(i),
                network_bytes_sent=i,
                network_bytes_recv=i
            )
            collector.system_metrics.append(metrics)
        
        # Должно остаться только 2 последних метрики
        assert len(collector.system_metrics) == 2
        assert collector.system_metrics[-1].cpu_percent == 4.0
        assert collector.system_metrics[-2].cpu_percent == 3.0

class TestStartMetricsCollection:
    """Тесты для функции start_metrics_collection"""
    
    @pytest.mark.asyncio
    async def test_start_metrics_collection(self):
        """Тест запуска сбора метрик"""
        with patch('app.metrics.asyncio.sleep') as mock_sleep:
            mock_sleep.side_effect = asyncio.CancelledError()  # Для завершения цикла
            
            try:
                await start_metrics_collection()
            except asyncio.CancelledError:
                pass  # Ожидаемое поведение
            
            # Проверяем, что sleep был вызван
            mock_sleep.assert_called_once()

class TestMetricsIntegration:
    """Интеграционные тесты метрик"""
    
    def test_full_metrics_workflow(self):
        """Тест полного рабочего процесса метрик"""
        collector = MetricsCollector()
        
        # Симулируем работу приложения
        with patch('app.metrics.psutil') as mock_psutil:
            # Настраиваем моки для системных метрик
            mock_cpu = Mock(return_value=25.0)
            mock_memory = Mock()
            mock_memory.percent = 60.0
            mock_disk = Mock()
            mock_disk.percent = 50.0
            mock_network = Mock()
            mock_network.bytes_sent = 1000
            mock_network.bytes_recv = 2000
            
            mock_psutil.cpu_percent = mock_cpu
            mock_psutil.virtual_memory = Mock(return_value=mock_memory)
            mock_psutil.disk_usage = Mock(return_value=mock_disk)
            mock_psutil.net_io_counters = Mock(return_value=mock_network)
            
            # Собираем системные метрики
            system_metrics = collector.collect_system_metrics()
            assert system_metrics is not None
            
            # Записываем запросы
            collector.record_request(0.1, False)
            collector.record_request(0.2, True, 500)
            collector.record_request(0.15, False)
            
            # Записываем события безопасности
            collector.record_failed_login("192.168.1.100")
            collector.record_suspicious_activity()
            collector.record_firewall_block()
            
            # Собираем метрики приложения
            app_metrics = collector.collect_app_metrics(5, 20, 3)
            assert app_metrics.total_requests == 3
            assert app_metrics.error_requests == 1
            assert app_metrics.avg_response_time == 0.15
            
            # Собираем метрики безопасности
            security_metrics = collector.collect_security_metrics()
            assert security_metrics.failed_login_attempts == 1
            assert security_metrics.blocked_ips == 1
            assert security_metrics.suspicious_activities == 1
            assert security_metrics.firewall_blocks == 1
            
            # Получаем сводку
            summary = collector.get_metrics_summary()
            assert summary["application"]["total_requests"] == 3
            assert summary["application"]["error_rate"] == pytest.approx(33.33, rel=0.1)
            assert summary["application"]["failed_logins"] == 1 