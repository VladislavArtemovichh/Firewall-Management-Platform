import time
import psutil
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json
from collections import Counter

@dataclass
class SystemMetrics:
    """Метрики системы"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int

@dataclass
class ApplicationMetrics:
    """Метрики приложения"""
    timestamp: datetime
    active_users: int
    total_requests: int
    error_requests: int
    avg_response_time: float
    firewall_rules_count: int
    active_sessions: int

@dataclass
class SecurityMetrics:
    """Метрики безопасности"""
    timestamp: datetime
    failed_login_attempts: int
    blocked_ips: int
    suspicious_activities: int
    firewall_blocks: int

class MetricsCollector:
    """Сборщик метрик"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.system_metrics: deque = deque(maxlen=max_history)
        self.app_metrics: deque = deque(maxlen=max_history)
        self.security_metrics: deque = deque(maxlen=max_history)
        
        # Счетчики для приложения
        self.request_count = 0
        self.error_count = 0
        self.response_times = deque(maxlen=100)
        self.failed_logins = 0
        self.blocked_ips = set()
        self.suspicious_activities = 0
        self.firewall_blocks = 0
        self.error_codes = []  # список кодов ошибок
        
        # Сетевые метрики
        self.last_network_stats = None
        
    def collect_system_metrics(self) -> Optional[SystemMetrics]:
        """Сбор системных метрик"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Сетевые метрики
            network_stats = psutil.net_io_counters()
            bytes_sent = network_stats.bytes_sent
            bytes_recv = network_stats.bytes_recv
            
            if self.last_network_stats:
                bytes_sent = network_stats.bytes_sent - self.last_network_stats.bytes_sent
                bytes_recv = network_stats.bytes_recv - self.last_network_stats.bytes_recv
            
            self.last_network_stats = network_stats
            
            metrics = SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_usage_percent=disk.percent,
                network_bytes_sent=bytes_sent,
                network_bytes_recv=bytes_recv
            )
            
            self.system_metrics.append(metrics)
            return metrics
            
        except Exception as e:
            print(f"Ошибка при сборе системных метрик: {e}")
            return None
    
    def collect_app_metrics(self, active_users: int, firewall_rules_count: int, active_sessions: int) -> ApplicationMetrics:
        """Сбор метрик приложения"""
        avg_response_time = 0
        if self.response_times:
            avg_response_time = sum(self.response_times) / len(self.response_times)
        
        metrics = ApplicationMetrics(
            timestamp=datetime.now(),
            active_users=active_users,
            total_requests=self.request_count,
            error_requests=self.error_count,
            avg_response_time=avg_response_time,
            firewall_rules_count=firewall_rules_count,
            active_sessions=active_sessions
        )
        
        self.app_metrics.append(metrics)
        return metrics
    
    def collect_security_metrics(self) -> SecurityMetrics:
        """Сбор метрик безопасности"""
        metrics = SecurityMetrics(
            timestamp=datetime.now(),
            failed_login_attempts=self.failed_logins,
            blocked_ips=len(self.blocked_ips),
            suspicious_activities=self.suspicious_activities,
            firewall_blocks=self.firewall_blocks
        )
        
        self.security_metrics.append(metrics)
        return metrics
    
    def record_request(self, response_time: float, is_error: bool = False, error_code: Optional[int] = None):
        """Запись метрик запроса"""
        self.request_count += 1
        if is_error:
            self.error_count += 1
            if error_code:
                self.error_codes.append(error_code)
        self.response_times.append(response_time)
    
    def record_failed_login(self, ip: str):
        """Запись неудачной попытки входа"""
        self.failed_logins += 1
        self.blocked_ips.add(ip)
    
    def record_suspicious_activity(self):
        """Запись подозрительной активности"""
        self.suspicious_activities += 1
    
    def record_firewall_block(self):
        """Запись блокировки брандмауэра"""
        self.firewall_blocks += 1
    
    def get_metrics_summary(self, hours: int = 24) -> Dict:
        """Получение сводки метрик за указанное время"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Фильтруем метрики по времени
        recent_system = [m for m in self.system_metrics if m.timestamp > cutoff_time]
        recent_app = [m for m in self.app_metrics if m.timestamp > cutoff_time]
        recent_security = [m for m in self.security_metrics if m.timestamp > cutoff_time]
        
        if not recent_system:
            print('[METRICS] Нет данных системных метрик, возвращаю нули')
            return {
                "system": {
                    "avg_cpu_percent": 0,
                    "avg_memory_percent": 0,
                    "avg_disk_percent": 0,
                    "current_cpu": 0,
                    "current_memory": 0,
                    "current_disk": 0
                },
                "application": {
                    "total_requests": 0,
                    "error_rate": 0,
                    "avg_response_time": 0,
                    "failed_logins": 0,
                    "blocked_ips": 0,
                    "suspicious_activities": 0,
                    "firewall_blocks": 0
                },
                "trends": {
                    "requests_per_hour": 0,
                    "errors_per_hour": 0,
                    "failed_logins_per_hour": 0
                },
                "errors_detail": []
            }
        
        # Системные метрики
        avg_cpu = sum(m.cpu_percent for m in recent_system) / len(recent_system)
        avg_memory = sum(m.memory_percent for m in recent_system) / len(recent_system)
        avg_disk = sum(m.disk_usage_percent for m in recent_system) / len(recent_system)
        
        # Метрики приложения
        total_requests = self.request_count
        error_rate = (self.error_count / total_requests * 100) if total_requests > 0 else 0
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        # Метрики безопасности
        total_failed_logins = self.failed_logins
        unique_blocked_ips = len(self.blocked_ips)
        
        # Детализация ошибок
        error_counter = Counter(self.error_codes)
        top_errors = error_counter.most_common(5)
        
        return {
            "system": {
                "avg_cpu_percent": round(avg_cpu, 2),
                "avg_memory_percent": round(avg_memory, 2),
                "avg_disk_percent": round(avg_disk, 2),
                "current_cpu": recent_system[-1].cpu_percent if recent_system else 0,
                "current_memory": recent_system[-1].memory_percent if recent_system else 0,
                "current_disk": recent_system[-1].disk_usage_percent if recent_system else 0
            },
            "application": {
                "total_requests": total_requests,
                "error_rate": round(error_rate, 2),
                "avg_response_time": round(avg_response_time, 3),
                "failed_logins": total_failed_logins,
                "blocked_ips": unique_blocked_ips,
                "suspicious_activities": self.suspicious_activities,
                "firewall_blocks": self.firewall_blocks
            },
            "trends": {
                "requests_per_hour": total_requests / hours if hours > 0 else 0,
                "errors_per_hour": self.error_count / hours if hours > 0 else 0,
                "failed_logins_per_hour": total_failed_logins / hours if hours > 0 else 0
            },
            "errors_detail": [
                {"code": code, "count": count} for code, count in top_errors
            ]
        }
    
    def get_chart_data(self, hours: int = 24) -> Dict:
        """Получение данных для графиков"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Фильтруем метрики
        system_data = [m for m in self.system_metrics if m.timestamp > cutoff_time]
        app_data = [m for m in self.app_metrics if m.timestamp > cutoff_time]
        
        return {
            "system": {
                "labels": [m.timestamp.strftime("%H:%M") for m in system_data],
                "cpu": [m.cpu_percent for m in system_data],
                "memory": [m.memory_percent for m in system_data],
                "disk": [m.disk_usage_percent for m in system_data]
            },
            "application": {
                "labels": [m.timestamp.strftime("%H:%M") for m in app_data],
                "active_users": [m.active_users for m in app_data],
                "response_time": [m.avg_response_time for m in app_data],
                "requests": [m.total_requests for m in app_data]
            }
        }

# Глобальный экземпляр сборщика метрик
metrics_collector = MetricsCollector()

async def start_metrics_collection():
    """Запуск сбора метрик в фоновом режиме"""
    while True:
        try:
            # Собираем системные метрики
            metrics_collector.collect_system_metrics()
            
            # Ждем 30 секунд перед следующим сбором
            await asyncio.sleep(30)
            
        except Exception as e:
            print(f"Ошибка при сборе метрик: {e}")
            await asyncio.sleep(60)  # Ждем дольше при ошибке 