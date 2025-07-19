import pytest
from app.utils import parse_ifconfig_output

class TestParseIfconfigOutput:
    """Тесты для функции parse_ifconfig_output"""
    
    def test_empty_output(self):
        """Тест с пустым выводом"""
        result = parse_ifconfig_output("")
        assert result == {}
    
    def test_none_output(self):
        """Тест с None"""
        result = parse_ifconfig_output(None)
        assert result == {}
    
    def test_basic_interface_parsing(self):
        """Тест базового парсинга интерфейса"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert result['interface'] == 'eth0'
        assert result['mac'] == '00:15:5d:01:ca:05'
        assert result['ipv4'] == '192.168.1.100'
        assert result['mask'] == '255.255.255.0'
        assert result['broadcast'] == '192.168.1.255'
        assert result['status'] == 'UP (RUNNING)'
        assert result['mtu'] == 1500
        assert result['rx_bytes'] == 123456
        assert result['tx_bytes'] == 78901
    
    def test_interface_with_ipv6(self):
        """Тест интерфейса с IPv6"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          inet6 addr: fe80::215:5dff:fe01:ca05/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert result['ipv6'] == 'fe80::215:5dff:fe01:ca05'
    
    def test_interface_down_status(self):
        """Тест интерфейса в состоянии DOWN"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert result['status'] == 'DOWN'
    
    def test_interface_up_only_status(self):
        """Тест интерфейса только с UP статусом"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert result['status'] == 'UP'
    
    def test_interface_without_broadcast(self):
        """Тест интерфейса без broadcast адреса"""
        output = """lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1234 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:123456 (120.5 KB)"""
        
        result = parse_ifconfig_output(output)
        
        # lo интерфейс может не иметь MAC адреса в стандартном формате
        assert result['ipv4'] == '127.0.0.1'
        assert result['mask'] == '255.0.0.0'
        assert 'broadcast' not in result
        assert result['status'] == 'UP (RUNNING)'
    
    def test_interface_without_mtu(self):
        """Тест интерфейса без MTU"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert 'mtu' not in result
    
    def test_interface_without_bytes(self):
        """Тест интерфейса без статистики байтов"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000"""
        
        result = parse_ifconfig_output(output)
        
        assert 'rx_bytes' not in result
        assert 'tx_bytes' not in result
    
    def test_malformed_first_line(self):
        """Тест с неправильно сформированной первой строкой"""
        output = """Invalid line format
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        # Должны быть извлечены данные, но не interface и mac
        assert 'interface' not in result
        assert 'mac' not in result
        assert result['ipv4'] == '192.168.1.100'
        assert result['status'] == 'UP (RUNNING)'
    
    def test_multiple_ipv6_addresses(self):
        """Тест с несколькими IPv6 адресами (берется последний)"""
        output = """eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          inet6 addr: fe80::215:5dff:fe01:ca05/64 Scope:Link
          inet6 addr: 2001:db8::1/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        # Функция берет последний IPv6 адрес
        assert result['ipv6'] == '2001:db8::1'
    
    def test_interface_with_comments(self):
        """Тест интерфейса с комментариями в выводе"""
        output = """# Network interface configuration
eth0      Link encap:Ethernet  HWaddr 00:15:5d:01:ca:05
          inet addr:192.168.1.100  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          # Statistics
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        # Проверяем только то, что парсится корректно
        assert result['ipv4'] == '192.168.1.100'
        assert result['status'] == 'UP (RUNNING)'
    
    def test_interface_with_extra_spaces(self):
        """Тест интерфейса с дополнительными пробелами"""
        output = """eth0        Link encap:Ethernet  HWaddr    00:15:5d:01:ca:05
          inet addr:192.168.1.100    Bcast:192.168.1.255    Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:567 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:123456 (120.5 KB)  TX bytes:78901 (77.0 KB)"""
        
        result = parse_ifconfig_output(output)
        
        assert result['interface'] == 'eth0'
        assert result['mac'] == '00:15:5d:01:ca:05'
        assert result['ipv4'] == '192.168.1.100'
        assert result['mask'] == '255.255.255.0'
        assert result['broadcast'] == '192.168.1.255' 