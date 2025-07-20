from fastapi import APIRouter
from fastapi.responses import JSONResponse
import psutil
import datetime
import socket
import uuid

router = APIRouter()

@router.get("/api/connections")
async def get_connections():
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        proc_name = ""
        create_time = ""
        # Определяем протокол
        if conn.type == socket.SOCK_STREAM:
            protocol = "TCP"
        elif conn.type == socket.SOCK_DGRAM:
            protocol = "UDP"
        elif conn.type == socket.SOCK_RAW:
            protocol = "RAW"
        else:
            protocol = f"UNKNOWN ({conn.type})"
        try:
            if conn.pid:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name()
                # Получаем время запуска процесса (секунды с эпохи)
                proc_create_time = proc.create_time()
                # Переводим в человекочитаемый формат
                create_time = datetime.datetime.fromtimestamp(proc_create_time).strftime('%d.%m.%Y %H:%M:%S')
        except Exception:
            proc_name = "Неизвестно"
            create_time = ""
        connections.append({
            "process": proc_name if proc_name else "Неизвестно",
            "protocol": protocol,
            "local_address": conn.laddr.ip if conn.laddr else "",
            "local_port": conn.laddr.port if conn.laddr else "",
            "remote_address": conn.raddr.ip if conn.raddr else "",
            "remote_port": conn.raddr.port if conn.raddr else "",
            "status": conn.status,
            "create_time": create_time  # Время запуска процесса
        })
    return JSONResponse(connections)

@router.get("/api/adapters")
async def get_adapters():
    import psutil
    adapters_active = []
    adapters_inactive = []
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    net_io_counters = psutil.net_io_counters(pernic=True)
    for name, addrs in net_if_addrs.items():
        mac = ''
        ip = ''
        for addr in addrs:
            if addr.family == psutil.AF_LINK or (hasattr(socket, 'AF_PACKET') and addr.family == socket.AF_PACKET):
                mac = addr.address
            elif addr.family == socket.AF_INET:
                ip = addr.address
        stats = net_if_stats.get(name)
        io = net_io_counters.get(name)
        isup = stats.isup if stats else False
        adapter = {
            'name': name,
            'mac': mac,
            'ip': ip,
            'speed': stats.speed if stats else None,
            'isup': isup,
            'in_packets': io.packets_recv if io else None,
            'out_packets': io.packets_sent if io else None,
            'in_errors': io.errin if io else None,
            'out_errors': io.errout if io else None
        }
        if isup:
            adapters_active.append(adapter)
        else:
            adapters_inactive.append(adapter)
    return {'active': adapters_active, 'inactive': adapters_inactive}

@router.get("/api/bandwidth")
async def get_bandwidth():
    import psutil
    import collections
    import subprocess
    import os
    
    proc_stats = collections.defaultdict(lambda: {"connections": 0, "bytes_recv": 0, "bytes_sent": 0})
    
    # Попытка получить трафик из /proc/net/nf_conntrack (более точные данные)
    try:
        with open('/proc/net/nf_conntrack', 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                # Парсим строку nf_conntrack
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                try:
                    protocol = parts[2]  # tcp, udp, icmp
                    state = parts[5]     # ESTABLISHED, TIME_WAIT, etc.
                    
                    # Ищем src и dst адреса, порты и трафик
                    src_addr = None
                    dst_addr = None
                    src_port = None
                    dst_port = None
                    packets_in = 0
                    bytes_in = 0
                    packets_out = 0
                    bytes_out = 0
                    
                    for i, part in enumerate(parts):
                        if part == 'src=':
                            src_addr = parts[i+1]
                        elif part == 'dst=':
                            dst_addr = parts[i+1]
                        elif part == 'sport=':
                            src_port = parts[i+1]
                        elif part == 'dport=':
                            dst_port = parts[i+1]
                        elif part == 'packets=':
                            if packets_in == 0:
                                packets_in = int(parts[i+1])
                            else:
                                packets_out = int(parts[i+1])
                        elif part == 'bytes=':
                            if bytes_in == 0:
                                bytes_in = int(parts[i+1])
                            else:
                                bytes_out = int(parts[i+1])
                    
                    if src_addr and dst_addr:
                        # Пытаемся найти процесс по адресу и порту
                        process_name = "unknown"
                        try:
                            for conn in psutil.net_connections(kind='inet'):
                                if (conn.laddr and conn.laddr.ip == src_addr and 
                                    str(conn.laddr.port) == src_port):
                                    if conn.pid:
                                        proc = psutil.Process(conn.pid)
                                        process_name = proc.name()
                                    break
                        except:
                            pass
                        
                        if process_name not in proc_stats:
                            proc_stats[process_name] = {"connections": 0, "bytes_recv": 0, "bytes_sent": 0}
                        
                        proc_stats[process_name]["connections"] += 1
                        proc_stats[process_name]["bytes_recv"] += bytes_in
                        proc_stats[process_name]["bytes_sent"] += bytes_out
                        
                except Exception as parse_error:
                    continue
                    
    except Exception as nf_error:
        # Fallback к старому методу если nf_conntrack недоступен
        # Попытка получить трафик из /proc/net/dev (общий трафик по интерфейсам)
        total_bytes_recv = 0
        total_bytes_sent = 0
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line and not line.startswith('Inter-'):
                        parts = line.split()
                        if len(parts) >= 10:
                            # bytes received и bytes transmitted
                            total_bytes_recv += int(parts[1])
                            total_bytes_sent += int(parts[9])
        except Exception:
            pass
        
        # Попытка получить трафик по процессам через ss (если доступен)
        process_traffic = {}
        try:
            result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'users:' in line:
                        # Парсим строку ss для получения PID и трафика
                        parts = line.split()
                        for part in parts:
                            if 'pid=' in part:
                                pid = part.split('=')[1].split(',')[0]
                                try:
                                    proc = psutil.Process(int(pid))
                                    proc_name = proc.name()
                                    if proc_name not in process_traffic:
                                        process_traffic[proc_name] = {"bytes_recv": 0, "bytes_sent": 0}
                                    # Распределяем общий трафик пропорционально количеству соединений
                                    process_traffic[proc_name]["bytes_recv"] += total_bytes_recv // 100  # Примерное распределение
                                    process_traffic[proc_name]["bytes_sent"] += total_bytes_sent // 100
                                except:
                                    pass
        except Exception:
            pass
        
        # Основной цикл по процессам
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'] or f"pid_{proc.info['pid']}"
                # Считаем только процессы с сетевыми соединениями
                conns = proc.connections(kind='inet')
                if not conns:
                    continue
                
                proc_stats[name]["connections"] += len(conns)
                
                # Добавляем трафик из process_traffic если есть
                if name in process_traffic:
                    proc_stats[name]["bytes_recv"] += process_traffic[name]["bytes_recv"]
                    proc_stats[name]["bytes_sent"] += process_traffic[name]["bytes_sent"]
                else:
                    # Если нет точных данных, распределяем общий трафик пропорционально
                    if total_bytes_recv > 0 or total_bytes_sent > 0:
                        proc_stats[name]["bytes_recv"] += total_bytes_recv // max(len(proc_stats), 1)
                        proc_stats[name]["bytes_sent"] += total_bytes_sent // max(len(proc_stats), 1)
                        
            except Exception:
                continue
    
    # Преобразуем в список для фронта
    result = []
    for name, stat in proc_stats.items():
        result.append({
            "process": name,
            "connections": stat["connections"],
            "in_traffic": stat["bytes_recv"],
            "out_traffic": stat["bytes_sent"]
        })
    
    # Сортируем по общему трафику (убывание)
    result.sort(key=lambda x: x["in_traffic"] + x["out_traffic"], reverse=True)
    
    return result

@router.get("/api/nf_conntrack")
async def get_nf_conntrack():
    """API для получения данных из /proc/net/nf_conntrack с группировкой по процессам"""
    import psutil
    import collections
    import subprocess
    
    proc_stats = collections.defaultdict(lambda: {
        "connections": 0, 
        "bytes_recv": 0, 
        "bytes_sent": 0,
        "protocols": set(),
        "remote_ips": set()
    })
    
    # Попытка 1: Чтение /proc/net/nf_conntrack (требует root)
    try:
        with open('/proc/net/nf_conntrack', 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                # Парсим строку nf_conntrack
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                try:
                    protocol = parts[2]  # tcp, udp, icmp
                    state = parts[5]     # ESTABLISHED, TIME_WAIT, etc.
                    
                    # Ищем src и dst адреса, порты и трафик
                    src_addr = None
                    dst_addr = None
                    src_port = None
                    dst_port = None
                    packets_in = 0
                    bytes_in = 0
                    packets_out = 0
                    bytes_out = 0
                    
                    for i, part in enumerate(parts):
                        if part == 'src=':
                            src_addr = parts[i+1]
                        elif part == 'dst=':
                            dst_addr = parts[i+1]
                        elif part == 'sport=':
                            src_port = parts[i+1]
                        elif part == 'dport=':
                            dst_port = parts[i+1]
                        elif part == 'packets=':
                            if packets_in == 0:
                                packets_in = int(parts[i+1])
                            else:
                                packets_out = int(parts[i+1])
                        elif part == 'bytes=':
                            if bytes_in == 0:
                                bytes_in = int(parts[i+1])
                            else:
                                bytes_out = int(parts[i+1])
                    
                    if src_addr and dst_addr:
                        # Пытаемся найти процесс по адресу и порту
                        process_name = "unknown"
                        try:
                            for conn in psutil.net_connections(kind='inet'):
                                if (conn.laddr and conn.laddr.ip == src_addr and 
                                    str(conn.laddr.port) == src_port):
                                    if conn.pid:
                                        proc = psutil.Process(conn.pid)
                                        process_name = proc.name()
                                    break
                        except:
                            pass
                        
                        if process_name not in proc_stats:
                            proc_stats[process_name] = {
                                "connections": 0, 
                                "bytes_recv": 0, 
                                "bytes_sent": 0,
                                "protocols": set(),
                                "remote_ips": set()
                            }
                        
                        proc_stats[process_name]["connections"] += 1
                        proc_stats[process_name]["bytes_recv"] += bytes_in
                        proc_stats[process_name]["bytes_sent"] += bytes_out
                        proc_stats[process_name]["protocols"].add(protocol.upper())
                        proc_stats[process_name]["remote_ips"].add(dst_addr)
                        
                except Exception as parse_error:
                    continue
    
    except PermissionError:
        # Попытка 2: Используем sudo для чтения nf_conntrack
        try:
            result = subprocess.run(['sudo', 'cat', '/proc/net/nf_conntrack'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if not line.strip():
                        continue
                    
                    # Парсим строку nf_conntrack
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    try:
                        protocol = parts[2]  # tcp, udp, icmp
                        state = parts[5]     # ESTABLISHED, TIME_WAIT, etc.
                        
                        # Ищем src и dst адреса, порты и трафик
                        src_addr = None
                        dst_addr = None
                        src_port = None
                        dst_port = None
                        packets_in = 0
                        bytes_in = 0
                        packets_out = 0
                        bytes_out = 0
                        
                        for i, part in enumerate(parts):
                            if part == 'src=':
                                src_addr = parts[i+1]
                            elif part == 'dst=':
                                dst_addr = parts[i+1]
                            elif part == 'sport=':
                                src_port = parts[i+1]
                            elif part == 'dport=':
                                dst_port = parts[i+1]
                            elif part == 'packets=':
                                if packets_in == 0:
                                    packets_in = int(parts[i+1])
                                else:
                                    packets_out = int(parts[i+1])
                            elif part == 'bytes=':
                                if bytes_in == 0:
                                    bytes_in = int(parts[i+1])
                                else:
                                    bytes_out = int(parts[i+1])
                        
                        if src_addr and dst_addr:
                            # Пытаемся найти процесс по адресу и порту
                            process_name = "unknown"
                            try:
                                for conn in psutil.net_connections(kind='inet'):
                                    if (conn.laddr and conn.laddr.ip == src_addr and 
                                        str(conn.laddr.port) == src_port):
                                        if conn.pid:
                                            proc = psutil.Process(conn.pid)
                                            process_name = proc.name()
                                        break
                            except:
                                pass
                            
                            if process_name not in proc_stats:
                                proc_stats[process_name] = {
                                    "connections": 0, 
                                    "bytes_recv": 0, 
                                    "bytes_sent": 0,
                                    "protocols": set(),
                                    "remote_ips": set()
                                }
                            
                            proc_stats[process_name]["connections"] += 1
                            proc_stats[process_name]["bytes_recv"] += bytes_in
                            proc_stats[process_name]["bytes_sent"] += bytes_out
                            proc_stats[process_name]["protocols"].add(protocol.upper())
                            proc_stats[process_name]["remote_ips"].add(dst_addr)
                            
                    except Exception as parse_error:
                        continue
            else:
                raise Exception("sudo cat /proc/net/nf_conntrack failed")
                
        except Exception as sudo_error:
            # Попытка 3: Fallback к обычному методу через psutil и ss
            try:
                # Получаем общий трафик из /proc/net/dev
                total_bytes_recv = 0
                total_bytes_sent = 0
                try:
                    with open('/proc/net/dev', 'r') as f:
                        for line in f:
                            if ':' in line and not line.startswith('Inter-'):
                                parts = line.split()
                                if len(parts) >= 10:
                                    total_bytes_recv += int(parts[1])
                                    total_bytes_sent += int(parts[9])
                except Exception:
                    pass
                
                # Получаем соединения через ss
                process_connections = collections.defaultdict(lambda: {
                    "connections": 0,
                    "protocols": set(),
                    "remote_ips": set()
                })
                
                try:
                    result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if 'users:' in line:
                                parts = line.split()
                                protocol = parts[0] if parts else "unknown"
                                
                                # Ищем PID
                                pid = None
                                for part in parts:
                                    if 'pid=' in part:
                                        pid = part.split('=')[1].split(',')[0]
                                        break
                                
                                if pid:
                                    try:
                                        proc = psutil.Process(int(pid))
                                        proc_name = proc.name()
                                        process_connections[proc_name]["connections"] += 1
                                        process_connections[proc_name]["protocols"].add(protocol.upper())
                                        
                                        # Ищем remote IP
                                        for part in parts:
                                            if ':' in part and not part.startswith('127.') and not part.startswith('::1'):
                                                remote_ip = part.split(':')[0]
                                                if remote_ip and remote_ip != '*':
                                                    process_connections[proc_name]["remote_ips"].add(remote_ip)
                                                break
                                    except:
                                        pass
                except Exception:
                    pass
                
                # Распределяем трафик пропорционально количеству соединений
                total_connections = sum(pc["connections"] for pc in process_connections.values())
                if total_connections > 0:
                    for proc_name, conn_info in process_connections.items():
                        if proc_name not in proc_stats:
                            proc_stats[proc_name] = {
                                "connections": 0, 
                                "bytes_recv": 0, 
                                "bytes_sent": 0,
                                "protocols": set(),
                                "remote_ips": set()
                            }
                        
                        proc_stats[proc_name]["connections"] = conn_info["connections"]
                        proc_stats[proc_name]["protocols"] = conn_info["protocols"]
                        proc_stats[proc_name]["remote_ips"] = conn_info["remote_ips"]
                        
                        # Распределяем трафик пропорционально
                        ratio = conn_info["connections"] / total_connections
                        proc_stats[proc_name]["bytes_recv"] = int(total_bytes_recv * ratio)
                        proc_stats[proc_name]["bytes_sent"] = int(total_bytes_sent * ratio)
                
            except Exception as fallback_error:
                return {"error": f"Не удалось получить данные о трафике. Попробуйте запустить с правами root или установить sudo."}
    
    except Exception as e:
        return {"error": f"Ошибка чтения /proc/net/nf_conntrack: {str(e)}"}
    
    # Преобразуем в список для фронта
    result = []
    for name, stat in proc_stats.items():
        result.append({
            "process": name,
            "connections": stat["connections"],
            "in_traffic": stat["bytes_recv"],
            "out_traffic": stat["bytes_sent"],
            "protocols": list(stat["protocols"]),
            "remote_ips_count": len(stat["remote_ips"])
        })
    
    # Сортируем по общему трафику (убывание)
    result.sort(key=lambda x: x["in_traffic"] + x["out_traffic"], reverse=True)
    
    return result 