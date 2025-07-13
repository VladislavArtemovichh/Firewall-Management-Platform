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
        adapter = {
            'name': name,
            'mac': mac,
            'ip': ip,
            'speed': stats.speed if stats else None,
            'isup': stats.isup if stats else None,
            'in_packets': io.packets_recv if io else None,
            'out_packets': io.packets_sent if io else None,
            'in_errors': io.errin if io else None,
            'out_errors': io.errout if io else None
        }
        if stats and stats.isup:
            adapters_active.append(adapter)
        else:
            adapters_inactive.append(adapter)
    return {'active': adapters_active, 'inactive': adapters_inactive}

@router.get("/api/bandwidth")
async def get_bandwidth():
    import psutil
    import collections
    proc_stats = collections.defaultdict(lambda: {"connections": 0, "bytes_recv": 0, "bytes_sent": 0})
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'] or f"pid_{proc.info['pid']}"
            # Считаем только процессы с сетевыми соединениями
            conns = proc.connections(kind='inet')
            if not conns:
                continue
            net_io = proc.io_counters() if hasattr(proc, 'io_counters') else None
            # psutil не даёт трафик только по сети для процесса, но можно получить bytes_sent/recv для сокетов
            # Альтернатива: использовать net_io_counters для интерфейсов, но не по процессам
            # Поэтому считаем только количество соединений, а трафик — общий по процессу (может включать диск)
            bytes_sent = 0
            bytes_recv = 0
            try:
                for c in conns:
                    if c.raddr:
                        # Для TCP/UDP сокетов можно получить send/recv через psutil (ограниченно)
                        pass
                # psutil не даёт сетевой трафик по процессу напрямую
            except Exception:
                pass
            proc_stats[name]["connections"] += len(conns)
            # Оставляем bytes_sent/recv = 0, т.к. psutil не даёт сетевой трафик по процессу напрямую
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
    return result 