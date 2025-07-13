from fastapi import APIRouter
from fastapi.responses import JSONResponse
import psutil
import datetime
import socket

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