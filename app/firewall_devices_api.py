from fastapi import APIRouter, HTTPException, Query, Body, WebSocket, WebSocketDisconnect
from app.models import FirewallDeviceModel, FirewallDeviceCreate
from app.database import get_all_firewall_devices, add_firewall_device, delete_firewall_device, get_firewall_device_by_id, get_device_config, save_device_config, backup_device_config, get_device_config_backups, get_device_config_audit
from typing import List
from netmiko import ConnectHandler
from pysnmp.hlapi.asyncio import *
import asyncio
import logging
import sys
import re
import subprocess
from datetime import datetime
import threading
from netmiko import ConnectHandler
from .database import get_ssh_connection, close_ssh_connection, cleanup_dead_connections

class ColorFormatter(logging.Formatter):
    COLORS = {
        'INFO': '\033[92m',      # Зеленый
        'ERROR': '\033[91m',     # Красный
        'FIREWALL-LOG': '\033[94m', # Синий
        'NETMIKO': '\033[95m',   # Фиолетовый
        'PARAMIKO': '\033[93m',  # Желтый
        'RESET': '\033[0m',
    }
    def format(self, record):
        msg = super().format(record)
        lower_msg = msg.lower()
        if '[FIREWALL-LOG]' in msg:
            color = self.COLORS['FIREWALL-LOG']
        elif 'netmiko' in lower_msg:
            color = self.COLORS['NETMIKO']
        elif 'paramiko' in lower_msg:
            color = self.COLORS['PARAMIKO']
        elif record.levelno == logging.INFO:
            color = self.COLORS['INFO']
        elif record.levelno == logging.ERROR:
            color = self.COLORS['ERROR']
        else:
            color = ''
        reset = self.COLORS['RESET']
        return f"{color}{msg}{reset}"

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter('%(asctime)s %(levelname)s %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[handler])

router = APIRouter()

@router.get("/api/firewall_devices", response_model=List[FirewallDeviceModel])
async def api_get_devices():
    logging.info("[FIREWALL-LOG] api_get_devices called")
    return await get_all_firewall_devices()

@router.post("/api/firewall_devices")
async def api_add_device(device: FirewallDeviceCreate):
    logging.info(f"[FIREWALL-LOG] api_add_device called with device={device}")
    await add_firewall_device(device)
    return {"result": "ok"}

@router.delete("/api/firewall_devices/{device_id}")
async def api_delete_device(device_id: int):
    logging.info(f"[FIREWALL-LOG] api_delete_device called with device_id={device_id}")
    await delete_firewall_device(device_id)
    return {"result": "ok"}

def poll_device_via_ssh_sync(netmiko_device, command):
    from netmiko import ConnectHandler
    logging.info(f"[FIREWALL-LOG] poll_device_via_ssh_sync called with netmiko_device={netmiko_device}, command={command}")
    with ConnectHandler(**netmiko_device) as ssh:
        return ssh.send_command(command)

async def poll_device_via_ssh(netmiko_device, command):
    loop = asyncio.get_event_loop()
    logging.info(f"[FIREWALL-LOG] poll_device_via_ssh called with netmiko_device={netmiko_device}, command={command}")
    return await loop.run_in_executor(None, poll_device_via_ssh_sync, netmiko_device, command)

@router.get("/api/firewall_connections")
async def api_get_connections(device_id: int = Query(...)):
    logging.info(f"[FIREWALL-LOG] api_get_connections called with device_id={device_id}")
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    netmiko_device = {
        'device_type': 'linux' if device['type'] == 'openwrt' else device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    try:
        if device['type'] == 'openwrt' or device['type'] == 'linux':
            # Сначала пробуем получить данные из nf_conntrack (более детально)
            try:
                command = 'cat /proc/net/nf_conntrack'
                output = await poll_device_via_ssh(netmiko_device, command)
                connections = []
                
                for line in str(output).splitlines():
                    if not line.strip():
                        continue
                    
                    # Парсим строку nf_conntrack
                    # Пример: ipv4 2 tcp 6 300 ESTABLISHED src=192.168.1.100 dst=8.8.8.8 sport=12345 dport=53 packets=5 bytes=300 src=8.8.8.8 dst=192.168.1.100 sport=53 dport=12345 packets=3 bytes=150 mark=0 use=1
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    try:
                        # Извлекаем основную информацию
                        protocol = parts[2]  # tcp, udp, icmp
                        state = parts[5]     # ESTABLISHED, TIME_WAIT, etc.
                        
                        # Ищем src и dst адреса
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
                                # Первый packets - входящие
                                if packets_in == 0:
                                    packets_in = int(parts[i+1])
                                else:
                                    packets_out = int(parts[i+1])
                            elif part == 'bytes=':
                                # Первый bytes - входящие
                                if bytes_in == 0:
                                    bytes_in = int(parts[i+1])
                                else:
                                    bytes_out = int(parts[i+1])
                        
                        if src_addr and dst_addr:
                            connections.append({
                                "interface": '-',
                                "protocol": protocol.upper(),
                                "local_address": src_addr,
                                "local_port": src_port or '-',
                                "remote_address": dst_addr,
                                "remote_port": dst_port or '-',
                                "status": state,
                                "process": '-',
                                "packets_in": packets_in,
                                "bytes_in": bytes_in,
                                "packets_out": packets_out,
                                "bytes_out": bytes_out,
                                "total_traffic": bytes_in + bytes_out
                            })
                    except Exception as parse_error:
                        logging.warning(f"[FIREWALL-LOG] Error parsing nf_conntrack line: {line[:100]}... Error: {parse_error}")
                        continue
                
                if connections:
                    # Сортируем по общему трафику (убывание)
                    connections.sort(key=lambda x: x.get('total_traffic', 0), reverse=True)
                    return connections
                    
            except Exception as nf_error:
                logging.warning(f"[FIREWALL-LOG] nf_conntrack failed, falling back to netstat: {nf_error}")
            
            # Fallback к netstat если nf_conntrack недоступен
            command = 'netstat -tunp'
            output = await poll_device_via_ssh(netmiko_device, command)
            connections = []
            for line in str(output).splitlines():
                if line.startswith('Proto') or line.startswith('Active') or not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 7:
                    continue
                proto = parts[0]
                local = parts[3]
                remote = parts[4]
                status = parts[5] if proto.startswith('tcp') else '-'
                pid_proc = parts[6] if len(parts) > 6 else '-'
                local_addr, local_port = local.rsplit(':', 1) if ':' in local else (local, '-')
                remote_addr, remote_port = remote.rsplit(':', 1) if ':' in remote else (remote, '-')
                connections.append({
                    "interface": '-',
                    "protocol": proto,
                    "local_address": local_addr,
                    "local_port": local_port,
                    "remote_address": remote_addr,
                    "remote_port": remote_port,
                    "status": status,
                    "process": pid_proc,
                    "packets_in": 0,
                    "bytes_in": 0,
                    "packets_out": 0,
                    "bytes_out": 0,
                    "total_traffic": 0
                })
            return connections
        elif 'cisco' in device['type']:
            command = 'show conn'
            output = await poll_device_via_ssh(netmiko_device, command)
            connections = []
            for line in str(output).splitlines():
                if not line.strip() or line.startswith(' '):
                    continue
                parts = line.split()
                if len(parts) >= 7:
                    connections.append({
                        "interface": parts[0],
                        "protocol": parts[1],
                        "local_address": parts[2],
                        "local_port": parts[3],
                        "remote_address": parts[4],
                        "remote_port": parts[5],
                        "status": parts[6],
                        "process": '-',
                        "packets_in": 0,
                        "bytes_in": 0,
                        "packets_out": 0,
                        "bytes_out": 0,
                        "total_traffic": 0
                    })
            return connections
        elif 'mikrotik' in device['type']:
            # Mikrotik RouterOS использует свой синтаксис команд
            command = '/ip firewall connection print'
            output = await poll_device_via_ssh(netmiko_device, command)
            connections = []
            
            for line in str(output).splitlines():
                if not line.strip() or line.startswith('Flags:') or line.startswith('Columns:'):
                    continue
                
                # Парсим вывод Mikrotik
                # Пример: 0 D tcp 192.168.1.100:12345 8.8.8.8:53 established 0 0
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        # Извлекаем данные из строки Mikrotik
                        protocol = parts[2].upper()  # tcp, udp, icmp
                        local_full = parts[3]  # 192.168.1.100:12345
                        remote_full = parts[4]  # 8.8.8.8:53
                        status = parts[5]  # established, time-wait, etc.
                        
                        # Парсим адреса и порты
                        local_addr, local_port = local_full.rsplit(':', 1) if ':' in local_full else (local_full, '-')
                        remote_addr, remote_port = remote_full.rsplit(':', 1) if ':' in remote_full else (remote_full, '-')
                        
                        # Пытаемся получить трафик (если есть дополнительные поля)
                        packets_in = 0
                        bytes_in = 0
                        packets_out = 0
                        bytes_out = 0
                        
                        if len(parts) >= 8:
                            try:
                                packets_in = int(parts[6])
                                bytes_in = int(parts[7])
                            except:
                                pass
                        
                        if len(parts) >= 10:
                            try:
                                packets_out = int(parts[8])
                                bytes_out = int(parts[9])
                            except:
                                pass
                        
                        connections.append({
                            "interface": '-',
                            "protocol": protocol,
                            "local_address": local_addr,
                            "local_port": local_port,
                            "remote_address": remote_addr,
                            "remote_port": remote_port,
                            "status": status,
                            "process": '-',
                            "packets_in": packets_in,
                            "bytes_in": bytes_in,
                            "packets_out": packets_out,
                            "bytes_out": bytes_out,
                            "total_traffic": bytes_in + bytes_out
                        })
                    except Exception as parse_error:
                        logging.warning(f"[FIREWALL-LOG] Error parsing Mikrotik line: {line[:100]}... Error: {parse_error}")
                        continue
            
            # Сортируем по общему трафику (убывание)
            connections.sort(key=lambda x: x.get('total_traffic', 0), reverse=True)
            return connections
        else:
            raise HTTPException(status_code=400, detail="Unsupported device type")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/device_config")
async def api_get_device_config(device_id: int = Query(...)):
    logging.info(f"[FIREWALL-LOG] api_get_device_config called with device_id={device_id}")
    config = await get_device_config(device_id)
    return {"config": config}

@router.post("/api/device_config")
async def api_save_device_config(device_id: int = Query(...), config: str = Body(...), username: str = Body(...)):
    logging.info(f"[FIREWALL-LOG] api_save_device_config called with device_id={device_id}, config={config}, username={username}")
    await save_device_config(device_id, config, username)
    return {"result": "ok"}

@router.post("/api/device_config_backup")
async def api_backup_device_config(device_id: int = Query(...), config: str = Body(...), username: str = Body(...)):
    logging.info(f"[FIREWALL-LOG] api_backup_device_config called with device_id={device_id}, config={config}, username={username}")
    await backup_device_config(device_id, config, username)
    return {"result": "ok"}

@router.get("/api/device_config_backups")
async def api_get_device_config_backups(device_id: int = Query(...)):
    logging.info(f"[FIREWALL-LOG] api_get_device_config_backups called with device_id={device_id}")
    backups = await get_device_config_backups(device_id)
    return backups

@router.get("/api/device_config_audit")
async def api_get_device_config_audit(device_id: int = Query(...)):
    logging.info(f"[FIREWALL-LOG] api_get_device_config_audit called with device_id={device_id}")
    audit = await get_device_config_audit(device_id)
    return audit 

@router.post("/api/device_cli_command")
async def api_device_cli_command(device_id: int = Query(...), command_data: dict = Body(...)):
    logging.info(f"[FIREWALL-LOG] api_device_cli_command called with device_id={device_id}, command_data={command_data}")
    command = command_data.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="Command is required")
    
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SSH-ветка (через executor)
    netmiko_device = {
        'device_type': 'linux' if device['type'] == 'openwrt' else device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    try:
        output = await poll_device_via_ssh(netmiko_device, command)
        return {"result": output}
    except Exception as e:
        return {"error": str(e)} 

@router.get("/api/device_interfaces")
async def api_get_device_interfaces(device_id: int = Query(...)):
    logging.info(f"[FIREWALL-LOG] api_get_device_interfaces called with device_id={device_id}")
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    netmiko_device = {
        'device_type': 'linux' if device['type'] == 'openwrt' else device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    
    try:
        if device['type'] == 'mikrotik_routeros':
            # Mikrotik RouterOS
            command = '/interface print'
            output = await poll_device_via_ssh(netmiko_device, command)
            interfaces = []
            
            for line in str(output).splitlines():
                if line.startswith('Flags:') or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    interface_name = parts[1]
                    status = 'UP' if 'R' in parts[0] else 'DOWN'
                    interfaces.append({
                        "interface": interface_name,
                        "status": status,
                        "ipv4": '-',
                        "ipv6": '-',
                        "mac": '-',
                        "mtu": '-',
                        "rx_bytes": 0,
                        "tx_bytes": 0
                    })
            
            # Получаем статистику трафика
            try:
                stats_command = '/interface print stats'
                stats_output = await poll_device_via_ssh(netmiko_device, stats_command)
                
                for line in str(stats_output).splitlines():
                    if 'rx-byte=' in line and 'tx-byte=' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'name=':
                                iface_name = parts[i+1]
                            elif part == 'rx-byte=':
                                rx_bytes = int(parts[i+1])
                            elif part == 'tx-byte=':
                                tx_bytes = int(parts[i+1])
                        
                        # Обновляем интерфейс
                        for iface in interfaces:
                            if iface['interface'] == iface_name:
                                iface['rx_bytes'] = rx_bytes
                                iface['tx_bytes'] = tx_bytes
                                break
            except Exception as stats_error:
                logging.warning(f"[FIREWALL-LOG] Failed to get Mikrotik interface stats: {stats_error}")
            
            return interfaces
            
        elif device['type'] == 'cisco_ios':
            # Cisco IOS
            command = 'show interfaces'
            output = await poll_device_via_ssh(netmiko_device, command)
            interfaces = []
            
            current_interface = None
            for line in str(output).splitlines():
                if line.startswith('Interface '):
                    if current_interface:
                        interfaces.append(current_interface)
                    interface_name = line.split()[1]
                    current_interface = {
                        "interface": interface_name,
                        "status": "DOWN",
                        "ipv4": '-',
                        "ipv6": '-',
                        "mac": '-',
                        "mtu": '-',
                        "rx_bytes": 0,
                        "tx_bytes": 0
                    }
                elif current_interface and 'line protocol is' in line:
                    if 'up' in line.lower():
                        current_interface['status'] = 'UP'
                elif current_interface and 'MTU' in line:
                    mtu_match = re.search(r'MTU (\d+)', line)
                    if mtu_match:
                        current_interface['mtu'] = mtu_match.group(1)
                elif current_interface and 'input packets' in line:
                    # Извлекаем байты из строки статистики
                    rx_match = re.search(r'(\d+) bytes', line)
                    if rx_match:
                        current_interface['rx_bytes'] = int(rx_match.group(1))
                elif current_interface and 'output packets' in line:
                    tx_match = re.search(r'(\d+) bytes', line)
                    if tx_match:
                        current_interface['tx_bytes'] = int(tx_match.group(1))
            
            if current_interface:
                interfaces.append(current_interface)
            
            return interfaces
            
        else:
            # Linux/OpenWrt
            command = 'cat /proc/net/dev'
            output = await poll_device_via_ssh(netmiko_device, command)
            interfaces = []
            
            for line in str(output).splitlines():
                if ':' in line and not line.startswith('Inter-'):
                    parts = line.split()
                    if len(parts) >= 10:
                        interface_name = parts[0].rstrip(':')
                        rx_bytes = int(parts[1])
                        tx_bytes = int(parts[9])
                        
                        interfaces.append({
                            "interface": interface_name,
                            "status": "UP",  # Предполагаем что интерфейс активен
                            "ipv4": '-',
                            "ipv6": '-',
                            "mac": '-',
                            "mtu": '-',
                            "rx_bytes": rx_bytes,
                            "tx_bytes": tx_bytes
                        })
            
            return interfaces
            
    except Exception as e:
        logging.error(f"[FIREWALL-LOG] Error getting device interfaces: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting device interfaces: {str(e)}")

@router.get("/api/device_traffic")
async def api_get_device_traffic(device_id: int = Query(...)):
    """API для получения данных о трафике с удалённого устройства через nf_conntrack"""
    logging.info(f"[FIREWALL-LOG] api_get_device_traffic called with device_id={device_id}")
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    netmiko_device = {
        'device_type': 'linux' if device['type'] == 'openwrt' else device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    
    try:
        if device['type'] == 'openwrt' or device['type'] == 'linux':
            # Получаем данные из nf_conntrack на роутере
            command = 'cat /proc/net/nf_conntrack'
            output = await poll_device_via_ssh(netmiko_device, command)
            
            # Группируем по процессам (если возможно)
            process_stats = {}
            
            for line in str(output).splitlines():
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
                        # Пытаемся найти процесс по порту
                        process_name = "unknown"
                        try:
                            # Используем netstat для поиска процесса
                            netstat_cmd = f"netstat -tunp | grep ':{src_port}'"
                            netstat_output = await poll_device_via_ssh(netmiko_device, netstat_cmd)
                            
                            for netstat_line in str(netstat_output).splitlines():
                                if f':{src_port}' in netstat_line and 'users:' in netstat_line:
                                    # Извлекаем имя процесса
                                    if 'users:' in netstat_line:
                                        users_part = netstat_line.split('users:')[1]
                                        if 'pid=' in users_part:
                                            pid_match = re.search(r'pid=(\d+)', users_part)
                                            if pid_match:
                                                pid = pid_match.group(1)
                                                # Получаем имя процесса
                                                ps_cmd = f"ps -p {pid} -o comm="
                                                ps_output = await poll_device_via_ssh(netmiko_device, ps_cmd)
                                                process_name = str(ps_output).strip() or f"pid_{pid}"
                                            break
                        except Exception:
                            pass
                        
                        if process_name not in process_stats:
                            process_stats[process_name] = {
                                "connections": 0,
                                "bytes_recv": 0,
                                "bytes_sent": 0,
                                "protocols": set(),
                                "remote_ips": set()
                            }
                        
                        process_stats[process_name]["connections"] += 1
                        process_stats[process_name]["bytes_recv"] += bytes_in
                        process_stats[process_name]["bytes_sent"] += bytes_out
                        process_stats[process_name]["protocols"].add(protocol.upper())
                        process_stats[process_name]["remote_ips"].add(dst_addr)
                        
                except Exception as parse_error:
                    logging.warning(f"[FIREWALL-LOG] Error parsing nf_conntrack line: {line[:100]}... Error: {parse_error}")
                    continue
            
            # Преобразуем в список для фронта
            result = []
            for name, stat in process_stats.items():
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
            
        elif device['type'] == 'mikrotik_routeros':
            # Mikrotik RouterOS - используем connection tracking
            command = '/ip firewall connection print'
            output = await poll_device_via_ssh(netmiko_device, command)
            
            process_stats = {}
            
            for line in str(output).splitlines():
                if 'connection' in line.lower() or not line.strip():
                    continue
                
                try:
                    parts = line.split()
                    if len(parts) >= 4:
                        # Парсим Mikrotik connection output
                        protocol = parts[0] if parts else "unknown"
                        src_addr = parts[1] if len(parts) > 1 else "unknown"
                        dst_addr = parts[2] if len(parts) > 2 else "unknown"
                        status = parts[3] if len(parts) > 3 else "unknown"
                        
                        process_name = "mikrotik_connection"
                        
                        if process_name not in process_stats:
                            process_stats[process_name] = {
                                "connections": 0,
                                "bytes_recv": 0,
                                "bytes_sent": 0,
                                "protocols": set(),
                                "remote_ips": set()
                            }
                        
                        process_stats[process_name]["connections"] += 1
                        process_stats[process_name]["protocols"].add(protocol.upper())
                        process_stats[process_name]["remote_ips"].add(dst_addr)
                        
                except Exception as parse_error:
                    continue
            
            # Преобразуем в список для фронта
            result = []
            for name, stat in process_stats.items():
                result.append({
                    "process": name,
                    "connections": stat["connections"],
                    "in_traffic": stat["bytes_recv"],
                    "out_traffic": stat["bytes_sent"],
                    "protocols": list(stat["protocols"]),
                    "remote_ips_count": len(stat["remote_ips"])
                })
            
            return result
            
        else:
            # Для других устройств возвращаем базовую информацию
            return [{
                "process": "device_connection",
                "connections": 0,
                "in_traffic": 0,
                "out_traffic": 0,
                "protocols": [],
                "remote_ips_count": 0
            }]
            
    except Exception as e:
        logging.error(f"[FIREWALL-LOG] Error getting device traffic: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting device traffic: {str(e)}") 

@router.get("/api/device_nf_conntrack")
async def api_get_device_nf_conntrack(device_id: int = Query(...)):
    """API для получения данных nf_conntrack с устройства"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        netmiko_device = {
            'device_type': 'linux' if device['type'] == 'openwrt' else device['type'],
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            # Используем кэшированное SSH соединение
            ssh = get_ssh_connection(netmiko_device)
            
            if device['type'] == 'mikrotik_routeros':
                # Для Mikrotik RouterOS используем connection tracking
                result = ssh.send_command("/ip firewall connection print", read_timeout=10)
                lines = [line for line in result.splitlines() if line.strip() and not line.startswith('Flags:')]
            else:
                # Для Linux/OpenWrt используем nf_conntrack
                result = ssh.send_command("cat /proc/net/nf_conntrack", read_timeout=10)
                lines = [line for line in result.splitlines() if line.strip()]
            
            # НЕ закрываем соединение - оно остается в кэше для переиспользования
            
            return {
                "device_name": device['name'],
                "device_ip": device['ip'],
                "lines": lines,
                "total_connections": len(lines),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[FIREWALL-LOG] Error getting nf_conntrack from {device['ip']}: {e}")
            # При ошибке закрываем соединение из кэша
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error connecting to device: {str(e)}")
            
    except Exception as e:
        logging.error(f"[FIREWALL-LOG] Error in api_get_device_nf_conntrack: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}") 

def get_all_network_interfaces_info():
    """
    Получает информацию о всех сетевых интерфейсах на локальной машине.
    """
    interfaces = []
    try:
        # Используем psutil для получения информации о сетевых интерфейсах
        import psutil
        for interface, addrs in psutil.net_if_addrs().items():
            if addrs:
                ipv4_info = next((addr for addr in addrs if addr.family == psutil.AF_INET), None)
                ipv6_info = next((addr for addr in addrs if addr.family == psutil.AF_INET6), None)
                
                if ipv4_info:
                    interfaces.append({
                        "interface": interface,
                        "status": "UP",
                        "ipv4": ipv4_info.address,
                        "ipv6": ipv6_info.address if ipv6_info else "-",
                        "mac": psutil.net_if_stats()[interface].mac if interface in psutil.net_if_stats() else "-",
                        "mtu": psutil.net_if_stats()[interface].mtu if interface in psutil.net_if_stats() else "-",
                        "rx_bytes": psutil.net_if_stats()[interface].bytes_recv if interface in psutil.net_if_stats() else 0,
                        "tx_bytes": psutil.net_if_stats()[interface].bytes_sent if interface in psutil.net_if_stats() else 0
                    })
                elif ipv6_info:
                    interfaces.append({
                        "interface": interface,
                        "status": "UP",
                        "ipv4": "-",
                        "ipv6": ipv6_info.address,
                        "mac": psutil.net_if_stats()[interface].mac if interface in psutil.net_if_stats() else "-",
                        "mtu": psutil.net_if_stats()[interface].mtu if interface in psutil.net_if_stats() else "-",
                        "rx_bytes": psutil.net_if_stats()[interface].bytes_recv if interface in psutil.net_if_stats() else 0,
                        "tx_bytes": psutil.net_if_stats()[interface].bytes_sent if interface in psutil.net_if_stats() else 0
                    })
                else:
                    interfaces.append({
                        "interface": interface,
                        "status": "DOWN",
                        "ipv4": "-",
                        "ipv6": "-",
                        "mac": "-",
                        "mtu": "-",
                        "rx_bytes": 0,
                        "tx_bytes": 0
                    })
    except Exception as e:
        logging.error(f"[FIREWALL-LOG] Error getting local network interfaces: {e}")
    return interfaces 
