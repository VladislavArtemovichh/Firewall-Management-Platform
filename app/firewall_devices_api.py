import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel
from netmiko import ConnectHandler
import re
import json

from .database import get_firewall_device_by_id
from .models import FirewallDeviceModel, FirewallDeviceCreate

router = APIRouter()

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SSH соединения
ssh_connections = {}

def get_ssh_connection(device_config):
    """Получает или создает SSH соединение"""
    key = f"{device_config['host']}_{device_config['username']}"
    if key not in ssh_connections:
        ssh_connections[key] = ConnectHandler(**device_config)
    return ssh_connections[key]

def close_ssh_connection(host, username):
    """Закрывает SSH соединение"""
    key = f"{host}_{username}"
    if key in ssh_connections:
        try:
            ssh_connections[key].disconnect()
        except:
            pass
        del ssh_connections[key]

# === DNS БЛОКИРОВКА (DNSMASQ) ===

@router.get("/api/device_dns_rules")
async def api_get_dns_rules(device_id: int = Query(...)):
    """API для получения списка заблокированных доменов через dnsmasq"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support DNS blocking")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Читаем содержимое dnsmasq.conf
            dnsmasq_config = ssh.send_command("cat /etc/dnsmasq.conf", read_timeout=10)
            
            # Парсим заблокированные домены
            domains = []
            for line in dnsmasq_config.splitlines():
                line = line.strip()
                if line.startswith('address=/') and line.endswith('/0.0.0.0'):
                    # Извлекаем домен из строки address=/domain.com/0.0.0.0
                    domain = line[9:-8]  # Убираем 'address=/' и '/0.0.0.0'
                    domains.append(domain)
            
            return {
                "device_name": device['name'],
                "domains": domains,
                "total_count": len(domains)
            }
            
        except Exception as e:
            logging.error(f"[DNS-LOG] Error getting DNS rules: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error getting rules: {str(e)}")
            
    except Exception as e:
        logging.error(f"[DNS-LOG] Error in api_get_dns_rules: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/api/device_dns_block")
async def api_add_dns_block(device_id: int = Query(...), request_data: dict = Body(...)):
    """API для добавления блокировки домена через dnsmasq"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support DNS blocking")
        
        domain = request_data.get('domain', '').strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Добавляем домен в dnsmasq.conf
            ssh.send_command(f"echo 'address=/{domain}/0.0.0.0' >> /etc/dnsmasq.conf", read_timeout=10)
            
            # Перезапускаем dnsmasq
            try:
                ssh.send_command("/etc/init.d/dnsmasq restart", read_timeout=30)
            except:
                try:
                    ssh.send_command("/etc/init.d/dnsmasq reload", read_timeout=30)
                except:
                    pass
            
            return {
                "success": True,
                "message": f"Домен {domain} заблокирован",
                "blocked_domain": domain,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[DNS-LOG] Error blocking domain {domain}: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error blocking domain: {str(e)}")
            
    except Exception as e:
        logging.error(f"[DNS-LOG] Error in api_add_dns_block: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/api/device_dns_unblock")
async def api_remove_dns_block(device_id: int = Query(...), request_data: dict = Body(...)):
    """API для удаления блокировки домена через dnsmasq"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support DNS blocking")
        
        domain = request_data.get('domain', '').strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Удаляем строку с доменом из dnsmasq.conf
            # Экранируем точку в домене для sed
            escaped_domain = domain.replace('.', r'\.')
            ssh.send_command(f"sed -i '/address=\\/{escaped_domain}\\/0\\.0\\.0\\.0/d' /etc/dnsmasq.conf", read_timeout=10)
            
            # Перезапускаем dnsmasq
            try:
                ssh.send_command("/etc/init.d/dnsmasq restart", read_timeout=30)
            except:
                try:
                    ssh.send_command("/etc/init.d/dnsmasq reload", read_timeout=30)
                except:
                    pass
            
            return {
                "success": True,
                "message": f"Домен {domain} разблокирован",
                "unblocked_domain": domain,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[DNS-LOG] Error unblocking domain {domain}: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error unblocking domain: {str(e)}")
            
    except Exception as e:
        logging.error(f"[DNS-LOG] Error in api_remove_dns_block: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/api/device_dns_clear_all")
async def api_clear_all_dns_blocks(device_id: int = Query(...)):
    """API для удаления всех DNS блокировок"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support DNS blocking")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Удаляем все строки с address= из dnsmasq.conf
            ssh.send_command("sed -i '/^address=\\/.*\\/0\\.0\\.0\\.0$/d' /etc/dnsmasq.conf", read_timeout=10)
            
            # Перезапускаем dnsmasq
            try:
                ssh.send_command("/etc/init.d/dnsmasq restart", read_timeout=30)
            except:
                try:
                    ssh.send_command("/etc/init.d/dnsmasq reload", read_timeout=30)
                except:
                    pass
            
            return {
                "success": True,
                "message": "Все DNS блокировки удалены",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[DNS-LOG] Error clearing all DNS blocks: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error clearing blocks: {str(e)}")
            
    except Exception as e:
        logging.error(f"[DNS-LOG] Error in api_clear_all_dns_blocks: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# === IP БЛОКИРОВКА (IPTABLES) ===

@router.get("/api/device_ip_rules")
async def api_get_ip_rules(device_id: int = Query(...), direction: str = Query(None)):
    """API для получения списка заблокированных IP через iptables"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support IP blocking")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Получаем заблокированные IP из iptables
            try:
                # Проверяем все цепочки: FORWARD, INPUT, OUTPUT
                chains = ['FORWARD', 'INPUT', 'OUTPUT']
                ips = []
                raw_rules = []  # Для отладки
                
                for chain in chains:
                    try:
                        iptables_output = ssh.send_command(f"iptables -L {chain} -n -v --line-numbers", read_timeout=10)
                        logging.info(f"[IP-LOG] Raw iptables output for {chain}: {iptables_output}")
                        
                        for line in iptables_output.splitlines():
                            line = line.strip()
                            if not line:  # Пропускаем пустые строки
                                continue
                                
                            logging.info(f"[IP-LOG] Processing line in {chain}: {line}")
                            raw_rules.append(f"{chain}: {line}")
                            
                            # Ищем все правила DROP (не только с комментарием blocked_ip)
                            if 'DROP' in line:
                                logging.info(f"[IP-LOG] Found DROP rule in {chain}: {line}")
                                
                                # Сначала пробуем найти IP в комментарии blocked_ip
                                # Ищем комментарий в формате /* blocked_ip:IP:PORT:direction */ или /* blocked_ip:IP:direction */
                                comment_match = re.search(r'blocked_ip:(\d+\.\d+\.\d+\.\d+)(?::(\d+))?(?::(in|out))?', line)
                                if comment_match:
                                    ip = comment_match.group(1)
                                    port = comment_match.group(2) if comment_match.group(2) else None
                                    direction = comment_match.group(3) if comment_match.group(3) else None
                                    
                                    # Проверяем, что IP валидный (только числовой IP, не DNS-имя)
                                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and not re.search(r'[a-zA-Z]', ip):
                                        # Формируем информацию о блокировке с направлением
                                        direction_text = {
                                            'in': 'входящий',
                                            'out': 'исходящий',
                                            'both': 'весь трафик'
                                        }.get(direction, 'неизвестно')
                                        
                                        if port:
                                            ip_info = f"{ip}:{port} ({direction_text})"
                                        else:
                                            ip_info = f"{ip} ({direction_text})"
                                        
                                        # Добавляем IP с информацией о направлении
                                        ips.append(ip_info)
                                        logging.info(f"[IP-LOG] Added IP from comment: {ip_info}")
                                        continue  # Переходим к следующей строке, так как уже нашли IP
                                
                                # Если нет комментария, ищем IP в самой строке правила
                                # Улучшенный поиск IP-адресов в строке
                                ip_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                                logging.info(f"[IP-LOG] Found IP matches in line: {ip_matches}")
                                
                                for ip in ip_matches:
                                    # Проверяем, что это не служебные IP и что это числовой IP
                                    if (ip != '0.0.0.0' and ip != '127.0.0.1' and 
                                        ip != '255.255.255.255' and ip != '224.0.0.0' and
                                        re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and 
                                        not re.search(r'[a-zA-Z]', ip)):
                                        
                                        # Определяем направление по содержимому строки и цепочке
                                        rule_direction = 'неизвестно'
                                        if chain == 'INPUT' or '-d ' + ip in line:
                                            rule_direction = 'входящий'
                                        elif chain == 'OUTPUT' or '-s ' + ip in line:
                                            rule_direction = 'исходящий'
                                        elif chain == 'FORWARD':
                                            if '-d ' + ip in line:
                                                rule_direction = 'входящий'
                                            elif '-s ' + ip in line:
                                                rule_direction = 'исходящий'
                                        
                                        ip_info = f"{ip} ({rule_direction})"
                                        ips.append(ip_info)
                                        logging.info(f"[IP-LOG] Added IP from rule: {ip_info}")
                    except Exception as chain_error:
                        logging.error(f"[IP-LOG] Error processing chain {chain}: {chain_error}")
                        continue
                
                # Убираем дубликаты
                ips = list(set(ips))
                
                # Фильтруем по направлению, если указано
                if direction:
                    filter_direction = direction.lower()
                    filtered_ips = []
                    for ip_info in ips:
                        if filter_direction == 'in' and 'входящий' in ip_info:
                            filtered_ips.append(ip_info)
                        elif filter_direction == 'out' and 'исходящий' in ip_info:
                            filtered_ips.append(ip_info)
                        elif filter_direction == 'both':
                            # Для 'both' показываем все IP, но группируем по направлению
                            filtered_ips.append(ip_info)
                    ips = filtered_ips
                
                logging.info(f"[IP-LOG] Total blocked IPs found: {len(ips)} (filtered by direction: {filter_direction if 'filter_direction' in locals() else direction})")
                logging.info(f"[IP-LOG] All found IPs: {ips}")
                logging.info(f"[IP-LOG] Raw rules processed: {raw_rules}")
                
                return {
                    "device_name": device['name'],
                    "ips": ips,
                    "total_count": len(ips),
                    "filter_direction": filter_direction if 'filter_direction' in locals() else direction,
                    "debug_info": {
                        "raw_rules_count": len(raw_rules),
                        "raw_rules_sample": raw_rules[:5] if raw_rules else []  # Первые 5 правил для отладки
                    }
                }
                
            except Exception as e:
                logging.error(f"[IP-LOG] Error getting IP rules: {e}")
                return {
                    "device_name": device['name'],
                    "ips": [],
                    "error": f"Ошибка получения правил: {str(e)}",
                    "debug_info": {
                        "error_details": str(e),
                        "raw_rules_count": len(raw_rules),
                        "raw_rules_sample": raw_rules[:5] if raw_rules else []
                    }
                }
                
        except Exception as e:
            logging.error(f"[IP-LOG] Error connecting to device: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error connecting to device: {str(e)}")
            
    except Exception as e:
        logging.error(f"[IP-LOG] Error in api_get_ip_rules: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.get("/api/device_iptables_raw")
async def api_get_iptables_raw(device_id: int = Query(...)):
    """API для получения сырых данных iptables без фильтрации"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support IP blocking")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Получаем все правила iptables без фильтрации
            chains = ['FORWARD', 'INPUT', 'OUTPUT']
            all_rules = {}
            
            for chain in chains:
                try:
                    iptables_output = ssh.send_command(f"iptables -L {chain} -n -v --line-numbers", read_timeout=10)
                    all_rules[chain] = iptables_output.splitlines()
                    logging.info(f"[IPTABLES-RAW] Chain {chain} rules: {len(all_rules[chain])} lines")
                except Exception as e:
                    logging.error(f"[IPTABLES-RAW] Error getting {chain} rules: {e}")
                    all_rules[chain] = [f"Error: {str(e)}"]
            
            return {
                "device_name": device['name'],
                "all_rules": all_rules,
                "total_chains": len(chains),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[IPTABLES-RAW] Error connecting to device: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error connecting to device: {str(e)}")
            
    except Exception as e:
        logging.error(f"[IPTABLES-RAW] Error in api_get_iptables_raw: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/api/device_ip_block")
async def api_add_ip_block(device_id: int = Query(...), request_data: dict = Body(...)):
    """API для добавления блокировки IP через iptables"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support IP blocking")
        
        ip = request_data.get('ip', '').strip()
        print(ip)
        port = request_data.get('port', '').strip()
        direction = request_data.get('direction', 'both').strip().lower()  # 'in', 'out', 'both'
        
        logging.info(f"[IP-LOG] Received request to block IP: '{ip}', port: '{port}', direction: '{direction}'")
        logging.info(f"[IP-LOG] Request data: {request_data}")
        
        if not ip:
            raise HTTPException(status_code=400, detail="IP address is required")
        
        # Принудительная проверка, что IP - это числовой адрес, а не DNS-имя
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            logging.error(f"[IP-LOG] Invalid IP format: '{ip}'")
            raise HTTPException(status_code=400, detail="Invalid IP address format. Only numeric IP addresses are allowed.")
        
        # Дополнительная проверка на DNS-имена
        if re.search(r'[a-zA-Z]', ip):
            logging.error(f"[IP-LOG] DNS name detected: '{ip}'")
            raise HTTPException(status_code=400, detail="DNS names are not allowed. Please use numeric IP addresses only.")
        
        logging.info(f"[IP-LOG] IP validation passed: '{ip}'")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Формируем команды iptables в зависимости от направления
            
            if port:
                # Блокируем конкретный порт
                if direction in ['in', 'both']:
                    # Блокируем входящий трафик к IP на указанном порту
                    cmd1 = f"iptables -I FORWARD 1 -d {ip} -p tcp --dport {port} -j DROP -m comment --comment 'blocked_ip:{ip}:{port}:in'"
                    ssh.send_command(cmd1, read_timeout=10)
                    logging.info(f"[IP-LOG] Added IN rule for IP {ip}:{port} with comment: blocked_ip:{ip}:{port}:in")
                
                if direction in ['out', 'both']:
                    # Блокируем исходящий трафик от IP с указанного порта
                    cmd2 = f"iptables -I FORWARD 1 -s {ip} -p tcp --sport {port} -j DROP -m comment --comment 'blocked_ip:{ip}:{port}:out'"
                    ssh.send_command(cmd2, read_timeout=10)
                    logging.info(f"[IP-LOG] Added OUT rule for IP {ip}:{port} with comment: blocked_ip:{ip}:{port}:out")
            else:
                # Блокируем весь трафик
                if direction in ['in', 'both']:
                    # Блокируем весь входящий трафик к IP (FORWARD + INPUT)
                    cmd1 = f"iptables -I FORWARD 1 -d {ip} -j DROP -m comment --comment 'blocked_ip:{ip}:in'"
                    ssh.send_command(cmd1, read_timeout=10)
                    cmd1_input = f"iptables -I INPUT 1 -d {ip} -j DROP -m comment --comment 'blocked_ip:{ip}:in'"
                    ssh.send_command(cmd1_input, read_timeout=10)
                    logging.info(f"[IP-LOG] Added IN rules for IP {ip} (FORWARD + INPUT)")
                
                if direction in ['out', 'both']:
                    # Блокируем весь исходящий трафик от IP (FORWARD + OUTPUT)
                    cmd2 = f"iptables -I FORWARD 1 -s {ip} -j DROP -m comment --comment 'blocked_ip:{ip}:out'"
                    ssh.send_command(cmd2, read_timeout=10)
                    cmd2_output = f"iptables -I OUTPUT 1 -d {ip} -j DROP -m comment --comment 'blocked_ip:{ip}:out'"
                    ssh.send_command(cmd2_output, read_timeout=10)
                    logging.info(f"[IP-LOG] Added OUT rules for IP {ip} (FORWARD + OUTPUT)")
            
            # Формируем сообщение в зависимости от направления
            direction_text = {
                'in': 'входящий трафик',
                'out': 'исходящий трафик', 
                'both': 'весь трафик'
            }.get(direction, 'весь трафик')
            
            return {
                "success": True,
                "message": f"IP {ip}" + (f":{port}" if port else "") + f" заблокирован ({direction_text})",
                "blocked_ip": ip,
                "blocked_port": port,
                "direction": direction,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[IP-LOG] Error blocking IP {ip}: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error blocking IP: {str(e)}")
            
    except Exception as e:
        logging.error(f"[IP-LOG] Error in api_add_ip_block: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.post("/api/device_ip_unblock")
async def api_remove_ip_block(device_id: int = Query(...), request_data: dict = Body(...)):
    """API для удаления блокировки IP через iptables"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support IP blocking")
        
        ip = request_data.get('ip', '').strip()
        
        logging.info(f"[IP-LOG] Received request to unblock IP: '{ip}'")
        logging.info(f"[IP-LOG] Request data: {request_data}")
        
        if not ip:
            raise HTTPException(status_code=400, detail="IP address is required")
        
        # Принудительная проверка, что IP - это числовой адрес, а не DNS-имя
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            logging.error(f"[IP-LOG] Invalid IP format: '{ip}'")
            raise HTTPException(status_code=400, detail="Invalid IP address format. Only numeric IP addresses are allowed.")
        
        # Дополнительная проверка на DNS-имена
        if re.search(r'[a-zA-Z]', ip):
            logging.error(f"[IP-LOG] DNS name detected: '{ip}'")
            raise HTTPException(status_code=400, detail="DNS names are not allowed. Please use numeric IP addresses only.")
        
        logging.info(f"[IP-LOG] IP validation passed: '{ip}'")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            
            # Удаляем правила iptables для этого IP из всех цепочек
            
            # Проверяем все цепочки: FORWARD, INPUT, OUTPUT
            chains = ['FORWARD', 'INPUT', 'OUTPUT']
            total_removed = 0
            
            for chain in chains:
                iptables_output = ssh.send_command(f"iptables -L {chain} -n -v --line-numbers", read_timeout=10)
                logging.info(f"[IP-LOG] Looking for IP {ip} in {chain} chain")
            
                rule_numbers = []
                for line in iptables_output.splitlines():
                    line = line.strip()
                    logging.info(f"[IP-LOG] Checking line in {chain}: {line}")
                    
                    # Ищем все правила DROP с нужным IP (не только с комментарием blocked_ip)
                    if 'DROP' in line:
                        # Проверяем, есть ли IP в строке правила
                        ip_matches = re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', line)
                        for rule_ip in ip_matches:
                            # Проверяем, что это числовой IP, а не DNS-имя
                            if rule_ip == ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', rule_ip) and not re.search(r'[a-zA-Z]', rule_ip):
                                # Извлекаем номер строки
                                match = re.search(r'^(\d+)', line)
                                if match:
                                    rule_numbers.append((chain, match.group(1)))
                                    logging.info(f"[IP-LOG] Found rule number {match.group(1)} for IP {ip} in {chain}")
                                    break  # Нашли IP в этом правиле, переходим к следующему правилу
                
                if rule_numbers:
                    # Удаляем правила в обратном порядке (чтобы номера не сбились)
                    rule_numbers.reverse()
                    for chain_name, rule_num in rule_numbers:
                        try:
                            ssh.send_command(f"iptables -D {chain_name} {rule_num}", read_timeout=10)
                            logging.info(f"[IP-LOG] Removed rule {rule_num} from {chain_name}")
                            total_removed += 1
                        except Exception as e:
                            logging.error(f"[IP-LOG] Error removing rule {rule_num} from {chain_name}: {e}")
            
            if total_removed > 0:
                message = f"IP {ip} разблокирован (удалено {total_removed} правил)"
            else:
                message = f"IP {ip} не найден в правилах блокировки"
                logging.warning(f"[IP-LOG] IP {ip} not found in rules")
            
            return {
                "success": True,
                "message": message,
                "unblocked_ip": ip,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[IP-LOG] Error unblocking IP {ip}: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error unblocking IP: {str(e)}")
            
    except Exception as e:
        logging.error(f"[IP-LOG] Error in api_remove_ip_block: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")



@router.post("/api/device_ip_clear_all")
async def api_clear_all_ip_blocks(device_id: int = Query(...)):
    """API для удаления всех IP блокировок"""
    try:
        device = await get_firewall_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if device['type'] != 'openwrt':
            raise HTTPException(status_code=400, detail="Device type does not support IP blocking")
        
        netmiko_device = {
            'device_type': 'linux',
            'host': device['ip'],
            'username': device['username'],
            'password': device['password'],
        }
        
        try:
            ssh = get_ssh_connection(netmiko_device)
            

            
            # Получаем все правила DROP из всех цепочек
            chains = ['FORWARD', 'INPUT', 'OUTPUT']
            total_removed = 0
            
            for chain in chains:
                iptables_output = ssh.send_command(f"iptables -L {chain} -n -v --line-numbers", read_timeout=10)
                rule_numbers = []
                
                for line in iptables_output.splitlines():
                    line = line.strip()
                    if 'DROP' in line:
                        # Извлекаем номер строки
                        match = re.search(r'^(\d+)', line)
                        if match:
                            rule_numbers.append(match.group(1))
                            logging.info(f"[IP-LOG] Found DROP rule number {match.group(1)} in {chain}: {line}")
                
                # Удаляем правила в обратном порядке (чтобы номера не сбились)
                rule_numbers.reverse()
                for rule_num in rule_numbers:
                    try:
                        ssh.send_command(f"iptables -D {chain} {rule_num}", read_timeout=10)
                        total_removed += 1
                    except:
                        pass
            
            return {
                "success": True,
                "message": f"Удалено {total_removed} IP блокировок",
                "removed_count": total_removed,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"[IP-LOG] Error clearing all IP blocks: {e}")
            close_ssh_connection(device['ip'], device['username'])
            raise HTTPException(status_code=500, detail=f"Error clearing blocks: {str(e)}")
            
    except Exception as e:
        logging.error(f"[IP-LOG] Error in api_clear_all_ip_blocks: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# === УПРАВЛЕНИЕ УСТРОЙСТВАМИ ===

@router.get("/api/firewall_devices", response_model=List[FirewallDeviceModel])
async def api_get_devices():
    """API для получения списка устройств"""
    from .database import get_all_firewall_devices
    devices = await get_all_firewall_devices()
    logging.info(f"[API-LOG] Returning {len(devices)} devices")
    for i, device in enumerate(devices):
        logging.info(f"[API-LOG] Device {i+1}: {device}")
    result = [FirewallDeviceModel(**device) for device in devices]
    logging.info(f"[API-LOG] Final result: {result}")
    return result

@router.get("/api/firewall_devices_raw")
async def api_get_devices_raw():
    """API для получения сырых данных устройств без обновления статуса"""
    import asyncpg
    from .db_config import DB_USER, DB_PASSWORD, DB_NAME, DB_HOST, DB_PORT
    
    try:
        conn = await asyncpg.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST,
            port=DB_PORT
        )
        rows = await conn.fetch('SELECT * FROM firewall_devices ORDER BY id')
        await conn.close()
        
        devices = [dict(row) for row in rows]
        logging.info(f"[API-LOG] Raw devices from DB: {devices}")
        return {"devices": devices, "count": len(devices)}
        
    except Exception as e:
        logging.error(f"[API-LOG] Error getting raw devices: {e}")
        return {"error": str(e), "devices": [], "count": 0}

@router.post("/api/firewall_devices")
async def api_add_device(device: FirewallDeviceCreate):
    """API для добавления устройства"""
    from .database import add_firewall_device
    await add_firewall_device(device)
    return {"message": "Device added successfully"}

@router.delete("/api/firewall_devices/{device_id}")
async def api_delete_device(device_id: int):
    """API для удаления устройства"""
    from .database import delete_firewall_device
    await delete_firewall_device(device_id)
    return {"message": "Device deleted successfully"}

 
