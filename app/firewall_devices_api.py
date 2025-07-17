from fastapi import APIRouter, HTTPException, Query, Body
from app.models import FirewallDeviceModel, FirewallDeviceCreate
from app.database import get_all_firewall_devices, add_firewall_device, delete_firewall_device, get_firewall_device_by_id, get_device_config, save_device_config, backup_device_config, get_device_config_backups, get_device_config_audit
from typing import List
from netmiko import ConnectHandler
from pysnmp.hlapi.asyncio import *

router = APIRouter()

@router.get("/api/firewall_devices", response_model=List[FirewallDeviceModel])
async def api_get_devices():
    return await get_all_firewall_devices()

@router.post("/api/firewall_devices")
async def api_add_device(device: FirewallDeviceCreate):
    await add_firewall_device(device)
    return {"result": "ok"}

@router.delete("/api/firewall_devices/{device_id}")
async def api_delete_device(device_id: int):
    await delete_firewall_device(device_id)
    return {"result": "ok"}

async def get_snmp_interfaces(ip, community='public'):
    interfaces = []
    # OID для ifDescr (имя интерфейса)
    descr_oid = '1.3.6.1.2.1.2.2.1.2'
    # OID для ifOperStatus (статус интерфейса)
    status_oid = '1.3.6.1.2.1.2.2.1.8'
    # OID для ifInOctets (входящий трафик)
    in_octets_oid = '1.3.6.1.2.1.2.2.1.10'
    # OID для ifOutOctets (исходящий трафик)
    out_octets_oid = '1.3.6.1.2.1.2.2.1.16'

    descrs = {}
    statuses = {}
    in_octets = {}
    out_octets = {}

    # Получаем имена интерфейсов
    async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(descr_oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            idx = str(varBind[0]).split('.')[-1]
            descrs[idx] = str(varBind[1])

    # Получаем статусы
    async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(status_oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            idx = str(varBind[0]).split('.')[-1]
            statuses[idx] = int(varBind[1])

    # Получаем входящий трафик
    async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(in_octets_oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            idx = str(varBind[0]).split('.')[-1]
            in_octets[idx] = int(varBind[1])

    # Получаем исходящий трафик
    async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(out_octets_oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            idx = str(varBind[0]).split('.')[-1]
            out_octets[idx] = int(varBind[1])

    # Собираем интерфейсы
    for idx in descrs:
        interfaces.append({
            "interface": descrs.get(idx, f"if{idx}"),
            "status": "up" if statuses.get(idx, 2) == 1 else "down",
            "in_octets": in_octets.get(idx, 0),
            "out_octets": out_octets.get(idx, 0)
        })
    return interfaces

@router.get("/api/firewall_connections")
async def api_get_connections(device_id: int = Query(...)):
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SNMP-ветка
    if 'snmp' in device['type']:
        interfaces = await get_snmp_interfaces(device['ip'])
        return interfaces
    # SSH-ветка (как было)
    netmiko_device = {
        'device_type': device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    try:
        with ConnectHandler(**netmiko_device) as ssh:
            output = ssh.send_command('show conn' if 'cisco' in device['type'] else 'interface print')
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
                    "status": parts[6]
                })
        return connections
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/device_config")
async def api_get_device_config(device_id: int = Query(...)):
    config = await get_device_config(device_id)
    return {"config": config}

@router.post("/api/device_config")
async def api_save_device_config(device_id: int = Query(...), config: str = Body(...), username: str = Body(...)):
    await save_device_config(device_id, config, username)
    return {"result": "ok"}

@router.post("/api/device_config_backup")
async def api_backup_device_config(device_id: int = Query(...), config: str = Body(...), username: str = Body(...)):
    await backup_device_config(device_id, config, username)
    return {"result": "ok"}

@router.get("/api/device_config_backups")
async def api_get_device_config_backups(device_id: int = Query(...)):
    backups = await get_device_config_backups(device_id)
    return backups

@router.get("/api/device_config_audit")
async def api_get_device_config_audit(device_id: int = Query(...)):
    audit = await get_device_config_audit(device_id)
    return audit 

@router.post("/api/device_cli_command")
async def api_device_cli_command(device_id: int = Query(...), command: str = Body(...)):
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SNMP-ветка
    if 'snmp' in device['type']:
        parts = command.strip().split()
        if len(parts) < 2:
            return {"error": "Формат команды: get <OID> или walk <OID>"}
        action, oid = parts[0].lower(), parts[1]
        community = device.get('community', 'public')
        ip = device['ip']
        result = ""
        if action == "get":
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = await iterator
            if errorIndication:
                result = f"SNMP error: {errorIndication}"
            elif errorStatus:
                result = f"SNMP error: {errorStatus.prettyPrint()}"
            else:
                for varBind in varBinds:
                    result += f'{varBind[0]} = {varBind[1]}\n'
        elif action == "walk":
            async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication:
                    result += f"SNMP error: {errorIndication}\n"
                    break
                elif errorStatus:
                    result += f"SNMP error: {errorStatus.prettyPrint()}\n"
                    break
                else:
                    for varBind in varBinds:
                        result += f'{varBind[0]} = {varBind[1]}\n'
        else:
            result = "Поддерживаются только команды: get <OID>, walk <OID>"
        return {"result": result.strip()}
    # SSH-ветка (как было)
    netmiko_device = {
        'device_type': device['type'],
        'host': device['ip'],
        'username': device['username'],
        'password': device['password'],
    }
    try:
        with ConnectHandler(**netmiko_device) as ssh:
            output = ssh.send_command(command)
        return {"result": output}
    except Exception as e:
        return {"error": str(e)} 