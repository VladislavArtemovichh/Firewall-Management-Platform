from fastapi import APIRouter, HTTPException, Query
from app.models import FirewallDeviceModel, FirewallDeviceCreate
from app.database import get_all_firewall_devices, add_firewall_device, delete_firewall_device, get_firewall_device_by_id
from typing import List
from netmiko import ConnectHandler

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

@router.get("/api/firewall_connections")
async def api_get_connections(device_id: int = Query(...)):
    device = await get_firewall_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
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