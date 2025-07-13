from fastapi import APIRouter, HTTPException
from netmiko import ConnectHandler

router = APIRouter()

@router.post('/api/device_bandwidth')
async def device_bandwidth(ip: str, username: str, password: str, device_type: str = 'cisco_ios'):
    device = {
        'device_type': device_type,
        'host': ip,
        'username': username,
        'password': password,
    }
    try:
        with ConnectHandler(**device) as ssh:
            output = ssh.send_command('show interfaces summary')
        # output приводим к строке
        output_str = str(output)
        interfaces = []
        for line in output_str.splitlines():
            if 'GigabitEthernet' in line or 'FastEthernet' in line:
                parts = line.split()
                if len(parts) > 5:
                    interfaces.append({
                        'name': parts[0],
                        'in_traffic': parts[4],
                        'out_traffic': parts[5],
                    })
        return {'interfaces': interfaces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 