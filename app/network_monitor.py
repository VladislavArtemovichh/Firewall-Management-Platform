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
            if 'cisco' in device_type:
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
            elif 'mikrotik' in device_type:
                # Mikrotik RouterOS команды для получения трафика
                output = ssh.send_command('/interface print stats')
                output_str = str(output)
                interfaces = []
                
                for line in output_str.splitlines():
                    if not line.strip() or line.startswith('Flags:') or line.startswith('Columns:'):
                        continue
                    
                    # Парсим вывод Mikrotik
                    # Пример: 0 ether1 rx-byte=1234567 tx-byte=9876543 rx-packet=1234 tx-packet=5678
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            interface_name = parts[1]
                            in_traffic = '0'
                            out_traffic = '0'
                            
                            # Ищем rx-byte и tx-byte
                            for part in parts:
                                if part.startswith('rx-byte='):
                                    in_traffic = part.split('=')[1]
                                elif part.startswith('tx-byte='):
                                    out_traffic = part.split('=')[1]
                            
                            interfaces.append({
                                'name': interface_name,
                                'in_traffic': in_traffic,
                                'out_traffic': out_traffic,
                            })
                        except Exception as parse_error:
                            continue
                
                return {'interfaces': interfaces}
            else:
                # Fallback для других типов устройств
                output = ssh.send_command('show interfaces summary')
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