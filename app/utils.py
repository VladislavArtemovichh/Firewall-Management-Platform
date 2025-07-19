import re

def parse_ifconfig_output(output: str):
    """
    Парсит вывод ifconfig для одного интерфейса и возвращает словарь с параметрами:
    interface, mac, ipv4, mask, broadcast, ipv6, status, mtu, rx_bytes, tx_bytes
    """
    result = {}
    if output is None:
        return result
    
    lines = output.splitlines()
    if not lines:
        return result

    # Имя интерфейса и MAC-адрес
    m = re.match(r'^(\S+)\s+Link encap:\S+\s+HWaddr\s+([0-9A-Fa-f:]+)', lines[0])
    if m:
        result['interface'] = m.group(1)
        result['mac'] = m.group(2)

    # Определяем статус только по строкам этого блока
    has_up = False
    has_running = False
    for line in lines:
        if 'UP' in line:
            has_up = True
        if 'RUNNING' in line:
            has_running = True

    for line in lines[1:]:
        line = line.strip()
        if 'inet addr:' in line:
            m = re.search(r'inet addr:([\d\.]+)', line)
            if m:
                result['ipv4'] = m.group(1)
            m = re.search(r'Mask:([\d\.]+)', line)
            if m:
                result['mask'] = m.group(1)
            m = re.search(r'Bcast:([\d\.]+)', line)
            if m:
                result['broadcast'] = m.group(1)
        if 'inet6 addr:' in line:
            m = re.search(r'inet6 addr:\s*([a-fA-F0-9:]+)/\d+', line)
            if m:
                result['ipv6'] = m.group(1)
        if 'MTU:' in line:
            m = re.search(r'MTU:(\d+)', line)
            if m:
                result['mtu'] = int(m.group(1))
        if 'RX bytes:' in line and 'TX bytes:' in line:
            m = re.search(r'RX bytes:(\d+)', line)
            if m:
                result['rx_bytes'] = int(m.group(1))
            m = re.search(r'TX bytes:(\d+)', line)
            if m:
                result['tx_bytes'] = int(m.group(1))

    if has_up:
        result['status'] = 'UP (RUNNING)' if has_running else 'UP'
    else:
        result['status'] = 'DOWN'

    return result
