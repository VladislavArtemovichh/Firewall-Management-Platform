import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from app.database import (
    convert_row_for_json,
    create_users_table,
    create_user_sessions_table,
    create_firewall_devices_table,
    get_all_firewall_devices,
    add_firewall_device,
    delete_firewall_device,
    get_firewall_device_by_id,
    create_user_session,
    update_user_activity,
    logout_user_session,
    get_online_users,
    get_user_sessions,
    cleanup_old_sessions,
    mark_inactive_users_as_offline,
    get_user_id_by_username,
    cleanup_user_sessions,
    create_firewall_rules_table,
    get_all_firewall_rules,
    add_firewall_rule,
    update_firewall_rule,
    delete_firewall_rule,
    toggle_firewall_rule,
    add_audit_log,
    get_audit_log,
    check_device_online_sync,
    check_device_online,
    update_device_status
)


class TestConvertRowForJson:
    """Тесты для функции convert_row_for_json"""

    def test_convert_row_for_json_datetime_fields(self):
        """Тест преобразования datetime полей"""
        test_datetime = datetime(2023, 1, 1, 12, 0, 0)
        row_dict = {
            'id': 1,
            'username': 'test',
            'login_time': test_datetime,
            'logout_time': test_datetime,
            'last_activity': test_datetime,
            'created_at': test_datetime
        }
        
        result = convert_row_for_json(row_dict)
        
        # Проверяем, что datetime поля преобразованы в строки
        assert isinstance(result['login_time'], str)
        assert isinstance(result['logout_time'], str)
        assert isinstance(result['last_activity'], str)
        assert isinstance(result['created_at'], str)
        
        # Проверяем, что другие поля не изменились
        assert result['id'] == 1
        assert result['username'] == 'test'

    def test_convert_row_for_json_ip_address(self):
        """Тест преобразования IP адреса"""
        row_dict = {
            'id': 1,
            'ip_address': '192.168.1.1'
        }
        
        result = convert_row_for_json(row_dict)
        
        # Проверяем, что IP адрес преобразован в строку
        assert isinstance(result['ip_address'], str)
        assert result['ip_address'] == '192.168.1.1'

    def test_convert_row_for_json_none_values(self):
        """Тест обработки None значений"""
        row_dict = {
            'id': 1,
            'login_time': None,
            'ip_address': None
        }
        
        result = convert_row_for_json(row_dict)
        
        # Проверяем, что None значения остались None
        assert result['login_time'] is None
        assert result['ip_address'] is None

    def test_convert_row_for_json_no_datetime_fields(self):
        """Тест обработки строки без datetime полей"""
        row_dict = {
            'id': 1,
            'username': 'test',
            'email': 'test@example.com'
        }
        
        result = convert_row_for_json(row_dict)
        
        # Проверяем, что данные не изменились
        assert result == row_dict


class TestDatabaseTables:
    """Тесты для создания таблиц"""

    @pytest.mark.asyncio
    async def test_create_users_table(self):
        """Тест создания таблицы пользователей"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await create_users_table()
            
            # Проверяем, что соединение создано и закрыто
            mock_connect.assert_called_once()
            mock_conn.execute.assert_called_once()
            mock_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_sessions_table(self):
        """Тест создания таблицы сессий пользователей"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await create_user_sessions_table()
            
            # Проверяем, что соединение создано и закрыто
            mock_connect.assert_called_once()
            # Проверяем, что выполнено несколько SQL команд
            assert mock_conn.execute.call_count >= 4
            mock_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_firewall_devices_table(self):
        """Тест создания таблицы устройств брандмауэра"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await create_firewall_devices_table()
            
            # Проверяем, что соединение создано и закрыто
            mock_connect.assert_called_once()
            mock_conn.execute.assert_called_once()
            mock_conn.close.assert_called_once()


class TestFirewallDevices:
    """Тесты для работы с устройствами брандмауэра"""

    @pytest.mark.asyncio
    async def test_get_all_firewall_devices(self):
        """Тест получения всех устройств брандмауэра"""
        mock_devices = [
            {'id': 1, 'name': 'Router1', 'ip': '192.168.1.1', 'type': 'cisco'},
            {'id': 2, 'name': 'Router2', 'ip': '192.168.1.2', 'type': 'mikrotik'}
        ]
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = mock_devices
            mock_connect.return_value = mock_conn
            
            result = await get_all_firewall_devices()
            
            # Проверяем, что данные получены
            assert len(result) == len(mock_devices)
            assert result[0]['id'] == mock_devices[0]['id']
            assert result[0]['name'] == mock_devices[0]['name']
            assert result[0]['ip'] == mock_devices[0]['ip']
            assert result[0]['type'] == mock_devices[0]['type']
            assert 'status' in result[0]
            assert 'last_poll' in result[0]
            mock_conn.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_firewall_device(self):
        """Тест добавления устройства брандмауэра"""
        # Создаем объект с атрибутами вместо словаря
        class MockDevice:
            def __init__(self):
                self.name = 'TestRouter'
                self.ip = '192.168.1.100'
                self.type = 'cisco'
                self.username = 'admin'
                self.password = 'password'
        
        device = MockDevice()
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await add_firewall_device(device)
            
            # Проверяем, что команда INSERT выполнена
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_firewall_device(self):
        """Тест удаления устройства брандмауэра"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await delete_firewall_device(1)
            
            # Проверяем, что команда удаления выполнена
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_firewall_device_by_id(self):
        """Тест получения устройства по ID"""
        mock_device = {
            'id': 1,
            'name': 'TestRouter',
            'ip': '192.168.1.100',
            'type': 'cisco'
        }
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchrow.return_value = mock_device
            mock_connect.return_value = mock_conn
            
            result = await get_firewall_device_by_id(1)
            
            # Проверяем, что устройство найдено
            assert result == mock_device
            mock_conn.fetchrow.assert_called_once()


class TestUserSessions:
    """Тесты для работы с сессиями пользователей"""

    @pytest.mark.asyncio
    async def test_create_user_session(self):
        """Тест создания сессии пользователя"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await create_user_session(
                user_id=1,
                session_token="test_token",
                ip_address="192.168.1.1",
                user_agent="test_agent"
            )
            
            # Проверяем, что сессия создана
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_activity(self):
        """Тест обновления активности пользователя"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await update_user_activity("test_token")
            
            # Проверяем, что активность обновлена
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_logout_user_session(self):
        """Тест выхода из сессии"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await logout_user_session("test_token")
            
            # Проверяем, что сессия закрыта
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_online_users(self):
        """Тест получения онлайн пользователей"""
        mock_users = [
            {'id': 1, 'username': 'user1', 'last_activity': datetime.now()},
            {'id': 2, 'username': 'user2', 'last_activity': datetime.now()}
        ]
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = mock_users
            mock_connect.return_value = mock_conn
            
            result = await get_online_users()
            
            # Проверяем, что пользователи получены
            assert len(result) == len(mock_users)
            assert result[0]['id'] == mock_users[0]['id']
            assert result[0]['username'] == mock_users[0]['username']
            mock_conn.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_sessions(self):
        """Тест получения сессий пользователя"""
        mock_sessions = [
            {'id': 1, 'session_token': 'token1', 'login_time': datetime.now()},
            {'id': 2, 'session_token': 'token2', 'login_time': datetime.now()}
        ]
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = mock_sessions
            mock_connect.return_value = mock_conn
            
            result = await get_user_sessions(1)
            
            # Проверяем, что сессии получены
            assert len(result) == len(mock_sessions)
            assert result[0]['id'] == mock_sessions[0]['id']
            assert result[0]['session_token'] == mock_sessions[0]['session_token']
            mock_conn.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_old_sessions(self):
        """Тест очистки старых сессий"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await cleanup_old_sessions(24)
            
            # Проверяем, что очистка выполнена
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_inactive_users_as_offline(self):
        """Тест пометки неактивных пользователей как офлайн"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await mark_inactive_users_as_offline(30)
            
            # Проверяем, что пользователи помечены как офлайн
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_id_by_username(self):
        """Тест получения ID пользователя по имени"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchval.return_value = 1
            mock_connect.return_value = mock_conn
            
            result = await get_user_id_by_username("test_user")
            
            # Проверяем, что ID получен
            assert result == 1
            mock_conn.fetchval.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_user_sessions(self):
        """Тест очистки сессий пользователя"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await cleanup_user_sessions(1)
            
            # Проверяем, что сессии очищены
            assert mock_conn.execute.call_count >= 1


class TestFirewallRules:
    """Тесты для работы с правилами брандмауэра"""

    @pytest.mark.asyncio
    async def test_create_firewall_rules_table(self):
        """Тест создания таблицы правил брандмауэра"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await create_firewall_rules_table()
            
            # Проверяем, что таблица создана
            assert mock_conn.execute.call_count >= 1

    @pytest.mark.asyncio
    async def test_get_all_firewall_rules(self):
        """Тест получения всех правил брандмауэра"""
        mock_rules = [
            {'id': 1, 'name': 'Rule1', 'protocol': 'tcp', 'port': '80'},
            {'id': 2, 'name': 'Rule2', 'protocol': 'udp', 'port': '53'}
        ]
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = mock_rules
            mock_connect.return_value = mock_conn
            
            result = await get_all_firewall_rules()
            
            # Проверяем, что правила получены
            assert result == mock_rules
            mock_conn.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_firewall_rule(self):
        """Тест добавления правила брандмауэра"""
        rule = {
            'name': 'TestRule',
            'protocol': 'tcp',
            'port': '443',
            'direction': 'inbound',
            'action': 'allow',
            'enabled': True,
            'comment': 'Test rule'
        }
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchrow.return_value = {'id': 1, **rule}
            mock_connect.return_value = mock_conn
            
            result = await add_firewall_rule(rule)
            
            # Проверяем, что правило добавлено
            assert result['id'] == 1
            assert result['name'] == 'TestRule'
            mock_conn.fetchrow.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_firewall_rule(self):
        """Тест обновления правила брандмауэра"""
        rule = {
            'name': 'UpdatedRule',
            'protocol': 'tcp',
            'port': '443',
            'direction': 'inbound',
            'action': 'deny',
            'enabled': False,
            'comment': 'Updated rule'
        }
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchrow.return_value = {'id': 1, **rule}
            mock_connect.return_value = mock_conn
            
            result = await update_firewall_rule(1, rule)
            
            # Проверяем, что правило обновлено
            assert result['id'] == 1
            assert result['name'] == 'UpdatedRule'
            mock_conn.fetchrow.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_firewall_rule(self):
        """Тест удаления правила брандмауэра"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await delete_firewall_rule(1)
            
            # Проверяем, что правило удалено
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_toggle_firewall_rule(self):
        """Тест переключения состояния правила"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchrow.return_value = {
                'id': 1,
                'name': 'TestRule',
                'enabled': False
            }
            mock_connect.return_value = mock_conn
            
            result = await toggle_firewall_rule(1)
            
            # Проверяем, что состояние переключено
            assert result['id'] == 1
            assert result['enabled'] is False
            mock_conn.fetchrow.assert_called_once()


class TestAuditLog:
    """Тесты для работы с журналом аудита"""

    @pytest.mark.asyncio
    async def test_add_audit_log(self):
        """Тест добавления записи в журнал аудита"""
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value = mock_conn
            
            await add_audit_log(
                username="test_user",
                user_role="admin",
                action="test_action",
                details="test_details"
            )
            
            # Проверяем, что запись добавлена
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_audit_log(self):
        """Тест получения журнала аудита"""
        mock_logs = [
            {'id': 1, 'username': 'user1', 'action': 'login', 'timestamp': datetime.now()},
            {'id': 2, 'username': 'user2', 'action': 'logout', 'timestamp': datetime.now()}
        ]
        
        with patch('app.database.asyncpg.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = mock_logs
            mock_connect.return_value = mock_conn
            
            result = await get_audit_log()
            
            # Проверяем, что записи получены
            assert result == mock_logs
            mock_conn.fetch.assert_called_once()


class TestDeviceOnlineCheck:
    """Тесты для проверки онлайн статуса устройств"""

    def test_check_device_online_sync_success(self):
        """Тест успешной синхронной проверки онлайн статуса"""
        with patch('subprocess.run') as mock_subprocess:
            # Мокаем успешный ping
            mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
            
            result = check_device_online_sync("192.168.1.1", 22)
            
            # Проверяем, что устройство онлайн
            assert result is True
            mock_subprocess.assert_called_once()

    def test_check_device_online_sync_failure(self):
        """Тест неудачной синхронной проверки онлайн статуса"""
        with patch('subprocess.run') as mock_subprocess:
            # Мокаем неудачный ping
            mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="")
            
            with patch('socket.create_connection') as mock_socket:
                # Мокаем неудачное TCP соединение
                mock_socket.side_effect = Exception("Connection failed")
                
                result = check_device_online_sync("192.168.1.1", 22)
                
                # Проверяем, что устройство офлайн
                assert result is False

    def test_check_device_online_sync_tcp_success(self):
        """Тест успешной TCP проверки при неудачном ping"""
        with patch('subprocess.run') as mock_subprocess:
            # Мокаем неудачный ping
            mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="")
            
            with patch('socket.create_connection') as mock_socket:
                # Мокаем успешное TCP соединение с поддержкой контекстного менеджера
                mock_connection = Mock()
                mock_connection.__enter__ = Mock(return_value=mock_connection)
                mock_connection.__exit__ = Mock(return_value=None)
                mock_socket.return_value = mock_connection
                
                result = check_device_online_sync("192.168.1.1", 22)
                
                # Проверяем, что устройство онлайн через TCP
                assert result is True
                mock_socket.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_device_online(self):
        """Тест асинхронной проверки онлайн статуса"""
        with patch('app.database.check_device_online_sync') as mock_check:
            mock_check.return_value = True
            
            result = await check_device_online("192.168.1.1", 22)
            
            # Проверяем, что результат получен
            assert result is True
            mock_check.assert_called_once_with("192.168.1.1", 22)

    def test_check_device_online_sync_empty_ip(self):
        """Тест проверки с пустым IP"""
        result = check_device_online_sync("", 22)
        assert result is False
        
        result = check_device_online_sync(None, 22)
        assert result is False

    @pytest.mark.asyncio
    async def test_update_device_status(self):
        """Тест обновления статуса устройства"""
        device = {
            'id': 1,
            'name': 'TestDevice',
            'ip': '192.168.1.1'
        }
        
        with patch('app.database.check_device_online') as mock_check:
            with patch('app.database.asyncpg.connect') as mock_connect:
                mock_check.return_value = True
                mock_conn = AsyncMock()
                mock_connect.return_value = mock_conn
                
                await update_device_status(device)
                
                # Проверяем, что команда обновления выполнена
                mock_conn.execute.assert_called_once() 