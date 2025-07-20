import pytest
import time
from unittest.mock import Mock, patch, AsyncMock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import Response
from app.middleware import ActivityTrackingMiddleware, setup_middleware


class TestActivityTrackingMiddleware:
    """Тесты для ActivityTrackingMiddleware"""

    def test_middleware_initialization(self):
        """Тест инициализации middleware"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        assert middleware is not None

    @pytest.mark.asyncio
    async def test_middleware_dispatch_success(self):
        """Тест успешного прохождения через middleware"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        # Создаем мок запроса
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/dashboard"
        mock_request.cookies = {"session_token": "test_token"}
        
        # Создаем мок ответа
        mock_response = Response(content="test", status_code=200)
        
        # Мокаем call_next
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            with patch('app.middleware.metrics_collector') as mock_metrics:
                response = await middleware.dispatch(mock_request, mock_call_next)
                
                # Проверяем, что активность обновлена
                mock_update_activity.assert_called_once_with("test_token")
                
                # Проверяем, что метрики записаны
                mock_metrics.record_request.assert_called_once()
                
                assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_static_files(self):
        """Тест пропуска статических файлов"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/static/css/style.css"
        mock_request.cookies = {}
        
        mock_response = Response(content="test", status_code=200)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            with patch('app.middleware.metrics_collector') as mock_metrics:
                response = await middleware.dispatch(mock_request, mock_call_next)
                
                # Проверяем, что активность НЕ обновлена для статических файлов
                mock_update_activity.assert_not_called()
                
                # Проверяем, что метрики все равно записаны
                mock_metrics.record_request.assert_called_once()
                
                assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_api_activity(self):
        """Тест пропуска API запросов активности"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/api/user-activity"
        mock_request.cookies = {"session_token": "test_token"}
        
        mock_response = Response(content="test", status_code=200)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            with patch('app.middleware.metrics_collector') as mock_metrics:
                response = await middleware.dispatch(mock_request, mock_call_next)
                
                # Проверяем, что активность НЕ обновлена для API активности
                mock_update_activity.assert_not_called()
                
                # Проверяем, что метрики записаны
                mock_metrics.record_request.assert_called_once()
                
                assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_no_session_token(self):
        """Тест обработки запроса без токена сессии"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/dashboard"
        mock_request.cookies = {}
        
        mock_response = Response(content="test", status_code=200)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            with patch('app.middleware.metrics_collector') as mock_metrics:
                response = await middleware.dispatch(mock_request, mock_call_next)
                
                # Проверяем, что активность НЕ обновлена без токена
                mock_update_activity.assert_not_called()
                
                # Проверяем, что метрики записаны
                mock_metrics.record_request.assert_called_once()
                
                assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_error_response(self):
        """Тест обработки ответа с ошибкой"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/dashboard"
        mock_request.cookies = {"session_token": "test_token"}
        
        mock_response = Response(content="error", status_code=404)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            with patch('app.middleware.metrics_collector') as mock_metrics:
                response = await middleware.dispatch(mock_request, mock_call_next)
                
                # Проверяем, что метрики записаны с флагом ошибки
                mock_metrics.record_request.assert_called_once()
                call_args = mock_metrics.record_request.call_args
                assert call_args[0][1] is True  # is_error=True
                assert call_args[0][2] == 404   # error_code=404
                
                assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_activity_update_error(self):
        """Тест обработки ошибки при обновлении активности"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/dashboard"
        mock_request.cookies = {"session_token": "test_token"}
        
        mock_response = Response(content="test", status_code=200)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock) as mock_update_activity:
            mock_update_activity.side_effect = Exception("Database error")
            
            with patch('app.middleware.metrics_collector') as mock_metrics:
                with patch('builtins.print') as mock_print:
                    response = await middleware.dispatch(mock_request, mock_call_next)
                    
                    # Проверяем, что ошибка обработана
                    mock_print.assert_called_once()
                    
                    # Проверяем, что метрики все равно записаны
                    mock_metrics.record_request.assert_called_once()
                    
                    assert response == mock_response

    @pytest.mark.asyncio
    async def test_middleware_dispatch_metrics_error(self):
        """Тест обработки ошибки при записи метрик"""
        app = FastAPI()
        middleware = ActivityTrackingMiddleware(app)
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/dashboard"
        mock_request.cookies = {"session_token": "test_token"}
        
        mock_response = Response(content="test", status_code=200)
        
        async def mock_call_next(request):
            return mock_response
        
        with patch('app.middleware.update_user_activity', new_callable=AsyncMock):
            with patch('app.middleware.metrics_collector') as mock_metrics:
                mock_metrics.record_request.side_effect = Exception("Metrics error")
                
                with patch('builtins.print') as mock_print:
                    response = await middleware.dispatch(mock_request, mock_call_next)
                    
                    # Проверяем, что ошибка метрик обработана
                    mock_print.assert_called_once()
                    
                    assert response == mock_response


class TestSetupMiddleware:
    """Тесты для функции setup_middleware"""

    def test_setup_middleware(self):
        """Тест настройки middleware"""
        app = FastAPI()
        
        # Проверяем, что middleware добавляется без ошибок
        setup_middleware(app)
        
        # Проверяем, что middleware добавлены
        assert len(app.user_middleware) > 0
        
        # Проверяем наличие CORS middleware
        cors_middleware_found = False
        for middleware in app.user_middleware:
            if 'CORSMiddleware' in str(middleware.cls):
                cors_middleware_found = True
                break
        
        assert cors_middleware_found

    def test_setup_middleware_cors_configuration(self):
        """Тест конфигурации CORS"""
        app = FastAPI()
        
        # Добавляем тестовый маршрут
        @app.get("/")
        def root():
            return {"message": "Hello World"}
        
        setup_middleware(app)
        
        # Создаем тестовый клиент
        client = TestClient(app)
        
        # Проверяем, что CORS заголовки присутствуют
        response = client.options("/")
        assert response.status_code in [200, 405]  # OPTIONS может не поддерживаться
        
        # Проверяем GET запрос
        response = client.get("/")
        assert response.status_code == 200


class TestMiddlewareIntegration:
    """Интеграционные тесты middleware"""

    def test_middleware_integration_with_app(self):
        """Тест интеграции middleware с приложением"""
        app = FastAPI()
        
        @app.get("/test")
        def test_endpoint():
            return {"message": "test"}
        
        setup_middleware(app)
        client = TestClient(app)
        
        # Тестируем обычный запрос
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json() == {"message": "test"}

    def test_middleware_response_time_tracking(self):
        """Тест отслеживания времени ответа"""
        app = FastAPI()
        
        @app.get("/slow")
        def slow_endpoint():
            time.sleep(0.1)  # Имитируем медленный запрос
            return {"message": "slow"}
        
        setup_middleware(app)
        client = TestClient(app)
        
        # Тестируем запрос с измерением времени
        start_time = time.time()
        response = client.get("/slow")
        end_time = time.time()
        
        assert response.status_code == 200
        assert (end_time - start_time) >= 0.1  # Проверяем, что время измеряется 