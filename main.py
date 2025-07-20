from fastapi import FastAPI
from fastapi import Response
import db_config
from app.database import startup_event, router as database_router
from app.middleware import setup_middleware
from app.routes import setup_routes
from app.metrics import start_metrics_collection
from app.connections_api import router as connections_router
from app.network_monitor import router as network_monitor_router
from app.firewall_devices_api import router as firewall_devices_router

# Создаём приложение
app = FastAPI()

# Настраиваем middleware
setup_middleware(app)

# Настраиваем маршруты
setup_routes(app)

# Подключаем router для connections
app.include_router(connections_router)
app.include_router(network_monitor_router)
app.include_router(firewall_devices_router)
app.include_router(database_router)

# Заглушка для favicon.ico, чтобы не было 404
@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon")

# Заглушка для /static/favicon.png, чтобы не было 404 иконки.
@app.get("/static/favicon.png")
async def favicon_png():
    # Пустой PNG-файл (1x1 прозрачный пиксель)
    empty_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xdac\xf8\x0f"
        b"\x00\x01\x01\x01\x00\x18\xdd\x8d\x18\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return Response(content=empty_png, media_type="image/png")

# Инициализируем базу данных при запуске
@app.on_event("startup")
async def startup():
    await startup_event()
    # Запускаем сбор метрик в фоновом режиме
    import asyncio
    asyncio.create_task(start_metrics_collection())

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )
