from fastapi import FastAPI
from fastapi import Response
import db_config
from app.database import startup_event
from app.middleware import setup_middleware
from app.routes import setup_routes
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

# Заглушка для favicon.ico, чтобы не было 404
@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon")

# Инициализируем базу данных при запуске
@app.on_event("startup")
async def startup():
    await startup_event()

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )
