from fastapi import FastAPI
import db_config
from app.database import create_users_table
from app.middleware import setup_middleware
from app.routes import setup_routes

# Создаём приложение
app = FastAPI()

# Настраиваем middleware
setup_middleware(app)

# Настраиваем маршруты
setup_routes(app)

# Инициализируем базу данных при запуске
@app.get("/")
async def startup():
    await create_users_table()

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )
