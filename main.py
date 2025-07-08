from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Разрешаем CORS для тестирования (можно убрать в продакшене)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = {
    "admin": "admin",
    "user1": "pass1",
    "user2": "pass2"
}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username in users and users[username] == password:
        return {"message": "Успешная авторизация", "user": username}
    raise HTTPException(status_code=401, detail="Неверный логин или пароль")

@app.get("/")
def get_login_page():
    return FileResponse("авторизация2.html", media_type="text/html")


