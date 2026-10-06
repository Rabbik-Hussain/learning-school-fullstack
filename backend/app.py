from fastapi import FastAPI
from backend.auth import router as auth_router

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth")


@app.get("/")
def home():
    return {
        "message": "Learning School Full-Stack Backend is running!"
    }