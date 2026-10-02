from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "message": "Learning School Full-Stack Backend is running!"
    }