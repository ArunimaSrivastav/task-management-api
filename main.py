from fastapi import FastAPI

app = FastAPI(title="Task Management API")

@app.get("/")
async def root():
    return {"message": "Welcome to the Task Management API"}
