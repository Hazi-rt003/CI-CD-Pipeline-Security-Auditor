
from fastapi import FastAPI

app = FastAPI(
    title="CI/CD Pipeline Security Auditor",
    description="An automated tool for identifying security weaknesses in CI/CD pipelines.",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "Welcome to the CI/CD Pipeline Security Auditor",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "CI/CD Security Auditor"
    }
