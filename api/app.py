from pathlib import Path

from fastapi import FastAPI, HTTPException

from parser.log_parser import parse_log_file
from main import build_result


app = FastAPI(
    title="Web Security Log Analyzer",
    version="1.0.0",
    description="Web access log 기반 보안관제 분석 API",
)

LOG_FILE = Path("data/access.log")
RESULT_FILE = Path("data/alerts.json")


@app.get("/")
def root():
    return {
        "service": "Web Security Log Analyzer",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/analyze")
def analyze():
    if not LOG_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="data/access.log 파일이 없습니다.",
        )

    logs = parse_log_file(str(LOG_FILE))
    return build_result(logs)


@app.get("/api/alerts")
def alerts():
    if not RESULT_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="먼저 py main.py를 실행하세요.",
        )

    import json

    with open(RESULT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data["alerts"]


@app.get("/api/risk")
def risk():
    if not RESULT_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="먼저 py main.py를 실행하세요.",
        )

    import json

    with open(RESULT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data["risk_results"]


@app.get("/api/chains")
def chains():
    if not RESULT_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="먼저 py main.py를 실행하세요.",
        )

    import json

    with open(RESULT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data["attack_chains"]
