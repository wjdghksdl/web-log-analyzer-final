# Web Security Log Analyzer

Apache/Nginx access log를 분석하여 웹 공격 이벤트를 탐지하고,
IP별 Risk Score와 Attack Chain을 생성하는 간단한 보안관제 프로젝트입니다.

## 구조

web-log-analyzer/
├── main.py
├── requirements.txt
├── api/
│   └── app.py
├── parser/
│   ├── __init__.py
│   └── log_parser.py
├── detection/
│   ├── __init__.py
│   ├── sql_injection.py
│   ├── path_traversal.py
│   ├── scanner.py
│   ├── brute_force.py
│   └── http_flood.py
├── correlation/
│   ├── __init__.py
│   └── correlation_engine.py
├── risk/
│   ├── __init__.py
│   └── risk_engine.py
├── alert/
│   ├── __init__.py
│   └── alert_manager.py
└── data/
    └── access.log

## 실행

의존성 설치:

    py -m pip install -r requirements.txt

전체 로그 분석:

    py main.py

API 서버:

    py -m uvicorn api.app:app --reload

브라우저:

    http://127.0.0.1:8000/docs

결과:

    data/alerts.json
