# Web Security Log Analyzer

웹 서버 access log를 읽어 SQL Injection, Path Traversal, 웹 스캐너, Brute Force, HTTP Flood로 의심되는 요청을 탐지하고, IP별 위험도와 공격 흐름을 계산해 FastAPI로 제공하는 웹 로그 분석 프로젝트입니다.

---

## 프로젝트 소개

웹 서비스를 운영하면 정상 요청 사이에 관리자 페이지 탐색, 설정 파일 접근 시도, 로그인 반복 실패, 공격 문자열이 담긴 요청이 섞여 들어옵니다. 로그 파일을 사람이 직접 읽어서는 이런 요청을 빠르게 찾기 어렵습니다.

이 프로젝트는 access log를 파싱한 뒤 공격 유형별 탐지기로 의심 요청을 찾고, 탐지된 이벤트를 IP 기준으로 묶어 위험도와 공격 흐름을 산출합니다. 분석 결과는 JSON 파일과 REST API로 확인할 수 있습니다.

---

## 주요 기능

### 1. 공격 탐지

로그 한 줄 단위로 검사하는 탐지기 3종과, 여러 줄을 묶어 판단하는 탐지기 2종으로 구성했습니다.

| 탐지 유형 | 방식 | 설명 |
| --- | --- | --- |
| SQL Injection | 요청 단위 | 요청 URL에 포함된 SQL 구문 패턴 탐지 |
| Path Traversal | 요청 단위 | `../` 등 상위 경로 접근 시도 탐지 |
| Web Scanner | 요청 단위 | 관리자 페이지, 설정 파일 등을 훑는 스캐너성 요청 탐지 |
| Brute Force | 로그 전체 | 동일 IP의 반복적인 로그인 실패 탐지 |
| HTTP Flood | 로그 전체 | 동일 IP의 단시간 대량 요청 탐지 |

### 2. 상관 분석과 공격 흐름 탐지

탐지된 이벤트를 공격 유형별로 묶어 분석하고, 같은 IP에서 여러 유형의 공격이 이어진 경우 하나의 공격 흐름(attack chain)으로 탐지합니다.

### 3. IP별 위험도 산정

IP마다 탐지 이벤트를 종합해 위험 점수(`risk_score`)와 위험 등급(`risk_level`)을 계산합니다.

### 4. REST API

분석 결과를 FastAPI로 제공하며, Swagger UI(`/docs`)에서 바로 호출해 볼 수 있습니다.

---

## 처리 흐름

```
access.log
    ↓
로그 파싱 (parser)
    ↓
공격 탐지 (detection)
    SQL Injection / Path Traversal / Web Scanner / Brute Force / HTTP Flood
    ↓
상관 분석 · 공격 흐름 탐지 (correlation)
    ↓
IP별 위험도 산정 (risk)
    ↓
data/alerts.json 저장
    ↓
FastAPI (api)
```

### 시스템 구성

![시스템 구성도](docs/images/architecture.png)

---

## 프로젝트 구조

```
web-log-analyzer-final/
├── main.py            # 분석 실행, 결과를 data/alerts.json으로 저장
├── api/
│   └── app.py         # FastAPI 서버
├── parser/            # access log 파싱
├── detection/         # 공격 탐지기
├── correlation/       # 상관 분석, 공격 흐름 탐지
├── risk/              # IP별 위험도 산정
├── data/              # access.log, alerts.json
└── requirements.txt
```

---

## 사용 기술

- Python
- FastAPI, Uvicorn

---

## 실행 방법

```bash
pip install -r requirements.txt

# 1. 로그 분석 실행 (data/access.log -> data/alerts.json)
py main.py

# 2. API 서버 실행
py -m uvicorn api.app:app --reload
```

서버 실행 후 `http://127.0.0.1:8000/docs`에서 API 문서를 확인할 수 있습니다.

---

## API

| Method | Endpoint | 설명 |
| --- | --- | --- |
| GET | `/` | 서비스 상태 |
| GET | `/health` | 헬스 체크 |
| GET | `/api/analyze` | `data/access.log`를 즉시 분석해 전체 결과 반환 |
| GET | `/api/alerts` | 탐지된 이벤트 목록 |
| GET | `/api/risk` | IP별 위험도 |
| GET | `/api/chains` | 탐지된 공격 흐름 |

`/api/alerts`, `/api/risk`, `/api/chains`는 `py main.py`로 생성한 `data/alerts.json`을 읽습니다. 먼저 `py main.py`를 실행해야 합니다.

### 분석 결과 형식

`py main.py`와 `/api/analyze`는 아래 구조의 결과를 반환합니다.

| 항목 | 내용 |
| --- | --- |
| `summary` | 분석 로그 수, 탐지 이벤트 수, 탐지 IP 수, 공격 흐름 수 |
| `alerts` | 탐지된 이벤트 목록 |
| `risk_results` | IP별 위험 점수, 위험 등급, 탐지 이벤트 수 |
| `correlation_results` | 공격 유형별 상관 분석 결과 |
| `attack_chains` | 탐지된 공격 흐름 |

---

## 실행 화면

### API 문서 (Swagger UI)

![API 문서](docs/images/swagger-ui.png)

### 탐지된 이벤트 (`/api/alerts`)

![탐지 이벤트](docs/images/api-alerts.png)

### IP별 위험도 (`/api/risk`)

![IP별 위험도](docs/images/api-risk.png)

### 공격 흐름 (`/api/chains`)

![공격 흐름](docs/images/api-chains.png)

### 터미널 실행 결과

![터미널 실행 결과](docs/images/terminal-output.png)

---

## 샘플 데이터

`data/access.log`에는 동작 확인용 요청이 들어 있습니다. 관리자 페이지와 설정 파일 경로를 연달아 요청하는 스캐너성 접근, SQL Injection 문자열이 담긴 검색 요청, `../`로 시스템 파일에 접근하려는 요청, 로그인 실패(401)가 반복되는 요청을 포함합니다.

---

## 향후 계획

- 분석 결과를 보여 주는 웹 대시보드와 차트 시각화
- 시간대별 요청량, 상태 코드 분포 등 통계 추가
- 분석 결과 DB 저장
