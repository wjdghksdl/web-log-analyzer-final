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

탐지된 이벤트를 IP별로 묶어 어떤 유형의 공격이 몇 건 발생했는지 정리합니다. 또한 공격 유형을 정찰(Reconnaissance), 공격 시도(Exploitation), 인증 공격(Credential Attack), 가용성 공격(Availability Attack) 단계로 분류하고, 같은 IP에서 서로 다른 단계의 탐지가 2개 이상 나오면 하나의 공격 흐름(attack chain)으로 판단합니다.

| 공격 유형 | 단계 |
| --- | --- |
| Web Scanner | Reconnaissance |
| SQL Injection, Path Traversal | Exploitation |
| Brute Force | Credential Attack |
| HTTP Flood | Availability Attack |

### 3. IP별 위험도 산정

IP마다 탐지 이벤트를 종합해 위험 점수(`risk_score`)와 위험 등급(`risk_level`)을 계산합니다.

### 4. REST API

분석 결과를 FastAPI로 제공하며, Swagger UI(`/docs`)에서 바로 호출해 볼 수 있습니다.

---

## 처리 흐름

access.log를 파싱한 뒤 공격 탐지, 상관 분석, IP별 위험도 산정을 차례로 수행하고, 결과를 `data/alerts.json`에 저장해 FastAPI로 제공합니다.

### 시스템 구성

<img width="1727" height="869" alt="image" src="https://github.com/user-attachments/assets/2ce33b8e-c81b-4ea4-b113-b1d754896dbe" />

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
| `risk_results` | IP별 위험 점수, 위험 등급, 탐지 이벤트 수, 공격 유형 |
| `correlation_results` | IP별 탐지 이벤트 수와 공격 유형 |
| `attack_chains` | 공격 흐름이 탐지된 IP, 공격 유형, 해당 단계 |

---

## 실행 화면

### API 문서 (Swagger UI)

<img width="1548" height="660" alt="image" src="https://github.com/user-attachments/assets/27df1f75-7431-4284-8d97-6021497d79d4" />

### 탐지된 이벤트 (`/api/alerts`)

<img width="1400" height="600" alt="image" src="https://github.com/user-attachments/assets/f95f29c9-c69b-4da7-91f3-7b337ad6db7f" />

### IP별 위험도 (`/api/risk`)

<img width="1398" height="595" alt="image" src="https://github.com/user-attachments/assets/408ff36e-1c42-4a44-b7f3-f17e618bc870" />

### 공격 흐름 (`/api/chains`)

<img width="1406" height="417" alt="image" src="https://github.com/user-attachments/assets/38e30887-402c-4028-8a45-4ae037e9fae9" />


### 터미널 실행 결과

<img width="510" height="357" alt="image" src="https://github.com/user-attachments/assets/24d14e32-2a87-4115-9467-9a44ddb0dab6" />

---

## 샘플 데이터

`data/access.log`에는 동작 확인용 요청이 들어 있습니다. 관리자 페이지와 설정 파일 경로를 연달아 요청하는 스캐너성 접근, SQL Injection 문자열이 담긴 검색 요청, `../`로 시스템 파일에 접근하려는 요청, 로그인 실패(401)가 반복되는 요청을 포함합니다. 한 IP가 스캐너성 요청 뒤에 SQL Injection과 경로 조작을 시도하는 요청도 있으며, 이 IP는 공격 흐름으로 탐지됩니다.

---

## 향후 계획

- 분석 결과를 보여 주는 웹 대시보드와 차트 시각화
- 시간대별 요청량, 상태 코드 분포 등 통계 추가
- 분석 결과 DB 저장
