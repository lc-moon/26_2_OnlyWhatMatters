# OnlyWhatMatters

의존성 취약점의 **실제 영향도**를 판별해 우선순위를 알려주는 보안 분석 서비스.

GitHub 저장소를 연결하면 사용 중인 오픈소스 라이브러리의 알려진 취약점을 추적하고,
내 코드가 그 취약한 함수를 실제로 호출하는지까지 판별해 "지금 당장 고쳐야 하는 것"만 선별해 알려준다.

- 설계 원칙: **판단은 코드, 해석은 LLM.** LLM은 공개 취약점 문서에서 취약 함수를 뽑는 데만 쓰고,
  버전 판정·호출 판정은 코드(`packaging`, `ast`)가 한다
- 사용자 코드는 LLM에 보내지 않고, 실행하지도 않는다
- 판정 등급: 즉시 조치 / 여유 있음 / 판단 불가

2026년 2학기 심화응용프로젝트 개인 프로젝트. 자세한 내용은 [docs/프로젝트.md](docs/프로젝트.md).

## 폴더 구조

```
.
├── CLAUDE.md                작업 규칙 (매 세션 지킬 원칙)
├── README.md
├── .claude/skills/
│   ├── 기록/                /기록 — 하루 작업 기록 + 갱신 문서 점검
│   └── 실습일지/            /실습일지 — 주간 실습일지 원고·docx 작성
├── scripts/
│   └── analyze_osv.py       OSV PyPI 덤프 사전 검증 (수정 커밋·details 통계, 정답 후보 추출)
├── eval/                    정답 데이터 — 사람이 채운다. 작성 규칙은 eval/README.md
│   └── candidates.csv
├── data/raw/                내려받은 OSV 원본 (git 제외, 스크립트가 다시 받는다)
└── docs/
    ├── 프로젝트.md
    ├── 현황.md
    ├── decisions.md
    ├── 기록/                날짜별 작업 기록
    └── 실습일지/            주간 실습일지 원고(.md)와 양식
```

## 실행

Python 3.12 이상, `requests`.

```
python scripts/analyze_osv.py                OSV PyPI 요약 표 (첫 실행 때 덤프 35MB를 data/raw/에 받는다)
python scripts/analyze_osv.py --peek 3       원본 JSON 확인
python scripts/analyze_osv.py --keys         자유 필드 키 분포
python scripts/analyze_osv.py --candidates   eval/candidates.csv 생성(이미 있으면 건너뜀) + diff 실수신 10건
python scripts/analyze_osv.py --web-check    WEB 타입 커밋이 실제 수정 커밋인지 대조
```

## 문서

| 문서 | 성질 | 담는 것 |
|---|---|---|
| [CLAUDE.md](CLAUDE.md) | 규칙 | 매 세션 지킬 원칙. 바뀌는 상태는 넣지 않는다 |
| [docs/프로젝트.md](docs/프로젝트.md) | 갱신 | 배경, 설계, 데이터 구조, 스택, 일정, 평가 방법 — 무엇을 왜 만드나 |
| [docs/현황.md](docs/현황.md) | 갱신 | 현재 주차, 검증된 사실(수치+출처), 미확인 리스크, 남은 작업 |
| [docs/decisions.md](docs/decisions.md) | 누적 | 원래 계획을 바꾼 결정만. 최종 발표 "문제와 해결 과정"의 재료 |
| `docs/기록/YYYY-MM-DD_제목.md` | 누적 | 그날 한 일·실측 수치·판단 근거. 날이 지나면 고치지 않는다 |
| [docs/기록/README.md](docs/기록/README.md) | 갱신 | 기록 목차 + 주차별 흐름 요약 |
| [docs/실습일지/README.md](docs/실습일지/README.md) | 갱신 | 제출 일정표, 작성·제출 현황 |
| `docs/실습일지/NN주차.md` | 누적 | 제출한 실습일지의 원고. 제출 후 고치지 않는다 |

흐름: 매일 기록(`/기록`) → 방향이 바뀐 일은 decisions → 매주 기록·decisions·커밋을 모아 실습일지(`/실습일지`).

`docs/실습일지/*.docx`(양식·제출본)는 학번·이름이 들어가 git에서 제외한다.
