# eval — 정답 데이터

LLM 취약 함수 추출의 정확도를 재는 기준이다. **사람이 채운다.**
스크립트가 덮어쓰거나 추측으로 채우지 않는다. 손으로 채운 뒤에는 다시 만들 수 없으므로 커밋한다.

## candidates.csv

`python scripts/analyze_osv.py --candidates`가 만든 후보 20건이다.
- 대상: OSV PyPI 덤프 2026-10-08 스냅샷에서 최근 2년 분석 가능 후보(WEB 타입 커밋 포함, `docs/decisions.md` D-003)
- 패키지가 겹치지 않게 뽑았고 시드는 고정
- 파일이 이미 있으면 스크립트가 덮어쓰지 않는다
- 인코딩은 UTF-8(BOM). 엑셀에서 열어 한글을 채워도 깨지지 않는다
- 출처: OSV(PyPA Advisory Database, GitHub Advisory Database), CC-BY 4.0

| 컬럼 | 누가 | 내용 |
|---|---|---|
| `osv_id` ~ `details_summary` | 스크립트 | 공개 취약점 정보. `fix_commit_url`은 `출처 URL; 출처 URL` (출처 = FIX / GIT / WEB) |
| `my_answer_function` | **사람** | 취약 함수 |
| `my_answer_condition` | **사람** | 위험해지는 조건 |
| `note` | **사람** | 판단 근거와 특이사항 |

## 작성 규칙

**`my_answer_function`**
- 사용자가 **호출하는 공개 경로**로, 패키지명부터 쓴다. 예: `sqlparse.format`
- 메서드는 `패키지.클래스.메서드`. 예: `werkzeug.Request.get_data`
- 실제 정의 위치가 다르면 note에 적는다. 예: `정의는 sqlparse.formatter.build_filter_stack`
- 여러 개면 `;`로 구분한다
- 특정할 수 없으면 `불가`라고 쓰고, 이유를 note에 적는다(diff가 설정·문서만 고침, 함수 단위가 아님 등)

**`my_answer_condition`**
- 위험해지는 인자나 조건을 한 줄로 쓴다. 예: `strip_comments=True일 때`
- 조건 없이 호출만으로 위험하면 `항상`

**`note`**
- 무엇을 보고 판단했나: `diff` / `details` / `둘 다`
- `fix_commit_url`이 WEB 출처인데 실제로는 수정 커밋이 아니면 반드시 적는다(D-003의 남은 한계를 재는 자료)

## 채점 방식 (9주차 안)

- 함수: 공백을 정규화한 뒤 집합으로 비교해 건별 정밀도·재현율을 내고 전체를 평균한다
- 정답이 `불가`인데 LLM이 함수를 내면 오답으로 본다. 확신 없는 답보다 `불가`가 낫다는 원칙(위험 누락 방지)과 같다
- 조건: 자동 채점이 어려워 사람이 `맞음 / 부분 / 틀림`으로 매긴다
