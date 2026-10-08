"""OSV PyPI 덤프 사전 검증.

LLM이 취약 함수를 뽑으려면 근거 문서(수정 커밋 diff, details 설명문)가 있어야 한다.
PyPI 취약점 중 그런 근거가 실제로 얼마나 붙어 있는지를 공식 덤프로 센다.

    python scripts/analyze_osv.py --peek 3      덤프 내려받기 + JSON 3개 출력 (스키마 확인용)
    python scripts/analyze_osv.py               요약 표 (전체 / 최근 2년)
    python scripts/analyze_osv.py --keys        ecosystem_specific / database_specific 키 분포
    python scripts/analyze_osv.py --candidates  eval/candidates.csv 생성 + diff 실수신 10건 확인
    python scripts/analyze_osv.py --web-check   WEB 타입 커밋이 실제 수정 커밋인지 대조 (D-003 근거)

덤프 형식: https://google.github.io/osv.dev/data/
스키마:    https://ossf.github.io/osv-schema/ (v1.9.1)
"""

import argparse
import csv
import datetime as dt
import json
import random
import re
import sys
import unicodedata
import zipfile
from collections import Counter
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
ZIP_PATH = RAW_DIR / "PyPI_all.zip"
META_PATH = RAW_DIR / "PyPI_all.meta.json"
CANDIDATES_PATH = ROOT / "eval" / "candidates.csv"
DUMP_URL = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"

KST = dt.timezone(dt.timedelta(hours=9))
DETAILS_MIN = 200      # "details 충분"의 기준 (docs/현황.md 판정 기준)
RECENT_DAYS = 730      # 최근 2년
SEED = 20261008        # 후보 추출 시드. 바꾸면 다른 20건이 뽑힌다
N_CANDIDATES = 20
N_DIFF_CHECK = 10      # 비인증 GitHub API 한도(시간당 60회) 안에서

# GitHub 커밋 URL: github.com/{owner}/{repo}/commit/{sha}
GH_COMMIT_RE = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})")
GH_PR_RE = re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/pull/\d+")
GH_REPO_RE = re.compile(r"https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$")
# details 안의 "점으로 이어진 이름 + 여는 괄호" (예: sqlparse.format( ). 대략적인 감을 잡는 용도
CALL_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\(")


# ---------------------------------------------------------------- 내려받기

def download():
    """덤프를 data/raw/에 캐시한다. 이미 있으면 다시 받지 않는다."""
    if ZIP_PATH.exists() and META_PATH.exists():
        return json.loads(META_PATH.read_text(encoding="utf-8"))

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    part = ZIP_PATH.with_suffix(".part")
    with requests.get(DUMP_URL, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        with open(part, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r내려받는 중 {done / 1e6:5.1f} / {total / 1e6:.1f} MB", end="", flush=True)
        print()
        meta = {
            "url": DUMP_URL,
            "downloaded_at": dt.datetime.now(KST).isoformat(timespec="seconds"),
            # OSV는 계속 갱신되므로 객체의 Last-Modified를 스냅샷 시각으로 쓴다
            "last_modified": r.headers.get("Last-Modified"),
            "bytes": done,
        }
    part.replace(ZIP_PATH)
    META_PATH.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def snapshot_time(meta):
    return parsedate_to_datetime(meta["last_modified"]).astimezone(KST)


def iter_records(zf):
    """zip 안의 JSON을 하나씩 읽는다. 전체를 메모리에 펼치지 않는다."""
    names = [n for n in zf.namelist() if n.endswith(".json")]
    for i, name in enumerate(names, 1):
        if i % 1000 == 0 or i == len(names):
            print(f"\r읽는 중 {i:,} / {len(names):,}", end="", file=sys.stderr, flush=True)
        yield json.loads(zf.read(name))
    print(file=sys.stderr)


# ---------------------------------------------------------------- 항목 하나 해석

def parse_time(s):
    if not s:
        return None
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def gh_commit_url(owner, repo, sha):
    return f"https://github.com/{owner}/{repo.removesuffix('.git')}/commit/{sha.lower()}"


def extract(rec):
    """판정에 필요한 값만 뽑는다."""
    fix_refs = [x["url"] for x in rec.get("references", []) if x.get("type") == "FIX"]
    # 실제 데이터에서는 수정 커밋이 WEB 등 다른 타입으로 붙는다(GHSA는 전부 WEB).
    # 측정 전 기준에는 없던 출처라 따로 세고, 근거로 인정하는 것은 D-003 결정에 따른다
    other_gh_commits = [gh_commit_url(*GH_COMMIT_RE.match(x["url"]).groups())
                        for x in rec.get("references", [])
                        if x.get("type") != "FIX" and GH_COMMIT_RE.match(x["url"])]
    fix_gh_commits, fix_gh_pr, fix_other = [], 0, 0
    for url in fix_refs:
        m = GH_COMMIT_RE.match(url)
        if m:
            fix_gh_commits.append(gh_commit_url(*m.groups()))
        elif GH_PR_RE.match(url):
            fix_gh_pr += 1
        else:
            fix_other += 1

    # GIT range의 fixed 이벤트는 커밋 해시다. repo가 GitHub이면 커밋 URL을 만들 수 있다
    git_fixed, git_gh_commits = 0, []
    packages = {}
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") == "PyPI" and pkg.get("name"):
            packages.setdefault(normalize_pkg(pkg["name"]), []).extend(
                r for r in aff.get("ranges", []) if r.get("type") == "ECOSYSTEM")
        for rng in aff.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    git_fixed += 1
                    m = GH_REPO_RE.match(rng.get("repo", ""))
                    if m:
                        git_gh_commits.append(gh_commit_url(m.group(1), m.group(2), ev["fixed"]))

    details = rec.get("details") or ""
    return {
        "id": rec["id"],
        "aliases": rec.get("aliases", []),
        "withdrawn": "withdrawn" in rec,
        "published": parse_time(rec.get("published")),
        "details": details,
        "fix_ref": bool(fix_refs),
        "fix_gh_commits": fix_gh_commits,
        "fix_gh_pr": fix_gh_pr > 0,
        "fix_other": fix_other > 0,
        "git_fixed": git_fixed > 0,
        "git_gh_commits": git_gh_commits,
        "other_gh_commits": other_gh_commits,
        "packages": packages,
    }


def normalize_pkg(name):
    # PyPI 패키지명은 대소문자와 - _ . 를 구분하지 않는다 (PEP 503)
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- 중복 묶기

class UnionFind:
    """같은 취약점의 여러 ID(PYSEC-, GHSA-, CVE-)를 하나로 묶는다.

    스키마상 aliases는 "같은 취약점"이고 대칭·추이적이다. A↔B, B↔C면 A·B·C가 한 취약점이므로
    연결된 ID 덩어리를 찾는 문제가 된다. 덤프에 없는 CVE ID도 다리 역할을 하므로 노드로 넣는다.
    """

    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def load(meta):
    """덤프를 읽어 (항목 통계, 고유 취약점 묶음 목록)을 돌려준다."""
    prefix = Counter()
    withdrawn = mal = 0
    entries = []
    with zipfile.ZipFile(ZIP_PATH) as zf:
        for rec in iter_records(zf):
            prefix[rec["id"].split("-")[0]] += 1
            if "withdrawn" in rec:
                withdrawn += 1      # 철회된 항목은 분석에서 뺀다
            elif rec["id"].startswith("MAL-"):
                mal += 1            # 악성 패키지는 "취약 함수"가 없는 다른 종류의 데이터다
            else:
                entries.append(extract(rec))

    uf = UnionFind()
    for e in entries:
        uf.find(e["id"])
        for a in e["aliases"]:
            uf.union(e["id"], a)
    groups = {}
    for e in entries:
        groups.setdefault(uf.find(e["id"]), []).append(e)

    # 일반 항목이지만 aliases로 MAL과 이어진 묶음도 악성 패키지로 보고 뺀다
    mal_linked = 0
    vulns = []
    for members in groups.values():
        if any(a.startswith("MAL-") for m in members for a in m["aliases"]):
            mal_linked += 1
            continue
        vulns.append(summarize(members))

    stats = {"total": sum(prefix.values()), "prefix": prefix, "withdrawn": withdrawn,
             "mal": mal, "mal_linked": mal_linked, "entries": len(entries)}
    return stats, vulns


def summarize(members):
    """묶음 하나를 고유 취약점 한 건으로 요약한다. 한 항목이라도 근거가 있으면 '있음'."""
    gh_commits = sorted({u for m in members for u in m["fix_gh_commits"] + m["git_gh_commits"]})
    details = max((m["details"] for m in members), key=len)
    pubs = [m["published"] for m in members if m["published"]]
    ids = {m["id"] for m in members} | {a for m in members for a in m["aliases"]}
    packages = {}
    for m in members:
        for name, ranges in m["packages"].items():
            packages.setdefault(name, []).extend(ranges)
    return {
        "members": members,
        "ids": ids,
        "published": min(pubs) if pubs else None,
        "fix_ref": any(m["fix_ref"] for m in members),
        "fix_gh_commit": any(m["fix_gh_commits"] for m in members),
        "fix_gh_pr": any(m["fix_gh_pr"] for m in members),
        "fix_other": any(m["fix_other"] for m in members),
        "git_fixed": any(m["git_fixed"] for m in members),
        "gh_commits": gh_commits,
        "details": details,
        "call_pattern": any(CALL_RE.search(m["details"]) for m in members),
        "packages": packages,
        "other_gh_commit": any(m["other_gh_commits"] for m in members),
        "candidate": bool(gh_commits) and len(details.strip()) >= DETAILS_MIN,
        # 출처를 붙인 커밋 목록 (우선순위 FIX > GIT > WEB, 같은 커밋은 한 번만)
        "labeled_commits": labeled_commits(members),
    }


def labeled_commits(members):
    seen, out = set(), []
    for label, key in (("FIX", "fix_gh_commits"), ("GIT", "git_gh_commits"), ("WEB", "other_gh_commits")):
        for url in sorted({u for m in members for u in m[key]}):
            owner, repo, sha = GH_COMMIT_RE.match(url).groups()
            k = (owner.lower(), repo.lower(), sha[:7])
            if k not in seen:
                seen.add(k)
                out.append((label, url))
    return out


# ---------------------------------------------------------------- 출력

def width(s):
    # 한글은 콘솔에서 두 칸을 차지하므로 정렬할 때 따로 센다
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def ljust(s, n):
    return s + " " * max(0, n - width(s))


def rjust(s, n):
    return " " * max(0, n - width(s)) + s


def pct(n, d):
    return f"{n:>6,} {n / d * 100:5.1f}%" if d else f"{n:>6,}     -"


def split_recent(vulns, snap):
    cutoff = snap - dt.timedelta(days=RECENT_DAYS)
    return [v for v in vulns if v["published"] and v["published"] >= cutoff], cutoff


def print_summary(meta, stats, vulns):
    snap = snapshot_time(meta)
    recent, cutoff = split_recent(vulns, snap)
    cols = [vulns, recent]

    print(f"OSV PyPI 사전 검증 · 스냅샷 {snap:%Y-%m-%d %H:%M} KST (덤프 Last-Modified)")
    p = stats["prefix"]
    others = stats["total"] - p["PYSEC"] - p["GHSA"] - p["MAL"]
    print(f"항목 {stats['total']:,} = PYSEC {p['PYSEC']:,} · GHSA {p['GHSA']:,} · MAL {p['MAL']:,} · 기타 {others:,}")
    print(f"제외: withdrawn {stats['withdrawn']:,} · MAL {stats['mal']:,} · MAL과 alias로 이어진 묶음 {stats['mal_linked']:,}")
    print(f"분석 대상 항목 {stats['entries']:,} → aliases로 묶은 고유 취약점 {len(vulns):,}")
    print()

    L = 30
    print(ljust("", L) + rjust("전체", 14) + rjust("최근 2년", 14))
    print(ljust("", L) + rjust("", 14) + rjust(f"({cutoff:%Y-%m-%d}~)", 14))
    print(ljust("고유 취약점", L) + "".join(f"{len(c):>14,}" for c in cols))

    def row(label, key):
        print(ljust(label, L) + "".join(f"{pct(sum(1 for v in c if key(v)), len(c)):>14}" for c in cols))

    print("[수정 커밋]")
    row("  references FIX 있음", lambda v: v["fix_ref"])
    row("    └ GitHub 커밋 URL", lambda v: v["fix_gh_commit"])
    row("    └ GitHub PR URL", lambda v: v["fix_gh_pr"])
    row("    └ 기타 URL", lambda v: v["fix_other"])
    row("  ranges GIT fixed 있음", lambda v: v["git_fixed"])
    row("  둘 중 하나라도", lambda v: v["fix_ref"] or v["git_fixed"])
    row("  GitHub 커밋 diff 확보 가능", lambda v: bool(v["gh_commits"]))
    row("  (참고) WEB 등 타입의 GH 커밋", lambda v: v["other_gh_commit"])
    print("[details 길이]")
    row("  없음", lambda v: not v["details"].strip())
    row(f"  1~{DETAILS_MIN - 1}자", lambda v: 0 < len(v["details"].strip()) < DETAILS_MIN)
    row(f"  {DETAILS_MIN}~999자", lambda v: DETAILS_MIN <= len(v["details"].strip()) < 1000)
    row("  1000자 이상", lambda v: len(v["details"].strip()) >= 1000)
    row("  xxx.yyy( 패턴 등장", lambda v: v["call_pattern"])
    print("[판정]")
    row("  분석 가능 후보", lambda v: v["candidate"])
    row("  (참고) WEB 등 포함 시 후보", with_web)

    rate = sum(v["candidate"] for v in recent) / len(recent) * 100 if recent else 0
    web = sum(with_web(v) for v in recent) / len(recent) * 100 if recent else 0
    print(f"\n판정 대상(최근 2년) 후보 비율 {rate:.1f}% → {verdict(rate)}  (diff 실수신 보정 전)")
    print(f"  참고: WEB 등 포함 시 {web:.1f}% → {verdict(web)}")
    print_monthly(recent, snap)


def with_web(v):
    return (bool(v["gh_commits"]) or v["other_gh_commit"]) and len(v["details"].strip()) >= DETAILS_MIN


def verdict(rate):
    if rate >= 50:
        return "계획대로"
    if rate >= 25:
        return "계획 유지 + 판단 불가 비율 별도 보고"
    return "범위 조정"


def print_monthly(recent, snap):
    """최근 24개 '완결된' 달의 신규 고유 취약점 수. 이번 달은 진행 중이라 뺀다."""
    end = snap.replace(day=1)
    months = []
    y, m = end.year, end.month
    for _ in range(24):
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
        months.append((y, m))
    months.reverse()
    cnt = Counter((v["published"].year, v["published"].month) for v in recent)
    vals = [cnt[k] for k in months]
    print(f"\n월별 신규 고유 취약점 ({months[0][0]}-{months[0][1]:02d} ~ {months[-1][0]}-{months[-1][1]:02d})")
    for i in range(0, 24, 8):
        print("  " + "  ".join(f"{y % 100:02d}-{m:02d} {cnt[(y, m)]:>3}" for y, m in months[i:i + 8]))
    avg = sum(vals) / len(vals)
    print(f"  월평균 {avg:.1f}건 (최소 {min(vals)}, 최대 {max(vals)}) · 일평균 {avg / 30.4:.1f}건")


def print_keys():
    """함수 정보가 구조화된 필드로 있는지 — 자유 필드의 키 분포를 본다."""
    where = {"affected[].ecosystem_specific": Counter(), "affected[].database_specific": Counter(),
             "affected[].ranges[].database_specific": Counter(), "database_specific (최상위)": Counter()}
    example = {}

    def add(loc, obj):
        for k, val in (obj or {}).items():
            where[loc][k] += 1
            example.setdefault((loc, k), json.dumps(val, ensure_ascii=False)[:60])

    with zipfile.ZipFile(ZIP_PATH) as zf:
        for rec in iter_records(zf):
            add("database_specific (최상위)", rec.get("database_specific"))
            for aff in rec.get("affected", []):
                add("affected[].ecosystem_specific", aff.get("ecosystem_specific"))
                add("affected[].database_specific", aff.get("database_specific"))
                for rng in aff.get("ranges", []):
                    add("affected[].ranges[].database_specific", rng.get("database_specific"))

    for loc, c in where.items():
        print(f"\n{loc} — 키 {len(c)}종")
        for k, n in c.most_common(12):
            print(f"  {n:>7,}  {k:<28} 예: {example[(loc, k)]}")


def web_check(vulns, meta):
    """WEB 타입 GitHub 커밋을 수정 커밋 근거로 써도 되는가 (docs/decisions.md D-003)."""
    # 1) 출처(ID 접두어)별로 GitHub 커밋 링크가 어떤 references 타입으로 붙는가
    types = Counter()
    for v in vulns:
        for m in v["members"]:
            src = m["id"].split("-")[0]
            types[(src, "FIX")] += len(m["fix_gh_commits"])
            types[(src, "그 외(WEB 등)")] += len(m["other_gh_commits"])
    print("GitHub 커밋 링크의 references 타입 (출처별)")
    for (src, t), n in sorted(types.items()):
        if n:
            print(f"  {src:<6} {ljust(t, 14)} {n:>6,}")

    # 2) FIX·GIT 커밋과 WEB 커밋이 함께 있는 묶음에서 둘이 같은 커밋인가
    def key(url):
        o, r, s = GH_COMMIT_RE.match(url).groups()
        return o.lower(), r.lower(), s[:7]
    both = any_match = all_match = 0
    for v in vulns:
        fix = {key(u) for m in v["members"] for u in m["fix_gh_commits"] + m["git_gh_commits"]}
        web = {key(u) for m in v["members"] for u in m["other_gh_commits"]}
        if fix and web:
            both += 1
            any_match += bool(web & fix)
            all_match += web <= fix
    print(f"\nFIX·GIT 커밋과 WEB 커밋이 함께 있는 묶음 {both:,}")
    print(f"  WEB 커밋 중 하나 이상이 수정 커밋과 일치  {pct(any_match, both)}")
    print(f"  WEB 커밋 전부가 수정 커밋 목록에 있음     {pct(all_match, both)}")

    # 3) PYSEC 재수입으로 published가 늦게 찍힌 묶음이 최근 2년 집계를 부풀리는가
    recent, _ = split_recent(vulns, snapshot_time(meta))
    old = sum(1 for v in recent
              if (ys := [int(i.split("-")[1]) for i in v["ids"] if re.match(r"CVE-\d{4}-", i)])
              and max(ys) <= 2023)
    print(f"\n최근 2년 묶음 중 CVE 연도가 모두 2023 이하  {pct(old, len(recent))}")


def peek(n):
    """본 집계 전에 원본 JSON을 몇 개 그대로 본다. PYSEC·GHSA·MAL에서 하나씩."""
    with zipfile.ZipFile(ZIP_PATH) as zf:
        names = [x for x in zf.namelist() if x.endswith(".json")]
        print(f"zip 안 JSON 파일 {len(names):,}개 · 접두어 {dict(Counter(x.split('-')[0] for x in names))}")
        picks = []
        for pre in ("PYSEC-", "GHSA-", "MAL-"):
            hit = next((x for x in sorted(names, reverse=True) if x.startswith(pre)), None)
            if hit:
                picks.append(hit)
        for name in picks[:n]:
            rec = json.loads(zf.read(name))
            if len(rec.get("details", "")) > 300:
                rec["details"] = rec["details"][:300] + " …(생략)"
            for aff in rec.get("affected", []):
                # 버전 나열은 수백 줄이 되므로 개수만 보인다
                if "versions" in aff:
                    aff["versions"] = f"…({len(aff['versions'])}개 생략)"
            print(f"\n===== {name}")
            print(json.dumps(rec, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------- 정답 후보

def ranges_text(ranges):
    """ECOSYSTEM range 이벤트를 '>=1.0, <1.2' 형태로 읽기 좋게 바꾼다."""
    parts = []
    for rng in ranges:
        lo, segs = None, []
        for ev in rng.get("events", []):
            if "introduced" in ev:
                lo = ev["introduced"]
            elif "fixed" in ev or "last_affected" in ev:
                hi = f"<{ev['fixed']}" if "fixed" in ev else f"<={ev['last_affected']}"
                segs.append(hi if lo in (None, "0") else f">={lo}, {hi}")
                lo = None
        if lo is not None:
            segs.append("전체" if lo == "0" else f">={lo}")
        parts.extend(segs)
    return " | ".join(dict.fromkeys(parts))


def pick_candidates(vulns, meta):
    """최근 2년 분석 가능 후보에서 패키지가 겹치지 않게 20건. 시드 고정.

    WEB 타입 GitHub 커밋도 근거로 인정한 풀에서 뽑는다(docs/decisions.md D-003).
    평가 세트가 서비스가 실제로 받을 입력과 같아야 정확도 수치가 의미를 가진다.
    """
    recent, _ = split_recent(vulns, snapshot_time(meta))
    pool = sorted((v for v in recent if with_web(v) and len(v["packages"]) == 1),
                  key=lambda v: min(v["ids"]))
    random.Random(SEED).shuffle(pool)
    picked, used = [], set()
    for v in pool:
        pkg = next(iter(v["packages"]))
        if pkg not in used:
            used.add(pkg)
            picked.append(v)
        if len(picked) == N_CANDIDATES:
            break
    return picked


def candidate_row(v):
    ids = sorted(m["id"] for m in v["members"])
    osv_id = next((i for i in ids if i.startswith("PYSEC-")), None) or \
        next((i for i in ids if i.startswith("GHSA-")), ids[0])
    pkg, ranges = next(iter(v["packages"].items()))
    return {
        "osv_id": osv_id,
        "cve_alias": ";".join(sorted(i for i in v["ids"] if i.startswith("CVE-"))),
        "package_name": pkg,
        "affected_range": ranges_text(ranges),
        # "출처 URL; 출처 URL" — 출처는 FIX / GIT / WEB
        "fix_commit_url": "; ".join(f"{label} {url}" for label, url in v["labeled_commits"]),
        "details_summary": " ".join(v["details"].split())[:200],
        # 아래 세 칸은 사람이 채운다. 스크립트가 추측해 채우면 정답으로서 의미가 없다
        "my_answer_function": "",
        "my_answer_condition": "",
        "note": "",
    }


def write_candidates(rows):
    if CANDIDATES_PATH.exists():
        print(f"{CANDIDATES_PATH.relative_to(ROOT)} 가 이미 있어 덮어쓰지 않는다 (사람이 채운 정답 보호)")
        return
    CANDIDATES_PATH.parent.mkdir(exist_ok=True)
    # utf-8-sig: 엑셀에서 열어 한글을 채워도 깨지지 않게
    with open(CANDIDATES_PATH, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{CANDIDATES_PATH.relative_to(ROOT)} 생성 — {len(rows)}건, 정답 칸은 비어 있음")


def check_diffs(rows):
    """커밋 URL 형태만으로는 부족하다. 실제로 diff를 받을 수 있는지 GitHub API로 확인한다."""
    print(f"\ndiff 실수신 확인 (후보 앞 {N_DIFF_CHECK}건, 비인증 GitHub API)")
    ok = 0
    for row in rows[:N_DIFF_CHECK]:
        label, url = row["fix_commit_url"].split("; ")[0].split(" ", 1)
        owner, repo, sha = GH_COMMIT_RE.match(url).groups()
        api = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        r = requests.get(api, headers={"Accept": "application/vnd.github+json"}, timeout=30)
        moved = " (이동됨)" if r.history else ""
        if r.status_code == 200:
            files = r.json().get("files", [])
            py = sum(f["filename"].endswith(".py") for f in files)
            ok += 1
            result = f"200{moved}  파일 {len(files):>3}개 중 .py {py:>3}개"
        else:
            result = f"{r.status_code}{moved}  받지 못함"
        print(f"  {row['osv_id']:<20} {row['package_name'][:16]:<16} {label}  {result}")
    left = r.headers.get("X-RateLimit-Remaining")
    print(f"  성공 {ok}/{N_DIFF_CHECK} · API 잔여 한도 {left}")
    return ok


# ----------------------------------------------------------------

def main():
    # 콘솔이 cp949여도 출력이 깨지지 않게
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--peek", type=int, metavar="N", help="원본 JSON N개 출력 (스키마 확인)")
    ap.add_argument("--keys", action="store_true", help="자유 필드 키 분포")
    ap.add_argument("--candidates", action="store_true", help="eval/candidates.csv 생성 + diff 확인")
    ap.add_argument("--web-check", action="store_true", help="WEB 타입 커밋이 수정 커밋인지 대조")
    args = ap.parse_args()

    meta = download()
    if args.peek:
        peek(args.peek)
    elif args.keys:
        print_keys()
    else:
        stats, vulns = load(meta)
        if args.web_check:
            web_check(vulns, meta)
        elif args.candidates:
            rows = [candidate_row(v) for v in pick_candidates(vulns, meta)]
            write_candidates(rows)
            ok = check_diffs(rows)
            recent, _ = split_recent(vulns, snapshot_time(meta))
            # 성공 8건 미만이면 후보 비율 × 성공률로 판정한다 (docs/현황.md 판정 기준)
            factor = ok / N_DIFF_CHECK if ok < 8 else 1.0
            note = "보정 적용" if ok < 8 else f"보정 불필요 (성공 {ok}/{N_DIFF_CHECK} ≥ 8)"
            for label, key in (("FIX+GIT(원래 기준)", lambda v: v["candidate"]), ("WEB 포함(D-003)", with_web)):
                rate = sum(key(v) for v in recent) / len(recent) * 100 * factor
                print(f"{note} · {label} 후보 비율 {rate:.1f}% → {verdict(rate)}")
        else:
            print_summary(meta, stats, vulns)


if __name__ == "__main__":
    main()
