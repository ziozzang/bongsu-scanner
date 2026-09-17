# v0.6.0 문서 재구성 검증 기록

2026-09-18 문서 작업. 시작 HEAD: `24a6de6864f606b00101f75dcd7d7a42327666b1`.
병행 코드 작업의 변경은 수정하지 않았으며, 설정 override와 VEX metadata의
최종 동작은 확인 가능한 작업 트리 코드도 대조했다. 이 기록은 배포 완료나
전체 제품 승인 결과가 아니라 문서 변경·검증 범위의 기록이다.

## 문서 지도와 내용 이동

[사용자 문서 색인](README.md)에 전체 경로를 정리했다.
원 README의 상세 설명·예제를 다음과 같이 이동했다. 구성과 링크를 바꾸되,
기능 의미 변경은 아래에서 설명한 정정 및 확인된 병행 코드 반영에 한정했다.

| 기존 README 구간 | 새 위치 / 역할 |
| --- | --- |
| 소개·설치·초기 실행·지원 요약·보안 | 루트 `README.md`의 짧은 시작 안내 |
| 40–133 및 logging 19–26 | `docs/configuration.md` — 경로·기본값·보안·logging |
| 135–167 | `docs/releasing.md` — publisher 신뢰 정책, v0.6.0 checklist/artifacts/smoke |
| 169–248, self-update 455–472 | `deploy/README.md` — 단일 배포 문서, 기존 container/systemd/cron 절차와 통합 |
| 250–375 및 batch 454 | `docs/scanning.md` — local/image/registry/inventory/ownership/batch |
| 377–449 | `docs/signing.md` — 출력 서명·자동 서명·검증·scrambler |
| 474–486, 523–601, 606–683 | `docs/vulnerability-database.md` — 선택·갱신·저장·변환·전송 |
| 602, 604 | `docs/advisory-sources.md` — RubySec/VEX 변환, 별도 Measurements |
| 488–521, 684–721 | `docs/matching.md` — matching/report/severity/release mapping |
| 723–778 | `docs/llm-review.md` — 선택적 LLM 평가 |
| 780–793 | `docs/roadmap.md` — 미구현 서버 제출 제안 |

기존 `severity-policy`, `findings-json`, `ci-integration`, `support-matrix`를
계속 사용한다. `docs/commands.md`와 `docs/reviews/*`는 편집하지 않았다.
문서 사이의 기존 anchor 링크는 새 위치로 수정하고 모든 상대 링크를 검사했다.

## 수정한 오래되거나 오해 가능한 문장

이전 위치는 작업 시작 시 사본 기준, 이후 위치는 이 기록 작성 시 문서 기준이다.
새 항목 추가만으로 끝난 누락도 아래에 포함했다.

| 이전 file:line → 설명 | 이후 file:line → 설명 | 확인 근거 |
| --- | --- | --- |
| `README.md:35` — 0.5.0 빌드 예시 | `README.md:17` — 0.6.0 빌드 예시 | `Makefile`의 VERSION 인자 |
| `README.md:40` — 설정 파일 위치를 BONGSU_HOME만으로 설명 | `docs/configuration.md:6` — `--config` > BONGSU_CONFIG > 기본 파일; 기본 키·DB·cache는 BONGSU_HOME 유지 | `internal/config/config.go`, CLI override 실측 |
| `README.md:177` — FreeBSD release archive가 있는 것처럼 설명 | `deploy/README.md:33` — FreeBSD는 CI cross-build만 있고 release archive 없음 | `deploy/dist.sh`, `.github/workflows/ci.yml` |
| `README.md:185` — 다운로드·container·dist·서명 예시 0.5.0 | `deploy/README.md:40` — 모든 현행 버전 예시 0.6.0; tag 발행 여부는 단정하지 않음 | `deploy/dist.sh`, `.github/workflows/release.yml` |
| `deploy/README.md:4` — 배포 예시 0.5.0 | `deploy/README.md:4` — dist/image/tag 예시 0.6.0 | 동일 packaging 인자 |
| `README.md:277` — findings 종료 코드를 고정 2로 설명 | `docs/scanning.md:32` — 기본 2, global --findings-exit-code 1..125; partial 3/취소 130와 CI 우선순위 링크 | `cmd/bscan/match.go:50`, CLI 2/7/3/130 실측 |
| `README.md:494` — match 예시에서 고정 2로 설명 | `docs/matching.md:10` — 기본 findings 코드 2로 명시 | CLI help 및 match 코드 |
| `README.md:519` — LLM 오류와의 우선순위를 고정 코드 2로 설명 | `docs/matching.md:35` — 설정한 findings 코드가 LLM 오류 1보다 우선; 취소/partial 구분 | `cmd/bscan/match.go`, 기존 LLM 회귀 테스트 |
| `README.md:271` — scan report 형식 설명에 json 수용 동작 누락 | `docs/scanning.md:26` — json은 findings 파일만 사용하고 .report.json 추가 생성 안 함 | `cmd/bscan/scanmatch.go`, CLI 파일 검사 |
| `README.md:402` — 자동 서명이 고정 기본 설정 파일만 읽는 듯한 설명 | `docs/signing.md:28` — 선택한 설정 파일의 signer와 기본/설정 키 사용 | override scan 및 서명 검증 CLI |
| `README.md:131` — minimum version 적용 설명이 release에만 한정 | `docs/configuration.md:107` — verify/check 서명과 release 검증에 적용 | `cmd/bscan/main.go:958`, `cmd/bscan/update.go` |
| `README.md:644` — records.json 파일처럼 읽히는 표기 | `docs/vulnerability-database.md:136` — records 테이블의 json 컬럼으로 명시 | `internal/vulndb/sqlite.go:45` |
| `README.md:680` — DB import 별도 상한 누락 | `docs/vulnerability-database.md:172` — 8 GiB / 100,000 files; feed update 32 GiB와 별도 | `internal/vulndb/archive.go:128` 및 파일 개수 검사 |
| `README.md:565` — 700/920/670 MB 측정값을 운영 설명에 혼합 | `docs/advisory-sources.md:41` — 날짜·기준 커밋이 있는 Measurements로 이동, 기록된 bytes를 MiB로 환산 | 과거 기록 보존; 이번 외부 재측정 아님 |
| `deploy/README.md:147` — 배포 문서에 DB 선택·단위·freshness 설명 중복 | `deploy/README.md:186` — DB 페이지로 연결; 원 설명은 DB 페이지와 Measurements에 유지 | `cmd/bscan/db_selection.go`, `internal/vulndb/selection.go` |
| `README.md:604` — 2,154 중 1,981 처리 후 remaining 181이라는 산술 불일치 | `docs/advisory-sources.md:42` — 서로 다른 실행의 관찰이며 목록 증가 때문에 산술 잔여가 아님; 실험 바이너리 커밋 미기록 명시 | 사용자 제공 정정, `git show 24a6de6:README.md`; 수치 재측정 안 함 |
| `README.md:604` — 19.6 GB / 1 GB / 106 MB 실측이 운영 제한과 혼합 | `docs/advisory-sources.md:43` — 역사적 Measurements로 분리하고 bytes 및 GiB/MiB 환산; 원 측정 근거 한계 명시 | 원 README 관찰 보존; 현재 cap은 코드에서 별도 확인 |
| `README.md:604` — VEX 실패를 최대 세 번 retry한다고 표현 | `docs/advisory-sources.md:18` — 최대 세 번 시도, 두 번 retry로 정정 | `redhat_vex_delta.go`의 attempt == 2 종료 |
| `docs/severity-policy.md:22` — JSON 카운터를 Skipped["unimportant"]로 표기 | `docs/severity-policy.md:22` — skipped["unimportant"]로 정정 | findings JSON 태그 |
| `CHANGELOG.md:5` — 범위가 2026-09-17까지 | `CHANGELOG.md:5` — 2026-09-18까지 | 검토 날짜와 git log 범위 |
| `CHANGELOG.md:37` — fuzz target 45개 | `CHANGELOG.md:43` — func Fuzz 정의 47개 | `rg "^func Fuzz" --glob "*.go"` 집계 |
| `CHANGELOG.md:25` — release artifact 항상 서명한다고 설명 | `CHANGELOG.md:32` — publisher key 설정 시 서명 | release workflow secret 분기 |
| `CHANGELOG.md:48` — 모든 RHEL/UBI를 major로 설명 | `CHANGELOG.md:97` — 9까지 major, 10+ major.minor; README의 기존 정확한 설명도 보존 | `internal/match/sbom.go`, `internal/vulndb/model.go` |
| `CHANGELOG.md:12` — VEX 추가/삭제/수정 항목 중복 | `CHANGELOG.md:12` — 단일 feature 항목 아래 archive/delta/deletion/rating/status 통합 | VEX 코드, `git log 2de24ef..HEAD` |
| `CHANGELOG.md:65` — 기본/Ubuntu/severity 항목 중복 | `CHANGELOG.md:71` — 정책 변경 하나로 통합; USN 범위 수정·Alma 등급은 별도 사용자 효과로 기록 | `internal/match/severity.go`, `internal/vulndb/ingestion.go` |
| `CHANGELOG.md:84` — converter 내부 구현과 약 10 GiB 주장이 release 항목에 혼합 | `CHANGELOG.md:86` — 대형 catalog 변환 메모리 감소라는 사용자 효과만 기록 | `internal/vulndb/convert.go`; 측정은 review 링크 |
| `CHANGELOG.md:29` — 실제 config 선택 대신 plumbing으로 표현, CLI 변화 누락 | `CHANGELOG.md:36` — 실제 config 선택, custom findings code, memory target, template, units/json, Selection, streaming, quiet, freshness를 각 효과별로 기록 | 관련 CLI/code/help와 git log |
| `docs/support-matrix.md:3` — 과거 측정 기준을 현행 지원 표와 혼합 | `docs/support-matrix.md:3` — HEAD 기준 현재 표와 역사적 측정 섹션 분리 | 시작 HEAD 24a6de6, 현재 코드 |
| `docs/support-matrix.md:12` — USN cves_map 미지원이라고 설명 | `docs/support-matrix.md:20` — affected-entry/release별 CVE와 vendor rating 지원 | `internal/match/cache.go`, `internal/match/severity.go` |
| `docs/support-matrix.md:19` — owner가 있으면 무조건 distro-owned 제외로 설명 | `docs/support-matrix.md:39` — owner가 같은 SBOM에 있고 매칭 가능할 때만 제외; 아니면 owner-unmatched와 언어 매칭 | `internal/match/match.go:138` 및 subjectSkip |
| `docs/support-matrix.md:41` — VEX 문서 상한 64 MiB를 현재 설명과 혼합 | `docs/support-matrix.md:59` — 현재 256 MiB, 이전 64 MiB 관찰은 역사 섹션에 한정 | `internal/vulndb/redhat_vex.go` vexMaxDocument |
| `docs/support-matrix.md:7` — Red Hat 공급원·등급·archive/delta 동작과 실측 혼합 | `docs/support-matrix.md:15` — VEX 등급과 OSV CVSS fallback 구분; deltas/deletion/current limits 분리 | `redhat_vex*.go`, `severity.go`, 초기 HEAD + 병행 코드 |
| `docs/findings-json.md:86` — owner 필드가 언어 matching을 항상 제외한다고 설명 | `docs/findings-json.md:86` — 동일 문서의 matchable owner 조건과 owner-unmatched fallback; skip vocabulary 링크 | `internal/match/match.go` |
| `docs/findings-json.md:148` — source freshness/archive/delta metadata 필드 누락 | `docs/findings-json.md:153` — data_through/archive_date/모든 delta_* JSON 태그와 per-run/cumulative/current-state 의미 | `SourceMeta`, `updateVEXDeltaFeed`, `finalCacheMeta` |
| `docs/ci-integration.md:7` — Unreleased라 tag 가정하지 않는다는 설명 | `docs/ci-integration.md:7` — 발행 후 사용할 v0.6.0 pinned build 예시 | CLI build metadata 및 Makefile 버전 주입 방식 |
| `docs/ci-integration.md:48` — accompanying errors의 범위가 모호 | `docs/ci-integration.md:59` — 취소 > findings > partial > 기타 오류 순서를 명시 | 실제 batch findings+partial 종료 7; 요구한 partial 우선과 불일치 |
| `deploy/README.md:177` — air-gap을 이전 README section으로 링크 | `deploy/README.md:210` — 동일 배포 문서에 절차 통합, DB 제한은 DB 문서로 링크 | 상대 링크 전체 검사 |

## 단어 수와 이동 누락 검사

공백으로 구분한 토큰 수(`str.split()`, `wc -w`와 같은 기준)다. README 전체는
806줄 / 6,510단어에서 107줄 / 715단어로 줄었다. 아래 이전 수는 해당 이동
구간의 합이며 배포 행만 기존 `deploy/README.md` 1,268단어도 포함한다.
새 문서 수에는 제목·연결·정정·추가 checklist도 포함한다.
전체 편집 대상 문서(생성 참조·history·이 검증 기록 제외)는 14,466단어에서
16,630단어로 늘었다. README 축약을 설명 삭제로 대체하지 않았다.

| 이동 단위 | 이전 단어 | 이후 단어 |
| --- | ---: | ---: |
| `docs/configuration.md` | 655 | 786 |
| `docs/releasing.md` | 208 | 802 |
| `deploy/README.md` | 1,923 | 1,677 |
| `docs/scanning.md` | 1,026 | 1,081 |
| `docs/signing.md` | 434 | 441 |
| `docs/vulnerability-database.md` | 1,450 | 1,486 |
| `docs/advisory-sources.md` | 712 | 937 |
| `docs/matching.md` | 596 | 644 |
| `docs/llm-review.md` | 439 | 440 |
| `docs/roadmap.md` | 117 | 131 |

단어 수만으로 누락 여부를 판정하지 않았다. 이동 전후 토큰 diff도 비교하고
삭제된 긴 구간을 검토했다. 배포 감소분은 중복 설치/container/systemd 안내를
기존 절차로 통합하고 DB 선택·freshness 설명을 DB 페이지로 연결한 것이다.
DB 크기와 VEX runtime 숫자는 Measurements로 이동했다. LLM·서명·roadmap의
설명과 원래 shell 예제는 유지했다. air-gap 시작 문장의 줄 경계 누락도 검사
중 복구했다. 요청된 이동 구간에서 의도하지 않은 기능 설명 누락은 발견하지 못했다.

## 실행·정적 검증

- 요청한 `go build -o /home/ziozzang/.cache/bongsu-work/work-R28/bscan ./cmd/bscan` 성공.
- `BONGSU_HOME`과 임시 catalog/fixture/output을 모두 작업용 W 아래에 두고
  `BONGSU_OFFLINE=1`, `BONGSU_NO_UPDATE_CHECK=1`로 CLI 검사 25건 성공.
  help/init/about, legacy catalog 검증→SQLite 변환, scan+match+JSON/HTML,
  기본 exit 2/custom 7/범위 오류 1, memory target, report 재출력,
  서명 검증, signed DB export/import/verify, config init/show/override,
  기본 key/DB 유지, partial exit 3 및 remote target offline 거절을 확인했다.
- JSON 검사에서 `<base>.findings.json`과 HTML을 확인하고 `.report.json`이
  생성되지 않음을 확인했다. 최초 검증 스크립트는 YAML 값의 따옴표를
  예상하지 못해 멈췄으며 assertion을 수정해 override 검사까지 완료했다.
- 별도 SIGINT 검사에서 exit 130, findings+partial batch에서 custom exit 7을 확인했다.
- 기존 문서 계약 테스트 `TestREADMEConfigUpdateExitCodeGuidance`,
  `TestReadmeSignatureAndReleasePolicy`, `TestDeploymentContracts` 통과.
- `SourceMeta`의 모든 JSON 필드 이름이 findings reference에 포함되는지 검사했다.
- Markdown fence 균형, 문서 공백, `git diff --check`와 상대 경로/anchor 검사를 수행했다.
  링크 검사는 code fence를 제외하고 Markdown 링크·reference 정의와 대상 heading을
  읽는 작은 Python 스크립트로 실행했다. 생성 문서도 읽기 전용 검사에 포함했다.
  **18개 문서 / 상대 링크 80개 / 경로·anchor 오류 0개**였다.
  `docs/commands.md`는 작업 시작 사본과 SHA-256이 같았다.

## 미확인 사항과 릴리스 전에 남는 차이

- **종료 우선순위:** 요구한 “partial 3이 findings보다 우선”은 현재 코드와 다르다.
  `cmd/bscan/match.go`는 취소 130 → findings 설정값 → partial 3 → 기타 1 순서다.
  batch의 다른 대상에서 findings와 partial이 함께 생기면 실측 종료값은 7이었다.
  문서는 실제 동작을 명시했다. 정책을 바꾸려면 별도 코드 수정이 필요하다.
- **생성 참조의 config 설명:** `docs/commands.md:83` 부근에는 아직 config override가
  구현되지 않았다는 문장이 있다. 읽기 전용 지시를 지켰으므로 생성기와 결과를
  직접 고치지 않았다. 병행 코드 작업에서 생성기 설명과 생성 문서를 갱신해야 한다.
- **과거 수치:** feed 크기·성능·Trivy 비교는 기존 기록을 날짜·커밋과 함께 보관했으며
  이번에 외부 feed를 내려받거나 비교 benchmark를 재실행하지 않았다. VEX 2026-09-18
  관찰은 README에 기록된 커밋 `24a6de6`까지만 확인했고 실제 benchmark 바이너리
  커밋 및 원 timing/memory 로그는 확인하지 못했다. 목록 증가 설명은 사용자 제공 정정이다.
- **실제 배포:** v0.6.0 tag 존재, release secret 설정, CI green, release upload,
  GHCR의 실제 multi-arch manifest, native macOS/Windows/FreeBSD 실행,
  systemd 설치와 self-update 교체, 외부 LLM 및 hosted CI 업로드는 실행하지 않았다.
  산출물 목록과 정책은 packaging/workflow/CLI 코드로 확인했다.
- 전체 Go 회귀 테스트나 benchmark를 재실행하지 않았다. 문서 관련 기존 테스트와
  위 오프라인 CLI 검사로 이 변경을 검증했으며 병행 코드의 전체 검증을 대신하지 않는다.

임시 실행 파일·키·catalog·검증 스크립트·원본 사본은 결과 기록 후 W에서 삭제했다.
