# 배포판·취약점 공급원 지원 표

2026-09-17, 측정 커밋 `1ddd44d77fe93f94d97091b0600bd6d6fed80de0`의 코드와 실제 CLI/피드 조회 기준이다. file:line은 이 커밋 기준이며, 측정 중 다른 작업이 바꾼 작업 트리 소스는 포함하지 않는다. 인벤토리 수집 가능 여부와 취약점 매칭 지원은 다르다. 기본 목록은 `internal/vulndb/source.go:56`, 기본 공급원은 같은 파일 `:67`, PURL 매핑은 `internal/vulndb/model.go:180`에서 확인했다. 실제 검증 결과는 [Round 7 보고서](reviews/2026-09-17-accuracy-round7.md)와 [Round 7b 상세 JSON](reviews/2026-09-17-accuracy-round7b-details.json)에 있다.

| 배포판 / ecosystem | advisory 공급원 | 기본 / 선택 | 릴리스 매핑 | 심각도 출처 | 제한·주의와 코드 근거 |
|---|---|---|---|---|---|
| RHEL / UBI / Red Hat | OSV Red Hat; 선택형 CSAF VEX (`--add-source redhat-vex`) | OSV 기본, VEX opt-in; 함께 선택하면 OSV Red Hat feed 생략, selection 보존 실측 | RHEL ≤9 major, ≥10 CPE major.minor 보존 | VEX 제품 impact → aggregate Red Hat 등급; UBI9 Trivy 공통 **685/685** 일치 | UBI9/8 CVE 쌍: OSV **366/0**, VEX **822/545**; Trivy만 **375/530 → 17/0**. 17 중 16은 API Not affected, 1은 버전 한정 음성 marker의 EVR 유실 위험. Grype/API 대조로 expat CVE-2026-66046 **2쌍**의 archive coverage 누락도 확인. 주간 archive 이후 changes.csv 증분을 최신 문서 교체 방식으로 적용하고 deletions.csv는 affected 없는 withdrawn으로 보존한다. 4개 worker·문서 256 MiB·목록 16 MiB·업데이트 20,000건 및 델타 2 GiB 예산을 적용하며 잔여 작업은 다음 실행에서 재개한다. 상태 출력에 archive/델타 시각과 건수를 기록한다. VEX의 모듈 라벨 없는 Python source **13쌍**이 UBI8에서 추가되므로 module 문제가 전부 해소된 것은 아님. EUS/AUS/E4S/TUS/ELS는 CPE별 별도 릴리스. 이 커밋은 module 유무만 검사. `internal/vulndb/redhat_vex.go:73`, `:417`, `:435`; `internal/match/match.go:232`, `:242`; `internal/match/severity.go:208` |
| Rocky Linux | OSV RLSA | 기본 | `rocky-9.3` → `9` | erratum의 텍스트 등급 우선, 없으면 CVSS | `internal/match/sbom.go:367`, `internal/match/severity.go:227`. 하나의 advisory에 여러 CVE가 연결될 수 있음 |
| AlmaLinux | OSV ALSA | 기본 | `almalinux-9.8` → `9` | erratum 제목 Moderate/Important → MEDIUM/HIGH; 실측 **9 findings: MEDIUM 4, HIGH 5, UNKNOWN 0** | `related`의 CVE가 aliases로 승격돼 수동 errata 보정 없이 **48 CVE 쌍**, Trivy **31**을 모두 포함. 추가는 libevent 8 + FIPS provider 9; 후자는 전체 advisory CVE를 binary에 전파하는 범위 문제. `internal/vulndb/ingestion.go:181`, `internal/match/severity.go:254`, `internal/match/cache.go:294`. PURL `alma`/`almalinux`와 major 정규화는 유지 |
| CentOS Stream | 일반 RHEL feed로 대체하지 않음 | 미지원 | CentOS major ≥8 → `centos-stream:N` | 해당 OS 매칭 없음 | 실측 RPM **145개**는 `centos-stream-unsupported`, RPM 소유 Python **7개**는 `distro-owned`; finding 0은 안전 판정이 아님. `internal/match/sbom.go:377`, `internal/match/match.go:332`. 이 판별은 이름의 Stream 여부 대신 CentOS major를 사용하므로 CentOS Linux 8도 같은 이유로 제외됨 |
| CentOS Linux 6/7 | OSV Red Hat | 기본 Red Hat feed의 매핑 경로 존재 | CentOS major ≤7 → RHEL major | RHSA CVSS fallback | 코드 경로만 확인; 이번 실이미지 검증 대상 아님. `internal/match/sbom.go:361` |
| Ubuntu | 유지되는 OSV Ubuntu 전체 export (`--add-ecosystem Ubuntu`) | 선택; defaults에 추가 후 저장 선택 보존 확인 | 릴리스별 feed 선택도 base `Ubuntu`로 통합; 24.04/22.04 LTS 매칭 | ubuntu_priority → priority → record Ubuntu severity → fallback | 전체 **701,433,255 bytes / 66,936 records**, data through **2026-09-17**, freshness 경고 0. 24.04/22.04 CVE **58/96**, 기존 stale 오탐 **27** 제거·누락 **32** 복원. Trivy 전용 0, bscan 전용 110 = Ignored 27 + Needs evaluation 81 + Jammy glibc CVE-2026-19499 오탐 2. USN의 release별 cves_map 미반영과 UNKNOWN finding 2개는 남음. `internal/vulndb/selection.go:125`, `internal/vulndb/osv.go:334`, `internal/match/cache.go:294`, `internal/match/severity.go:207`, `cmd/bscan/db.go:276`, `:350` |
| Debian | OSV + Debian security tracker | 기본 | 코드명 → 숫자 major, 예: bookworm → 12 | release/package urgency, 이후 CVSS fallback | not-affected 억제, undetermined는 낮은 confidence. `internal/vulndb/debian.go:15`, `internal/match/cache.go:235`, `internal/match/match.go:228` |
| Alpine | OSV + Alpine secdb | 기본 | `3.20.10` → `v3.20` | vendor 메타데이터가 있으면 우선, 이후 CVSS | native secdb 기본 선택 v3.18–v3.22; OSV 내 coverage는 그보다 넓을 수 있음. `internal/vulndb/source.go:62`, `internal/match/sbom.go:382` |
| Wolfi | OSV Wolfi export | **기본** | rolling, 빈 release | vendor 메타데이터 / CVSS fallback | 이번 코드에서는 opt-in이 아님. `internal/vulndb/source.go:57`, `internal/vulndb/model.go:189`. ZIP **269,974,046 bytes (257.5 MiB)** |
| Chainguard | OSV Chainguard export | 전용 feed는 선택 | rolling, 빈 release | vendor 메타데이터 / CVSS fallback | ZIP **920,476,046 bytes (877.8 MiB)**, 기본 1 GiB 제한 이내. 다른 기본 feed에 포함된 교차 ecosystem 레코드는 기본 DB에도 나타날 수 있으므로 `db status`의 ecosystem 나열을 전용 feed 선택과 혼동하지 말 것. `internal/vulndb/source.go:43` |
| openSUSE / SUSE | OSV 해당 ecosystem | 선택 | Leap `15.6` → `Leap 15.6`; Tumbleweed; SLES `15.5` → `Linux Enterprise Server 15 SP5` | vendor 메타데이터 / CVSS fallback | 코드 경로만 확인, 이번 실이미지 검증 대상 아님. `internal/vulndb/model.go:219`, `internal/match/sbom.go:345` |
| Fedora / Amazon Linux / Oracle Linux / Photon | 전용 OS 매칭 공급원 없음 | 미지원 | RPM namespace를 다른 배포판으로 대체하지 않음 | 없음 | `internal/vulndb/model.go:225`. RPM 인벤토리가 있어도 해당 배포판 advisory coverage를 뜻하지 않음 |
| npm, PyPI, Go, crates.io, Maven, RubyGems, NuGet, Packagist | OSV | 기본 | 언어 ecosystem/name/version | OSV CVSS / 해당 advisory 메타데이터 | 기본 목록 `internal/vulndb/source.go:58`; PURL type 매핑 `internal/vulndb/model.go:195`. RPM/dpkg/APK 소유 언어 metadata는 SBOM `bscan:owner`를 유지하고 `distro-owned`로 매칭 제외(이번 RPM 표본 **55개**); `internal/scan/ownership.go:105`, `internal/match/match.go:328`. PyPI 이름의 `-_.` 정규화: `internal/vulndb/model.go:154` |
| RubyGems 추가 공급원 | RubySec | 기본 | gem 이름/version | 공급된 등급, 없으면 UNKNOWN 가능 | `internal/vulndb/source.go:64`, `internal/vulndb/rubysec.go`. OSV와 별개 공급원 |
| 언어 ecosystem 추가 공급원 | GHSA reviewed advisory database | 선택 (`--add-source ghsa`) | OSV 형태의 package/range | advisory 등급 / CVSS | 전체 저장소 archive에서 reviewed 항목 변환. `internal/vulndb/osv.go:364`; 기본 제외 `internal/vulndb/source.go:64` |
| NVD / CPE | NVD | DB 선택 + 매칭 선택 | CPE vendor/product/applicability | NVD CVSS | `--add-source nvd`와 스캔/매칭 `--cpe`는 별개. `internal/vulndb/selection.go:61`, `cmd/bscan/scanmatch.go:30`, `internal/match/match.go:279` |

Ubuntu를 포함해 기본 정책은 `distro`이며 vendor 등급이 없으면 CVSS로 돌아간다. `negligible`과 `unimportant`는 `NEGLIGIBLE`로 표현하고 기본적으로 포함한다. `--exclude-unimportant`로 제외한다 (`internal/match/severity.go:110`, `cmd/bscan/scanmatch.go:35`, `internal/match/match.go:241`). 따라서 `distro_severity`가 채워져 있어도 Red Hat 원문 등급이 있었다는 뜻은 아니다.

`db update --add-ecosystem`은 설치된 selection을 기초로 항목을 추가한다 (`cmd/bscan/db_selection.go:34`, `:67`). 카탈로그 A에서 defaults 14 ecosystems + `Ubuntu` 1개 추가를 검증했고 sources 4개·Alpine releases 5개가 보존됐다. B는 defaults + redhat-vex로 검증했다. `--ecosystem`은 선택을 교체하는 옵션이며 `default` 확장을 지원한다. 출력의 `Ecosystems`는 적재된 레코드의 내용, `Selection`은 선택한 feed 목록이다 (`cmd/bscan/db.go:254`, `internal/vulndb/selection.go:39`).

실제 OSV endpoint에 HTTP HEAD를 요청해 얻은 압축 크기다. MiB = 1,048,576 bytes. 날짜가 오래된 Ubuntu 릴리스별 export에 특히 유의해야 한다.

| OSV export | bytes | MiB | HTTP Last-Modified (UTC) |
|---|---:|---:|---|
| Ubuntu 전체 | 701,433,255 | 668.9 | 2026-09-17 08:10:35 |
| Ubuntu:24.04:LTS (동결; 선택 시 Ubuntu로 통합) | 142,361,968 | 135.8 | 2024-10-08 19:12:19 |
| Ubuntu:22.04:LTS (동결; 선택 시 Ubuntu로 통합) | 149,860,571 | 142.9 | 2024-10-09 02:28:02 |
| Wolfi | 269,974,046 | 257.5 | 2026-09-17 11:22:44 |
| Chainguard | 920,476,046 | 877.8 | 2026-09-17 11:23:55 |
| Red Hat | 26,411,461 | 25.2 | 2026-09-17 10:50:49 |
| Rocky Linux | 4,860,973 | 4.6 | 2026-09-17 06:33:39 |
| AlmaLinux | 6,275,299 | 6.0 | 2026-09-17 12:18:40 |

기본 개별 feed 다운로드 제한은 1 GiB, 압축 해제 누적 제한은 32 GiB다 (`internal/vulndb/source.go:43`, `internal/vulndb/options.go:11`). 전체 Ubuntu와 Chainguard도 기본 제한 안에 들어온다. 릴리스별 export 이름은 항상 base export로 대체되며, 각 feed의 최신 레코드 시각이 `db status`에 `data through`로 표시되고 60일을 넘으면 경고한다. Round 7b의 세 갱신은 각 **157.64 / 348.45 / 402.45초**, peak RSS **731,096 / 1,526,104 / 1,504,664 KiB**, DB 디렉터리 **3,427,343,574 / 6,656,173,070 / 5,540,126,568 bytes**였다. VEX archive는 **317,099,481 bytes**, data through **2026-09-13**. 문서당 **64 MiB** 제한 때문에 CVE-2023-39325(75,392,762 bytes)·CVE-2026-33186(106,439,641 bytes) 2개를 건너뛰었다(`internal/vulndb/osv.go:23`, `internal/vulndb/redhat_vex.go:192`); 이번 7개 이미지 차집합에는 영향 없음. URL·헤더 측정값은 Round 7b 상세 JSON `feed_sizes`에 보존했다. export URL 생성 규칙은 `internal/vulndb/osv.go:353`이다. 크기 및 upstream 갱신 여부는 시간이 지나면 달라진다.
