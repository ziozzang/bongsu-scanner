# 배포판·취약점 공급원 지원 표

2026-09-17, 커밋 `36bb5863e6ed6adb287505a5822489388778582b`의 코드와 실제 CLI/피드 조회 기준이다. 인벤토리 수집 가능 여부와 취약점 매칭 지원은 다르다. 기본 목록은 `internal/vulndb/source.go:56`, 기본 공급원은 같은 파일 `:67`, PURL 매핑은 `internal/vulndb/model.go:180`에서 확인했다. 실제 검증 결과는 [Round 7 보고서](reviews/2026-09-17-accuracy-round7.md)와 [상세 JSON](reviews/2026-09-17-accuracy-round7-details.json)에 있다.

| 배포판 / ecosystem | advisory 공급원 | 기본 / 선택 | 릴리스 매핑 | 심각도 출처 | 제한·주의와 코드 근거 |
|---|---|---|---|---|---|
| RHEL / UBI / Red Hat | OSV Red Hat; 선택형 CSAF VEX (`--add-source redhat-vex`) | OSV 기본, VEX opt-in; 동시 선택 시 OSV Red Hat feed 생략, 저장 선택 보존 | RHEL ≤9는 major, ≥10은 CPE major.minor 보존 | VEX 제품별 impact → aggregate Red Hat 등급; CVSS 독립 보존 | VEX는 CVE별 fixed 바이너리·미수정 소스 패키지·not-affected marker를 제공. EUS/AUS/E4S/TUS/ELS는 별도 릴리스. `.module+` 또는 VEX `modularity`가 있으면 모듈 라벨 subject에만 적용하며 개별 stream 일치는 검증하지 않음. 미수정 상태는 `distro_status` 표시. fixed 범위는 `[0,fixed)`이므로 설명문에만 있는 도입/비영향 버전은 추론하지 않음. `internal/vulndb/redhat_vex.go`, `internal/match/cache.go`, `internal/match/severity.go` |
| Rocky Linux | OSV RLSA | 기본 | `rocky-9.3` → `9` | erratum의 텍스트 등급 우선, 없으면 CVSS | `internal/match/sbom.go:367`, `internal/match/severity.go:227`. 하나의 advisory에 여러 CVE가 연결될 수 있음 |
| AlmaLinux | OSV ALSA | 기본 | `almalinux-9.8` → `9` | structured 등급/CVSS가 있으면 사용; 이번 8 findings는 모두 UNKNOWN | 원문 Moderate/Important는 summary에만 있어 미반영, CVE related 연결도 출력에서 유실. `internal/match/cache.go:288`, `internal/match/severity.go:227`. Rocky와 같은 major 규칙; PURL namespace `alma`, `almalinux`: `internal/vulndb/model.go:215` |
| CentOS Stream | 일반 RHEL feed로 대체하지 않음 | 미지원 | CentOS major ≥8 → `centos-stream:N` | 해당 OS 매칭 없음 | 정확한 skip reason: `centos-stream-unsupported`. `internal/match/sbom.go:361`, `internal/match/match.go:325`. 이 판별은 이름의 Stream 여부 대신 CentOS major를 사용하므로 CentOS Linux 8도 같은 이유로 제외됨 |
| CentOS Linux 6/7 | OSV Red Hat | 기본 Red Hat feed의 매핑 경로 존재 | CentOS major ≤7 → RHEL major | RHSA CVSS fallback | 코드 경로만 확인; 이번 실이미지 검증 대상 아님. `internal/match/sbom.go:361` |
| Ubuntu | 유지되는 OSV Ubuntu 전체 export (`--add-ecosystem Ubuntu`) | 선택 | `Ubuntu:24.04:LTS`, `Ubuntu:Pro:24.04:LTS`, `ubuntu-24.04`, `noble` → `24.04` | `affected.ecosystem_specific.ubuntu_priority` → `priority` → record의 `Ubuntu` severity 순; 이어 일반 fallback | `internal/vulndb/debian.go:32`, `internal/match/severity.go:207`. FIPS 등 알 수 없는 stream은 범위 유지. 릴리스별 ZIP은 **2024-10에 정지**하여 릴리스 선택도 전체 `Ubuntu`로 통합·저장. 전체 약 700 MB는 새 기본 제한 1 GiB 이내. `db status`의 `data through` 확인; 최신 레코드가 60일보다 오래되면 `--quiet`에서도 경고 |
| Debian | OSV + Debian security tracker | 기본 | 코드명 → 숫자 major, 예: bookworm → 12 | release/package urgency, 이후 CVSS fallback | not-affected 억제, undetermined는 낮은 confidence. `internal/vulndb/debian.go:15`, `internal/match/cache.go:235`, `internal/match/match.go:228` |
| Alpine | OSV + Alpine secdb | 기본 | `3.20.10` → `v3.20` | vendor 메타데이터가 있으면 우선, 이후 CVSS | native secdb 기본 선택 v3.18–v3.22; OSV 내 coverage는 그보다 넓을 수 있음. `internal/vulndb/source.go:62`, `internal/match/sbom.go:382` |
| Wolfi | OSV Wolfi export | **기본** | rolling, 빈 release | vendor 메타데이터 / CVSS fallback | 이번 코드에서는 opt-in이 아님. `internal/vulndb/source.go:57`, `internal/vulndb/model.go:189`. ZIP 약 257.3 MiB |
| Chainguard | OSV Chainguard export | 전용 feed는 선택 | rolling, 빈 release | vendor 메타데이터 / CVSS fallback | ZIP 약 877.7 MiB, 기본 1 GiB 제한 이내. 다른 기본 feed에 포함된 교차 ecosystem 레코드는 기본 DB에도 나타날 수 있으므로 `db status`의 ecosystem 나열을 전용 feed 선택과 혼동하지 말 것. `internal/vulndb/source.go:43`, `internal/vulndb/osv.go:101` |
| openSUSE / SUSE | OSV 해당 ecosystem | 선택 | Leap `15.6` → `Leap 15.6`; Tumbleweed; SLES `15.5` → `Linux Enterprise Server 15 SP5` | vendor 메타데이터 / CVSS fallback | 코드 경로만 확인, 이번 실이미지 검증 대상 아님. `internal/vulndb/model.go:219`, `internal/match/sbom.go:345` |
| Fedora / Amazon Linux / Oracle Linux / Photon | 전용 OS 매칭 공급원 없음 | 미지원 | RPM namespace를 다른 배포판으로 대체하지 않음 | 없음 | `internal/vulndb/model.go:225`. RPM 인벤토리가 있어도 해당 배포판 advisory coverage를 뜻하지 않음 |
| npm, PyPI, Go, crates.io, Maven, RubyGems, NuGet, Packagist | OSV | 기본 | 언어 ecosystem/name/version | OSV CVSS / 해당 advisory 메타데이터 | 기본 목록 `internal/vulndb/source.go:58`; PURL type 매핑 `internal/vulndb/model.go:195`. PyPI 이름의 `-_.` 정규화: 같은 파일 `:154` |
| RubyGems 추가 공급원 | RubySec | 기본 | gem 이름/version | 공급된 등급, 없으면 UNKNOWN 가능 | `internal/vulndb/source.go:64`, `internal/vulndb/rubysec.go`. OSV와 별개 공급원 |
| 언어 ecosystem 추가 공급원 | GHSA reviewed advisory database | 선택 (`--add-source ghsa`) | OSV 형태의 package/range | advisory 등급 / CVSS | 전체 저장소 archive에서 reviewed 항목 변환. `internal/vulndb/osv.go:364`; 기본 제외 `internal/vulndb/source.go:64` |
| NVD / CPE | NVD | DB 선택 + 매칭 선택 | CPE vendor/product/applicability | NVD CVSS | `--add-source nvd`와 스캔/매칭 `--cpe`는 별개. `internal/vulndb/selection.go:61`, `cmd/bscan/scanmatch.go:30`, `internal/match/match.go:279` |

Ubuntu를 포함해 기본 정책은 `distro`이며 vendor 등급이 없으면 CVSS로 돌아간다. `negligible`과 `unimportant`는 `NEGLIGIBLE`로 표현하고 기본적으로 포함한다. `--exclude-unimportant`로 제외한다 (`internal/match/severity.go:110`, `cmd/bscan/scanmatch.go:35`, `internal/match/match.go:241`). 따라서 `distro_severity`가 채워져 있어도 Red Hat 원문 등급이 있었다는 뜻은 아니다.

`db update --add-ecosystem`은 설치된 selection을 기초로 항목을 추가한다 (`cmd/bscan/db_selection.go:34`, `:67`). 새 카탈로그에서 실행한 기본 갱신과 Ubuntu 2개 항목 추가 갱신으로 검증했다. `--ecosystem`은 선택을 교체하는 옵션이며 `default` 확장을 지원한다. 출력의 `Ecosystems`는 적재된 레코드의 내용, `Selection`은 선택한 feed 목록이다 (`cmd/bscan/db.go:254`, `internal/vulndb/selection.go:39`).

실제 OSV endpoint에 HTTP HEAD를 요청해 얻은 압축 크기다. MiB = 1,048,576 bytes. 날짜가 오래된 Ubuntu 릴리스별 export에 특히 유의해야 한다.

| OSV export | bytes | MiB | HTTP Last-Modified (UTC) |
|---|---:|---:|---|
| Ubuntu 전체 | 701,433,255 | 668.9 | 2026-09-17 08:10:35 |
| Ubuntu:24.04:LTS (동결; 선택 시 Ubuntu로 통합) | 142,361,968 | 135.8 | 2024-10-08 19:12:19 |
| Ubuntu:22.04:LTS (동결; 선택 시 Ubuntu로 통합) | 149,860,571 | 142.9 | 2024-10-09 02:28:02 |
| Wolfi | 269,789,835 | 257.3 | 2026-09-17 04:35:28 |
| Chainguard | 920,288,558 | 877.7 | 2026-09-17 04:36:39 |
| Red Hat | 26,374,924 | 25.2 | 2026-09-17 10:33:59 |
| Rocky Linux | 4,860,973 | 4.6 | 2026-09-17 06:33:39 |
| AlmaLinux | 6,244,262 | 6.0 | 2026-09-16 14:07:32 |

기본 개별 feed 다운로드 제한은 1 GiB, 압축 해제 누적 제한은 32 GiB다 (`internal/vulndb/source.go:43`, `internal/vulndb/options.go:11`). 전체 Ubuntu와 Chainguard도 기본 제한 안에 들어온다. 릴리스별 export 이름은 항상 base export로 대체되며, 각 feed의 최신 레코드 시각이 `db status`에 `data through`로 표시되고 60일을 넘으면 경고한다. URL·헤더 측정값은 상세 JSON `feed_sizes`에 보존했다. export URL 생성 규칙은 `internal/vulndb/osv.go:348`이다. 크기 및 upstream 갱신 여부는 시간이 지나면 달라진다.
