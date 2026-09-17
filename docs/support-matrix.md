# 배포판·취약점 공급원 지원 표

현재 동작은 2026-09-18 검토 시작 시 HEAD인
`24a6de6864f606b00101f75dcd7d7a42327666b1`의 코드 기준이다.
인벤토리 수집 가능 여부와 취약점 매칭 지원은 다르다. 표의 기본 선택은
[공급원 기본값](../internal/vulndb/source.go), ecosystem 매핑은
[카탈로그 모델](../internal/vulndb/model.go), 릴리스 매핑은
[SBOM 해석 코드](../internal/match/sbom.go)를 기준으로 한다.
VEX 상태·tombstone 상한 설명은 같은 날 병행 수정된 작업 트리 코드도 반영했다.

## 현재 지원 상태

| 배포판 / ecosystem | 공급원과 선택 | 릴리스 매핑 | 심각도와 제한 |
| --- | --- | --- | --- |
| RHEL / UBI / Red Hat | OSV Red Hat 기본; `--add-source redhat-vex` 선택 시 해당 OSV feed를 대체하되 저장된 선택은 유지 | 9까지 major, 10부터 major.minor; 10+에서 minor가 없으면 `release-unknown`. EUS/AUS/E4S/TUS/ELS 등은 별도 제품 키 | Red Hat 제품 impact/aggregate 등급은 VEX 경로에서 제공한다. OSV Red Hat 경로는 그 VEX 등급을 제공하지 않으며 사용 가능한 CVSS로 fallback한다. 모듈/비모듈 빌드를 구분하지만 OSV의 모듈 이름·스트림 식별에는 한계가 있다. |
| Rocky Linux | OSV RLSA 기본 | `rocky-9.3` → `9` | erratum 텍스트 등급 우선, 없으면 CVSS. 다중 CVE advisory는 단일 CVE로 임의 분해하지 않는다. |
| AlmaLinux | OSV ALSA 기본 | `alma`/`almalinux` namespace, major 키 | Moderate/Important 제목 등급 → MEDIUM/HIGH. ALSA/ALBA/ALEA에 CVE alias가 없으면 related CVE를 alias로 승격한다. |
| CentOS 8+ / Stream | RHEL 매칭 미지원 | `centos-stream:N` | `centos-stream-unsupported`. 이름에 Stream이 없는 CentOS Linux 8도 제외된다. |
| CentOS Linux 6/7 | 기본 OSV Red Hat 경로 | RHEL major | OSV 경로의 CVSS fallback. 인벤토리만으로 advisory coverage를 보장하지 않는다. |
| Ubuntu | `--add-ecosystem Ubuntu` 선택 | release-qualified 선택도 유지되는 base `Ubuntu` export로 통합. LTS/Pro는 같은 숫자 release, FIPS는 분리 | USN affected-entry별 `cves_map`의 CVE·등급을 지원한다. 해당 범위의 Ubuntu 등급, `ubuntu_priority`, `priority`, record Ubuntu 등급 순으로 적용하며 usable 등급이 없으면 fallback한다. |
| Debian | OSV + Debian tracker 기본 | 코드명 → 숫자 release, 예: bookworm → 12 | package/release urgency 우선. not-affected 억제, undetermined는 낮은 confidence. |
| Alpine | OSV + Alpine secdb 기본 | `3.20.10` → `v3.20` | secdb 기본 선택 v3.18–v3.22. OSV 레코드의 coverage는 별개이며 vendor 등급이 없으면 CVSS로 fallback한다. |
| Wolfi | OSV 기본 | rolling, 빈 release | advisory 메타데이터 / CVSS fallback. |
| Chainguard | 전용 OSV feed 선택 | rolling, 빈 release | 다른 기본 feed의 교차 ecosystem 레코드가 나타날 수 있다. `Ecosystems` 출력은 전용 feed 선택을 의미하지 않는다. |
| openSUSE / SUSE | OSV 해당 ecosystem 선택 | Leap `15.6` → `Leap 15.6`; Tumbleweed; SLES `15.5` → `Linux Enterprise Server 15 SP5` | vendor 메타데이터 / CVSS fallback. 실제 coverage는 선택한 feed에 의존한다. |
| Fedora / Amazon Linux / Oracle Linux / Photon | 전용 OS 매칭 경로 없음 | 다른 배포판 advisory로 대체하지 않음 | RPM 인벤토리 수집과 해당 배포판 취약점 지원은 별개다. |
| npm, PyPI, Go, crates.io, Maven, RubyGems, NuGet, Packagist | OSV 기본 | ecosystem/name/version | OSV CVSS / advisory 메타데이터. PyPI `-_.` 이름 정규화 지원. 소유 OS 패키지가 없거나 매칭 불가능하면 언어 매칭을 유지한다. |
| RubyGems 추가 공급원 | RubySec 기본 | gem 이름/version | 복잡하거나 누락된 patch 조건은 무리하게 범위로 추정하지 않고 `no-usable-range`로 집계한다. |
| 언어 advisory 추가 공급원 | GHSA reviewed database 선택 | OSV package/range | 전체 저장소 archive에서 reviewed 항목을 변환한다. |
| NVD / CPE | `--add-source nvd` + 매칭 `--cpe` 별도 선택 | vendor/product/applicability | NVD CVSS. AND/negated/불확실한 platform 조건 등은 제외하며 일반 범위 매칭은 낮은 confidence다. |

기본 심각도 정책은 `distro`이며 vendor 등급이 없으면 CVSS를 사용한다.
`negligible`/`unimportant`는 `NEGLIGIBLE`로 기본 포함하고
`--exclude-unimportant`로 제외한다. [심각도 정책](severity-policy.md)은
Ubuntu 범위별 등급 우선순위와 Red Hat 상태를 자세히 설명한다.

RPM/dpkg/APK 소유 언어 metadata는 SBOM에 남는다. 소유 OS 패키지가 같은
SBOM에 있고 매칭 가능할 때만 언어 매칭을 `distro-owned`로 제외한다.
소유 패키지가 없거나 지원 ecosystem/release·coverage·버전 조건을 충족하지
못하면 `owner-unmatched`로 집계하면서 언어 매칭을 진행한다.
불완전하거나 충돌한 소유 정보도 언어 매칭을 막지 않는다.
[필드 및 skip 조건](findings-json.md#skipped-reason-vocabulary)을 참조한다.

## Feed 선택과 VEX 갱신

`--add-ecosystem` 등은 유효 선택을 확장하고 `--ecosystem` 등은 해당 목록을
교체한다. `db status`의 `Selection:`은 선택한 feed, `Ecosystems`는 적재된
레코드의 범위다. Ubuntu 릴리스별 export 선택은 base `Ubuntu`로 통합하며,
LTS/Pro/FIPS의 advisory 식별 정보는 매칭을 위해 보존한다.
[DB 가이드](vulnerability-database.md#selection-and-updates)를 참조한다.

VEX는 주간 archive에 `changes.csv`의 최신 문서와 `deletions.csv`를 적용한다.
삭제는 VEX의 기여만 제거하며 다른 공급원은 유지한다. VEX-only 삭제는 빈
withdrawn stub으로 남고 package index에서 제외된다. 삭제 tombstone은 새
archive에도 보존되며 더 최신 tracking date로 재등록되거나 archive에서
사라질 때 해제된다. 동시 시각에서는 삭제, delta, archive 순으로 우선한다.

기본 제한은 feed 다운로드 1 GiB, OSV/GHSA/VEX archive 확장 32 GiB다.
VEX 문서 상한은 **256 MiB**, 변경/삭제 목록은 각각 16 MiB이며, delta는
4개 worker, 실행당 20,000 document events와 2 GiB 쓰기 예산으로 처리한다.
예산을 넘는 잔여 작업은 다음 갱신에서 재개한다. Tombstone은 200,000개까지
보관하며 초과 시 오래된 항목을 제거하고 삭제 이력 불완전 경고를 남긴다. `db import`의 확장 상한은
이와 별개인 8 GiB다. [변환·삭제 상세](advisory-sources.md#red-hat-csaf-vex)와
[상태 필드](findings-json.md#catalog-metadata)를 참조한다.

## 역사적 측정 — 현재 지원 판정과 구분

다음은 2026-09-17, 측정 커밋
`1ddd44d77fe93f94d97091b0600bd6d6fed80de0`에서 기록된 관찰을 옮긴 것이다.
이 문서 정리에서는 외부 feed·이미지 비교를 재실행하지 않았다. 원본은
[배포판 검증](reviews/2026-09-17-accuracy-round7.md)과
[측정 JSON](reviews/2026-09-17-accuracy-round7b-details.json)에 있다.
과거 오탐·누락 수를 현재 코드의 수치로 읽으면 안 된다.

| 당시 표본 | 보관한 관찰 |
| --- | --- |
| UBI9 / UBI8 | OSV CVE 쌍 366/0, VEX 822/545; Trivy 전용 375/530 → 17/0. UBI9 공통 685/685 등급 일치. 잔여 17 중 16은 API Not affected, 1은 EVR 유실 위험으로 분류했다. archive coverage에서 expat 2쌍 누락, UBI8 모듈 라벨 없는 Python source 13쌍 추가를 기록했다. |
| AlmaLinux | 9 findings: MEDIUM 4, HIGH 5, UNKNOWN 0. 48 CVE 쌍에 Trivy 31쌍 포함. 추가 libevent 8 + FIPS provider 9; 후자는 advisory 전체 CVE가 binary에 전파되는 범위 문제로 기록했다. |
| CentOS 표본 | RPM 145개 `centos-stream-unsupported`, RPM 소유 Python 7개 `distro-owned`라는 당시 기록. 현재는 소유 패키지가 매칭 불가능하면 `owner-unmatched`로 fallback한다. |
| Ubuntu 24.04 / 22.04 | 전체 export 66,936 records, data through 2026-09-17, freshness 경고 0. CVE 58/96, stale 오탐 27 제거·누락 32 복원. Trivy 전용 0, bscan 전용 110 = Ignored 27 + Needs evaluation 81 + glibc 오탐 2. 당시 cves_map 미지원·UNKNOWN 2건 기록은 현재 지원 여부와 구분한다. |
| 소유권 / 선택 보존 | RPM 소유 언어 표본 55개. defaults 14 ecosystems에 Ubuntu를 추가하면서 sources 4개와 Alpine releases 5개를 보존; 별도 defaults + VEX 구성도 검사했다. |
| 세 catalog 갱신 | 157.64 / 348.45 / 402.45초; peak RSS 731,096 / 1,526,104 / 1,504,664 KiB; 디렉터리 3,427,343,574 / 6,656,173,070 / 5,540,126,568 bytes. |
| VEX archive | 317,099,481 bytes, data through 2026-09-13. 당시 64 MiB 문서 상한으로 CVE-2023-39325(75,392,762 bytes)와 CVE-2026-33186(106,439,641 bytes)를 건너뛰었으며 당시 7개 이미지 차집합에는 영향이 없다고 기록했다. 현재 상한은 256 MiB다. |

아래는 당시 HTTP HEAD에서 기록한 압축 크기다. MiB = 1,048,576 bytes.
현재 다운로드 크기나 upstream freshness를 보증하지 않는다.

| OSV export | bytes | MiB | HTTP Last-Modified (UTC) |
| --- | ---: | ---: | --- |
| Ubuntu 전체 | 701,433,255 | 668.9 | 2026-09-17 08:10:35 |
| Ubuntu:24.04:LTS (동결; 선택 시 Ubuntu로 통합) | 142,361,968 | 135.8 | 2024-10-08 19:12:19 |
| Ubuntu:22.04:LTS (동결; 선택 시 Ubuntu로 통합) | 149,860,571 | 142.9 | 2024-10-09 02:28:02 |
| Wolfi | 269,974,046 | 257.5 | 2026-09-17 11:22:44 |
| Chainguard | 920,476,046 | 877.8 | 2026-09-17 11:23:55 |
| Red Hat | 26,411,461 | 25.2 | 2026-09-17 10:50:49 |
| Rocky Linux | 4,860,973 | 4.6 | 2026-09-17 06:33:39 |
| AlmaLinux | 6,275,299 | 6.0 | 2026-09-17 12:18:40 |
