bscan 배포판 coverage 정확도 실측 — Round 7, 2026-09-17

**핵심 결과:** Red Hat·Rocky·AlmaLinux 기본 적재, major 릴리스 정규화, EUS/AUS/E4S/TUS 분리, CentOS Stream OS 제외, `--add-ecosystem` 선택 보존, Ubuntu vendor priority·negligible 필터는 동작했다. 그러나 **Ubuntu 릴리스별 export가 2024년 자료로 정지**, **RHEL 미수정 CVE coverage 공백**, **AppStream 모듈 혼동**, **RPM으로 수정된 Python의 upstream 오탐**, **AlmaLinux CVE 연결·등급 유실**을 확인했다.

지원된 6개 이미지의 인벤토리 교집합은 **857/862(99.42%)**다. Trivy 인벤토리 중 빠진 5개는 bscan이 의도적으로 제외한 GPG 키 레코드다. 패키지별 CVE 교집합은 **735/1,672(43.96%)**, bscan 전용 **473**, Trivy 전용 **937**이다. AlmaLinux는 출력에서 빠진 CVE를 공식 errata로 복원한 비교치다. 전체 Ubuntu 피드로 바꾸면 교집합은 **767/1,672(45.87%)**, Trivy 전용은 RHEL의 **905**건만 남는다. 이 수치는 도구 간 일치율이며 실제 정밀도·재현율이 아니다. CentOS Stream은 미지원이므로 분모에서 제외했다.

전체 정규화 집합·차집합·개별 분류·원문 확인·메타데이터는 [상세 JSON](2026-09-17-accuracy-round7-details.json), 지원 정책은 [지원 표](../support-matrix.md)에 기록했다.

**실험 조건**

- 커밋 `36bb5863e6ed6adb287505a5822489388778582b`; Go 1.25.0 최소, 실제 Go 1.27.1. `go build -mod=readonly -o "$W/bscan" ./cmd/bscan`. 바이너리 SHA-256 `c8d6790ebc12404194e6919f512e8a16a1a335cb67fe9ce9acca5c1cdffec0bf`. 빌드 메타데이터는 **vcs.modified=true**였으므로 clean build라고 주장하지 않는다. 시작 시 `git status --short`는 비어 있었고 제품 코드는 수정하지 않았다; 이 메타데이터 차이의 원인은 확인하지 않았다.
- 최신 GitHub Linux amd64 binary: Trivy **0.74.0**, Grype **0.118.0**. Trivy DB **2026-09-17 07:06:17 UTC**, Grype DB **06:31:43 UTC**, 각 1회 갱신. Java DB는 이 표본에서 필요하지 않아 적재하지 않았다.
- `$W=/home/ziozzang/.cache/bongsu-work/work-R4`; TMPDIR, Go 모듈·빌드 캐시, 도구·SBOM·카탈로그 모두 여기 사용. `BONGSU_HOME=$W/home`; `init` 후 기본 갱신 및 추가 갱신. `db update -h`에 `--add-ecosystem`이 실제 있어 대체 명령은 불필요했다.
- PURL type·namespace·버전 기준, epoch qualifier 복원 후 `0:` 정규화. `rhel/redhat`, `alma/almalinux`, `rocky/rockylinux` namespace 동의어를 합쳤다. 파일·OS 메타 컴포넌트는 제외하고 위치 중복을 제거했다. generic binary 탐지는 별도 실제 인벤토리 항목으로 남겼다.
- CVE는 advisory 수와 다르다. bscan ID·related_ids·record.aliases, Grype 관련 CVE를 확장했다. **ALSA는 예외적으로 DB의 `related`를 공식 errata 6개와 전수 대조하여 복원**했다. 임의 OSV `related`를 모두 alias로 취급하지 않았다.

```text
bscan db update --no-keep-raw
bscan db update --add-ecosystem Ubuntu:24.04:LTS --add-ecosystem Ubuntu:22.04:LTS --no-keep-raw
BONGSU_OFFLINE=1 bscan scan --no-sign --match --format cyclonedx --output OUT docker://REPO@sha256:DIGEST
trivy image --cache-dir "$W/trivy-cache" --image-src docker --offline-scan \
  --skip-db-update --skip-java-db-update --skip-version-check --scanners vuln \
  --list-all-pkgs --format json --output OUT REPO@sha256:DIGEST
GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false grype docker:REPO@sha256:DIGEST -o json
# Grype CycloneDX도 출력하여 취약점 없는 패키지를 포함한 전체 인벤토리 확보
```

**카탈로그 갱신 — 설치 선택 전후**

| 측정 | 레코드 | wall 초 | 최대 RSS KiB | DB 디렉터리 bytes |
|---|---|---|---|---|
| defaults | 764,789 | 158.42 | 734,580 | 3,423,803,971 |
| add Ubuntu releases | 781,139 | 207.67 | 1,063,432 | 4,399,030,263 |
| supplement: current Ubuntu | 66,936 | 208.15 | 868,564 | 3,214,428,823 |

기본 OSV 선택 14개에 Red Hat·Rocky Linux·AlmaLinux·**Wolfi**가 포함됐다. 추가 후 16개가 됐고 기존 sources 4개와 Alpine release 5개가 보존됐다. 기본 적재량: Red Hat 22,971, Rocky 4,206, AlmaLinux 5,852 records. 추가 Ubuntu ZIP 두 개는 합계 **292,222,539 bytes**다. 표의 크기는 cache 포함 전체 DB 디렉터리이며 최종 기본+추가 SQLite 자체는 **3,962,454,016 bytes**다. `--no-keep-raw`도 변환 cache는 남긴다.

**After fixes 형식 — 인벤토리**

| 이미지 | 실제 OS | bscan | Trivy | 공통 | bscan만 | Trivy만 | Grype |
|---|---|---|---|---|---|---|---|
| ubi9 | redhat 9.4 | 206 | 184 | 182 | 24 | 2 | 202 |
| ubi8 | redhat 8.10 | 207 | 185 | 183 | 24 | 2 | 205 |
| rocky9 | rocky 9.3 | 150 | 141 | 141 | 9 | 0 | 144 |
| alma9 | alma 9.8 | 171 | 159 | 158 | 13 | 1 | 166 |
| ubuntu24 | ubuntu 24.04 | 96 | 92 | 92 | 4 | 0 | 92 |
| ubuntu22 | ubuntu 22.04 | 105 | 101 | 101 | 4 | 0 | 101 |
| centos9 | centos-stream 9 | 158 | 미지원 | — | — | — | 152 |

지원 6개에서 버전 집합 불일치는 **0**이다. bscan 추가 78개는 binary fingerprint generic 30개 + 설치 Python metadata 48개다. 예: UBI9 `generic/glibc@2.34`, `generic/openssl@3.0.7`, `generic/python@3.9.18`; Python은 `idna@2.10`, `requests@2.25.1`, `urllib3@1.26.5`. 후자 48개는 Grype도 수집했다. Trivy는 distro 소유 Python을 인벤토리에서 제외했다.

Trivy 전용 5개는 GPG 키: UBI9 `gpg-pubkey@5a6340b3-6229229e`, `@fd431d51-4ae0493b`, UBI8 `@d4082792-5b32db75`, `@fd431d51-4ae0493b`, Alma `@b86b3716-61e69f29`. bscan의 명시적 제외는 `internal/scan/rpm.go:167`이다. 이를 설치 소프트웨어 cataloger 결함으로 세지 않는다. generic 경로는 `internal/scan/binaryclass.go:106`, Python 경로는 `internal/scan/catalog.go:1035`다.

**After fixes 형식 — 패키지별 CVE**

| 이미지 | raw bscan findings | bscan CVE | Trivy CVE | 공통 | bscan만 | Trivy만 | 공통 심각도 차이 |
|---|---|---|---|---|---|---|---|
| ubi9 | 198 | 376 | 702 | 327 | 49 | 375 | 169 |
| ubi8 | 151 | 369 | 530 | 0 | 369 | 530 | 0 |
| rocky9 | 178 | 373 | 365 | 365 | 8 | 0 | 140 |
| alma9 | 8 | 40 | 31 | 31 | 9 | 0 | 31 |
| ubuntu24 | 6 | 6 | 11 | 0 | 6 | 11 | 0 |
| ubuntu22 | 44 | 44 | 33 | 12 | 32 | 21 | 0 |
| centos9 | 0 | 0 | 미지원 | 0 | 0 | 0 | 0 |

AlmaLinux의 raw 8 findings는 **출력 ID/alias만으로는 CVE 0개**, 공식 errata로 확장하면 **40개**다. Trivy의 31개를 모두 포함하며 추가 9개는 `openssl-fips-provider`다. 8개 모두 UNKNOWN이고 공통 31개 모두 Trivy 등급과 다르다. 이 연결 보정을 하지 않으면 “AlmaLinux 전부 탐지 누락”이라는 잘못된 결론이 된다.

**영향도순 결함과 원인**

| ID / 우선순위 | 분류 | 실측과 판정 | 근본 원인 / file:line |
|---|---|---|---|
| R7-1 / P0 | c: feed coverage | Ubuntu 적재 레코드 최종 modified 2024-10-08. Trivy 전용 32건 전부 누락, 오래된 오탐 27건. 전체 feed로 둘 다 해소. | `internal/vulndb/osv.go:348` 선택 문자열을 그대로 export URL로 사용; `internal/match/match.go:291`도 오래된 릴리스 endpoint를 권장. `cmd/bscan/db.go:273`은 fetched 시각만 표시 |
| R7-2 / P1 | c: feed coverage | RHEL Trivy 전용 905건은 모두 수정 버전 없음. 756 affected, 105 will_not_fix, 32 under_investigation, 12 end_of_life. 모든 건을 확정 취약점이라고 주장하지 않음. | `internal/vulndb/source.go:56`, `internal/vulndb/osv.go:319`: RHSA export만 적재, Red Hat CVE package_state 공급원 없음 |
| R7-3 / P1 | e + b: module/source 범위 | UBI8 비모듈 Python RPM 6개에서 131 findings → 349 CVE 쌍. 모듈 수정 build를 일반 RPM에 적용. 3 CVE 원문으로 오매핑 확인. | `internal/scan/rpm.go:38`, `:140`에 module label 없음; `internal/match/match.go:350` source-name 조회; `internal/vulndb/redhat.go:12` mainline 제품을 major로 축약 |
| R7-4 / P1 | a + b: distro 소유권 | UBI의 PyPI 전용 38 CVE 쌍. 최소 idna/requests/urllib3 3건은 설치 RPM changelog에 보안 수정이 있어 upstream 버전 경고가 오탐. | `internal/scan/catalog.go:1048` RPM 소유·backport와 분리된 PyPI 항목 생성; `internal/match/match.go:350` 언어 PURL 버전으로 매칭 |
| R7-5 / P1 | b + c: Alma 메타데이터 | 8 findings의 CVE 40쌍 연결이 출력에서 빠지고 8건 모두 UNKNOWN. 원문 6개 errata는 Moderate/Important를 제공. | `internal/vulndb/osv.go:88` aliases/upstream과 related 분리; `internal/match/cache.go:288`은 ID+Aliases만 출력; `internal/match/severity.go:227`은 structured label/CVSS가 없는 Alma summary 등급을 읽지 않음 |
| R7-6 / P2, 판정 보류 | b: source/binary/branch 범위 | UBI9 전용 RPM 31건 + Alma FIPS provider 9건. advisory 전체 CVE를 source/binary에 전파하는 범위 차이. fixed package는 원문과 일치하나 개별 binary 영향 판정은 보류. | `internal/match/match.go:350`, `internal/match/cache.go:288`; upstream feed가 introduced=0인 넓은 범위를 제공 |

EUS/AUS/E4S/TUS 분리가 AppStream의 python27/python38/python39 모듈 선택까지 해결하는 것은 아니다. R7-3의 349건은 모두 잘못된 module 범위의 경고라는 증거가 있으나, 각 CVE의 실제 exploit 가능성을 전수 재현한 숫자는 아니다. RPM EVR 비교 함수 자체의 순서 오류는 이번 표본에서 입증하지 못했다.

**차이 유형별 전수 분류와 구체적 예**

- **a/b: RPM 소유 Python upstream 경고 38건:** `ubi9 / pypi/idna@2.10 | CVE-2024-3651`; `ubi9 / pypi/idna@2.10 | CVE-2026-45409`; `ubi9 / pypi/requests@2.25.1 | CVE-2023-32681`.
- **b: advisory binary/branch 범위 40건:** `ubi9 / rpm/redhat/glibc-common@2.34-100.el9_4.4 | CVE-2025-15281`; `ubi9 / rpm/redhat/glibc-common@2.34-100.el9_4.4 | CVE-2026-0861`; `ubi9 / rpm/redhat/glibc-common@2.34-100.el9_4.4 | CVE-2026-0915`.
- **c: RHEL 미수정 상태 coverage 905건:** `ubi9 / rpm/redhat/bzip2-libs@1.0.8-8.el9 | CVE-2026-42250`; `ubi9 / rpm/redhat/coreutils-single@8.32-35.el9 | CVE-2026-56391`; `ubi9 / rpm/redhat/curl-minimal@7.76.1-29.el9_4.1 | CVE-2024-11053`.
- **e/b: AppStream 모듈 혼동 349건:** `ubi8 / rpm/redhat/python3-chardet@3.0.4-7.el8 | CVE-2007-4559`; `ubi8 / rpm/redhat/python3-chardet@3.0.4-7.el8 | CVE-2015-20107`; `ubi8 / rpm/redhat/python3-chardet@3.0.4-7.el8 | CVE-2018-18074`.
- **c/f: Rocky 공급원 적재 차이 8건:** `rocky9 / rpm/rocky/libevent@2.1.12-6.el9 | CVE-2026-63379`; `rocky9 / rpm/rocky/libevent@2.1.12-6.el9 | CVE-2026-63381`; `rocky9 / rpm/rocky/libevent@2.1.12-6.el9 | CVE-2026-63382`.
- **c: Ubuntu Ignored 정책 차이 11건:** `ubuntu24 / deb/ubuntu/coreutils@9.4-3ubuntu6.3 | CVE-2016-2781`; `ubuntu24 / deb/ubuntu/gpgv@2.4.4-2ubuntu17.6 | CVE-2022-3219`; `ubuntu24 / deb/ubuntu/libc-bin@2.39-0ubuntu8.9 | CVE-2016-20013`.
- **c: 오래된 Ubuntu 피드 오탐 27건:** `ubuntu24 / deb/ubuntu/libgcrypt20@1.10.3-2ubuntu0.2 | CVE-2024-2236`; `ubuntu24 / deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.15 | CVE-2024-41996`; `ubuntu22 / deb/ubuntu/gcc-12-base@12.3.0-1ubuntu1~22.04.3 | CVE-2023-4039`.
- **c: 오래된 Ubuntu 피드 누락 32건:** `ubuntu24 / deb/ubuntu/libc-bin@2.39-0ubuntu8.9 | CVE-2026-18374`; `ubuntu24 / deb/ubuntu/libsystemd0@255.4-1ubuntu8.17 | CVE-2026-40228`; `ubuntu24 / deb/ubuntu/login@1:4.13+dfsg1-4ubuntu3.2 | CVE-2024-56433`.

위 분류 합계는 bscan/Trivy 차집합 **1,410건(473+937)**이다. Grype까지 포함한 모든 쌍의 차이는 JSON에 별도 분류했다. 0건인 순수 EVR 비교 오류에는 사례를 만들지 않았다.

**원문·설치 증거 판정**

- RHEL 미수정 사례: [CVE-2026-42250](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-42250.json)의 bzip2, [CVE-2026-56391](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-56391.json)의 coreutils는 RHEL8/9 Fix deferred; [CVE-2024-11053](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-11053.json)의 curl은 Affected. RHSA fixed export만으로 이 상태를 재현할 수 없다.
- 모듈 사례: [CVE-2020-14343](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14343.json)은 PyYAML/python38 advisory인데 `python3-chardet@3.0.4-7.el8`에 매칭됐다. [CVE-2019-7164](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-7164.json)는 python27/python36 모듈, [CVE-2021-29921](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-29921.json)은 python38/python39 모듈 수정이다. 이미지의 chardet/pysocks/idna/requests/urllib3/six는 모두 `MODULARITYLABEL=(none)`이었다.
- RPM backport: UBI8 `python3-idna 2.5-8.el8_10`의 CVE-2024-3651, `python3-requests 2.20.0-6.el8_10`의 CVE-2023-32681, `python3-urllib3 1.24.2-10.el8_10`의 CVE-2023-43804는 `rpm -q --changelog`에 수정 기록이 있다. 각각의 PyPI 2.5/2.20.0/1.24.2 경고는 설치 빌드의 패치를 놓친다. 변경 이력 발췌는 JSON에 보존했다.
- Rocky libevent 8건: [공식 RESF OSV](https://storage.googleapis.com/resf-osv-data/RLSA-2026:67910.json)의 수정 버전 `0:2.1.13-1.el9_8`, CVE-2026-63379/63381/63382 등 8개 upstream ID를 확인했다. 설치 `2.1.12-6.el9`는 미수정이다. Grype도 보고한다. Trivy 누락은 공급원 적재 격차이며, 이번 Trivy DB 생성 07:06은 advisory 게시 06:06보다 늦어 단순 생성 시각 차이만으로 설명할 수 없다. [errata 페이지](https://errata.rockylinux.org/RLSA-2026:67910)는 JS shell만 반환해 공식 JSON으로 확인했다.
- Alma CVE 연결·등급: [coreutils ALSA-2026:66403](https://errata.almalinux.org/9/ALSA-2026-66403.html), [expat ALSA-2026:64812](https://errata.almalinux.org/9/ALSA-2026-64812.html), [glib2 ALSA-2026:64800](https://errata.almalinux.org/9/ALSA-2026-64800.html)를 포함한 6개 원문에서 CVE 목록을 전수 일치 확인했다. CVE-2026-56392, CVE-2026-50219/56132, CVE-2026-16118 등의 연결이 JSON에서 빠진다. 원문 등급 Moderate/Important는 bscan UNKNOWN과 다르다.
- Ubuntu 오래된 오탐 27건 전부: 현재 원문의 source package·release·상태를 연결하고 `dpkg --compare-versions`로 fixed version 이상임을 확인하거나 Not affected를 확인했다. 예: [libgcrypt20 / CVE-2024-2236](https://ubuntu.com/security/CVE-2024-2236)은 두 이미지 모두 설치 버전에서 수정; [gcc-12 / CVE-2023-4039](https://ubuntu.com/security/CVE-2023-4039)는 22.04 수정 버전 12.3.0-1ubuntu1~22.04.2 이상; [OpenSSL / CVE-2024-41996](https://ubuntu.com/security/CVE-2024-41996)는 Not affected다. 전체 목록은 `ubuntu_removed_checks`에 있다.
- 전체 feed에서도 bscan 전용으로 남는 기존 11건은 [coreutils / CVE-2016-2781](https://ubuntu.com/security/CVE-2016-2781), [gnupg2 / CVE-2022-3219](https://ubuntu.com/security/CVE-2022-3219), [glibc / CVE-2016-20013](https://ubuntu.com/security/CVE-2016-20013) 등 Ignored 정책 차이다. 이를 자동으로 bscan 오탐이나 Trivy 확정 누락이라고 세지 않았다.

**Ubuntu vendor priority — 20개 CVE 원문 대조**

| CVE | 패키지 예 | OSV ubuntu_priority | bscan Severity | ubuntu.com priority | 일치 |
|---|---|---|---|---|---|
| [CVE-2024-2236](https://ubuntu.com/security/CVE-2024-2236) | libgcrypt20 | medium | MEDIUM | Low | 아니오 |
| [CVE-2016-2781](https://ubuntu.com/security/CVE-2016-2781) | coreutils | low | LOW | Low | 예 |
| [CVE-2022-3219](https://ubuntu.com/security/CVE-2022-3219) | gpgv | low | LOW | Low | 예 |
| [CVE-2024-41996](https://ubuntu.com/security/CVE-2024-41996) | libssl3t64 | low | LOW | Low | 예 |
| [CVE-2016-20013](https://ubuntu.com/security/CVE-2016-20013) | libc-bin | negligible | NEGLIGIBLE | Negligible | 예 |
| [CVE-2023-4039](https://ubuntu.com/security/CVE-2023-4039) | gcc-12-base | medium | MEDIUM | Low | 아니오 |
| [CVE-2024-26462](https://ubuntu.com/security/CVE-2024-26462) | libgssapi-krb5-2 | medium | MEDIUM | Medium | 예 |
| [CVE-2023-31486](https://ubuntu.com/security/CVE-2023-31486) | perl-base | medium | MEDIUM | Medium | 예 |
| [CVE-2022-27943](https://ubuntu.com/security/CVE-2022-27943) | gcc-12-base | low | LOW | Low | 예 |
| [CVE-2024-26461](https://ubuntu.com/security/CVE-2024-26461) | libgssapi-krb5-2 | low | LOW | Low | 예 |
| [CVE-2023-45918](https://ubuntu.com/security/CVE-2023-45918) | libncurses6 | low | LOW | Low | 예 |
| [CVE-2023-50495](https://ubuntu.com/security/CVE-2023-50495) | libncurses6 | low | LOW | Low | 예 |
| [CVE-2022-41409](https://ubuntu.com/security/CVE-2022-41409) | libpcre2-8-0 | low | LOW | Low | 예 |
| [CVE-2023-7008](https://ubuntu.com/security/CVE-2023-7008) | libsystemd0 | low | LOW | Low | 예 |
| [CVE-2021-46848](https://ubuntu.com/security/CVE-2021-46848) | libtasn1-6 | low | LOW | Low | 예 |
| [CVE-2022-4899](https://ubuntu.com/security/CVE-2022-4899) | libzstd1 | low | LOW | Low | 예 |
| [CVE-2023-29383](https://ubuntu.com/security/CVE-2023-29383) | login | low | LOW | Low | 예 |
| [CVE-2024-26458](https://ubuntu.com/security/CVE-2024-26458) | libgssapi-krb5-2 | negligible | NEGLIGIBLE | Negligible | 예 |
| [CVE-2017-11164](https://ubuntu.com/security/CVE-2017-11164) | libpcre3 | negligible | NEGLIGIBLE | Negligible | 예 |
| [CVE-2023-47039](https://ubuntu.com/security/CVE-2023-47039) | perl-base | negligible | NEGLIGIBLE | Negligible | 예 |

20/20에서 bscan의 distro 값은 적재한 `ubuntu_priority`와 일치한다. 현재 Ubuntu 페이지와는 **18/20 일치**; CVE-2024-2236·CVE-2023-4039는 오래된 feed의 medium 대 현재 Low 차이다. 두 CVE는 전체 feed 사용 시 해당 설치 버전에서 경고 자체가 제거된다. 따라서 priority 추출 코드 오류와 feed 노후화를 구분해야 한다.

**`--exclude-unimportant` 전후 histogram — raw findings**

| 카탈로그 / 이미지 | HIGH | MEDIUM | LOW | NEGLIGIBLE | UNKNOWN | 총합 전 → 후 |
|---|---|---|---|---|---|---|
| 요청 릴리스 / ubuntu24 | 0 | 1 | 3 | 2 → 0 | 0 | 6 → 4 |
| 요청 릴리스 / ubuntu22 | 0 | 9 | 27 | 8 → 0 | 0 | 44 → 36 |
| 전체 feed / ubuntu24 | 0 | 51 | 6 | 2 → 0 | 0 | 59 → 57 |
| 전체 feed / ubuntu22 | 0 | 69 | 18 | 8 → 0 | 2 | 97 → 89 |

표의 다른 severity bucket은 전후 동일하다. 요청 카탈로그에서 제거된 10건은 glibc/CVE-2016-20013 4건, krb5/CVE-2024-26458 4건, pcre3/CVE-2017-11164 1건, perl/CVE-2023-47039 1건이다. 모두 `distro_severity=negligible`, `Severity=NEGLIGIBLE`였다. 전체 feed도 각각 negligible 2·8건만 제거했다. `unimportant`와 동등 처리하는 코드 및 회귀 테스트도 확인했다.

**RHEL CVSS 대 Red Hat 등급 — 12개 불일치 CVE**

| UBI9 패키지 | CVE | bscan CVSS-derived | Trivy | Red Hat 원문 |
|---|---|---|---|---|
| acl@2.3.1-4.el9 | [CVE-2026-54370](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-54370.json) | HIGH | MEDIUM | Moderate |
| curl-minimal@7.76.1-29.el9_4.1 | [CVE-2026-1965](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-1965.json) | HIGH | MEDIUM | Moderate |
| curl-minimal@7.76.1-29.el9_4.1 | [CVE-2026-3783](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-3783.json) | HIGH | MEDIUM | Moderate |
| expat@2.5.0-2.el9_4.1 | [CVE-2024-8176](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-8176.json) | HIGH | MEDIUM | Moderate |
| expat@2.5.0-2.el9_4.1 | [CVE-2025-59375](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-59375.json) | MEDIUM | HIGH | Important |
| glib2@2.68.4-14.el9_4.1 | [CVE-2024-52533](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-52533.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2025-13601](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-13601.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2025-4373](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-4373.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2026-15588](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-15588.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2026-16118](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-16118.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2026-58010](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-58010.json) | HIGH | MEDIUM | Moderate |
| glib2@2.68.4-14.el9_4.1 | [CVE-2026-58011](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-58011.json) | HIGH | MEDIUM | Moderate |

불일치 집합에서 고른 표본이므로 무작위 불일치율이 아니다. UBI9 공통 327건 중 169건이 다르다. UBI8은 공통 CVE가 0개여서 동일 CVE 심각도 비교가 성립하지 않는다. 두 UBI 모두 명시적 `--severity-source cvss`와 기본 결과의 severity가 완전히 같았다. RHSA 최종 DB 22,530개 레코드를 전수 읽어 record/affected의 vendor severity·urgency 필드가 모두 없음을 확인했다. RHSA DB severity type은 CVSS_V2 29, CVSS_V3 19,068, CVSS_V4 87 항목이며 별도 Red Hat rating 필드는 없었다. 여러 CVE가 한 RHSA의 최대 점수를 공유하는 영향도 있다.

**전체 Ubuntu 피드 보충 검증 — 코드 수정 없이**

`bscan db update --db "$W/ubuntu-current-db" --source osv --ecosystem Ubuntu --max-feed-bytes 1500000000 --no-keep-raw` 후 동일 SBOM을 오프라인 재매칭했다. 처음 요청한 카탈로그는 보존했다.

| 이미지 | bscan CVE: 릴리스 → 전체 | Trivy 공통: 전 → 후 | Trivy만: 전 → 후 | 오래된 경고 제거 | 새 CVE 쌍 | 전체 vs Grype 공통 |
|---|---|---|---|---|---|---|
| ubuntu24 | 6 → 58 | 0 → 11 | 11 → 0 | 2 | 54 | 58 |
| ubuntu22 | 44 → 96 | 12 → 33 | 21 → 0 | 25 | 77 | 94 |

전체 feed의 Ubuntu24 CVE 58건은 Grype와 완전히 같다. Ubuntu22는 Grype 94건을 모두 포함하고 glibc/CVE-2026-19499의 binary 2개를 추가 보고한다; 이 2개의 실제 영향 판정은 보류했다. 전체 feed에서도 Trivy보다 47/63건 많아 vendor Ignored·공급원 정책을 무시한 단순 일치율 해석은 부적절하다. raw findings가 CVE보다 각 1개 많은 것은 비-CVE advisory를 별도로 유지하기 때문이다.

**Grype 보조 비교**

| 이미지 | Grype CVE | bscan과 공통 | bscan만 | Grype만 | Trivy와 공통 |
|---|---|---|---|---|---|
| ubi9 | 804 | 354 | 22 | 450 | 681 |
| ubi8 | 511 | 0 | 369 | 511 | 509 |
| rocky9 | 933 | 371 | 2 | 562 | 363 |
| alma9 | 557 | 39 | 1 | 518 | 30 |
| ubuntu24 | 58 | 4 | 2 | 54 | 11 |
| ubuntu22 | 94 | 19 | 25 | 75 | 33 |
| centos9 | 495 | 0 | 0 | 495 | 0 |

Grype는 Rocky/Alma/CentOS에서도 Red Hat namespace에 근거한 CVE를 보고하므로 다른 공급원을 정답으로 삼을 수 없다. 예: Rocky `krb5-libs / CVE-2023-36054`, `CVE-2023-39975`, Alma `pam / CVE-2026-54411`은 bscan·Trivy에는 있으나 Grype에는 없다(합계 3건; 개별 vendor range 차이는 JSON에 기록, 실제 영향 추가 판정 보류). 반대로 Grype 전용 예: UBI9 `rpm/redhat/bzip2-libs@1.0.8-8.el9 | CVE-2026-42250`; UBI9 `rpm/redhat/coreutils-single@8.32-35.el9 | CVE-2026-56391`; UBI9 `rpm/redhat/curl-minimal@7.76.1-29.el9_4.1 | CVE-2024-11053` 등은 전체 개별 집합으로 보존했다. 모든 비교 쌍의 분류별 개수와 최대 3개 구체적 예는 JSON `comparison_class_summaries`에 있다. 개수가 3개 미만인 분류는 전부 열거했다.

**CentOS Stream 및 릴리스·스트림 검증**

CentOS Stream 9는 설치 RPM **145개 전부** `centos-stream-unsupported`, Red Hat finding **0**이었다. 전체 인벤토리 158개에는 Python 7개와 generic 6개도 있으므로 “모든 종류의 패키지가 같은 이유로 skip”은 정확하지 않다. generic 및 메타 subject는 unknown-ecosystem, Python은 독립된 PyPI 매칭 대상이며 finding이 없었다. Trivy도 unsupported os를 기록하고 inventory/results를 내지 않았다. Grype는 495 CVE 쌍을 보고했지만 이를 Stream 정답으로 판정하지 않았다.

UBI9의 RPM finding 180개는 `Red Hat:enterprise_linux:9::baseos` 175개 + appstream 5개, UBI8의 131개는 major 8 appstream이었다. **EUS/AUS/E4S/TUS finding 0**. DB 자체에는 각각 별도 lifecycle release 키가 남아 있으므로 피드를 버린 결과가 아니다. Rocky·Alma는 실제 9.3·9.8에서 release 9로 매칭됐다. `internal/vulndb/redhat.go:20`, `internal/match/cache.go:221`, `internal/match/sbom.go:361`와 관련 테스트로 확인했다.

**scan+match 성능**

| 이미지 | wall 초 | 최대 RSS KiB |
|---|---|---|
| ubi9 | 2.61 | 57,072 |
| ubi8 | 2.41 | 39,360 |
| rocky9 | 1.6 | 37,084 |
| alma9 | 1.73 | 44,324 |
| ubuntu24 | 0.81 | 37,764 |
| ubuntu22 | 0.8 | 38,040 |
| centos9 | 1.69 | 46,140 |

GNU `/usr/bin/time -v`로 scan+match 전체를 측정했다. image pull 시간은 제외하고 로컬 Docker image 읽기·파일 해시·SBOM 작성·매칭은 포함했다. 1회 실행값이며 cold-cache benchmark나 반복 평균은 아니다.

**고정 digest와 재현성**

| pull 태그 | RepoDigest sha256 |
|---|---|
| registry.access.redhat.com/ubi9/ubi:9.4 | `ee0b908e958a1822afc57e5d386d1ea128eebe492cb2e01b6903ee19c133ea75` |
| registry.access.redhat.com/ubi8/ubi:8.10 | `f62cf5375e9e17dbb719ab70d6ab3abfe83445a2ed31d46580b70ee2f0440617` |
| rockylinux:9 | `d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` |
| almalinux:9 | `3a3fa7f043b142bc8008c8b308d39b47d2c84008addcd52f9f9a7a82d2a90474` |
| ubuntu:24.04 | `69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9` |
| ubuntu:22.04 | `829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7` |
| quay.io/centos/centos:stream9 | `cfee9f59eb4d66295690829cebb75c6c97ca199c8929f8f933d88745280cbab4` |

모두 `docker pull --platform linux/amd64` 후 RepoDigest·amd64 image ID를 기록하고 동일 digest로 세 도구를 실행했다. `rockylinux:9`는 2023-11-28 빌드, 실제 Rocky 9.3이었다. 대상 태그를 최신 패치 상태로 일반화하지 않았다. API 첫 요청에서 일부 403이 발생해 동일 URL에 cache-busting query와 User-Agent로 재시도했고 원문 조회에 성공했다.

**검증 결과와 한계**

선택 회귀 테스트: `go test ./internal/match ./internal/vulndb ./cmd/bscan -run 'RedHat|RPMRelease|UbuntuPriority|DBSelection|DefaultRPM' -count=1` — **3개 패키지 통과**. 제품 코드·테스트·기존 보고서는 수정하지 않았다. 종료 점검에서 다른 작업의 새 문서 `docs/reviews/2026-09-17-round7-distro-coverage.md`가 관찰됐으며 건드리지 않았다. 버전 비교 자체의 새 오류나 EUS 혼입은 입증되지 않았다. AppStream 범위와 RPM backport 문제는 별개로 남는다. CVE exploit 전수 재현, 전체 테스트 suite, 다른 CPU architecture는 수행하지 않았다.

이번에 받은 Docker 이미지 **7개를 모두 `docker rmi`로 제거**하고 image ID가 존재하지 않음을 확인했다. 생성한 바이너리·DB·도구 캐시·SBOM·임시 스크립트도 모두 삭제했다. 작업 루트에는 시작 전부터 있던 sandbox mount용 디렉터리만 남겼다. 상세 JSON `cleanup`에 삭제 결과를 기록했다. 이 작업이 작성한 저장소 파일은 허용된 문서 3개뿐이다.
