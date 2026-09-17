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

## After fixes (round 7b)

**결과:** 기본+Ubuntu 카탈로그 A에서 기존 UBI8 모듈 오탐 **349쌍**, UBI의 RPM 소유 PyPI 경고 **38쌍**, Ubuntu stale 오탐 **27쌍·누락 32쌍**이 모두 제거·복원됐다. AlmaLinux는 수동 errata 확장 없이 **48 CVE 쌍**, **9 findings 모두 Moderate/Important에 대응하는 MEDIUM/HIGH**를 출력했다. 그러나 VEX 카탈로그 B에는 **모듈 범위가 없는 Python 소스 항목 13쌍**이 남으며, 그중 **5쌍은 기존 모듈 오탐 집합과 겹친다**. 따라서 “모듈 문제가 모든 공급원에서 해결됐다”는 결론은 부적절하다.

지원 6개 이미지에서 A는 **공통 767/1,672(45.87%), bscan만 174, Trivy만 905**다. UBI 두 개에만 B를 사용하면 **공통 1,655/1,672(98.98%), bscan만 287, Trivy만 17**이다. 17쌍 중 16쌍은 현재 Red Hat API의 Not affected와 Trivy가 충돌하며, 나머지 1쌍은 버전 한정 VEX 음성 marker의 범위 확대 문제다. 이 비율은 도구 일치율이며 정밀도·재현율이 아니다. 불확실·Ignored 상태를 확정 취약점으로 세지 않는다. [Round 7b 상세 JSON](2026-09-17-accuracy-round7b-details.json)에 이미지별 차집합 전수, 분류, 원문 판정, metadata와 성능을 저장했다.

**재현 조건·동시 작업**

- 측정 커밋 **`1ddd44d77fe93f94d97091b0600bd6d6fed80de0`**, Go **1.27.1**(최소 1.25.0), `go build -mod=readonly -o "$W/bscan" ./cmd/bscan`. `vcs.modified=false`, 바이너리 SHA-256 `f161a5a34232a1ee364b1f9417c7d92ce47908178bfe97a6d2a53391fa231275`.
- `$W=/home/ziozzang/.cache/bongsu-work/work-R14`. 임시 도구·Go build cache·DB·SBOM·스크립트·원문 모두 W 아래 사용. Docker 이미지는 아래 본문의 동일 digest 7개를 `--platform linux/amd64`로 pull했으며 image ID도 이전 측정과 일치했다. 태그로 갱신하지 않았다.
- 최신 GitHub release를 조회해 Trivy **0.74.0**, Grype **0.118.0**을 다운로드했다. DB는 각각 한 번만 갱신: Trivy **2026-09-17 07:06:17 UTC**, Grype **06:31:43 UTC**. 두 도구의 모든 이미지 CVE 집합은 이전 run과 완전히 동일했다.
- 본문의 PURL·epoch 정규화 및 ID/related_ids/aliases CVE 확장을 그대로 사용했다. AlmaLinux 예외 DB/errata 수동 확장은 **사용하지 않았다**. Grype는 이미지마다 한 번 호출해 JSON과 CycloneDX JSON을 동시에 출력했다. 이후 bscan offline, Trivy DB/Java DB/version update 비활성화·offline-scan, Grype DB/app update 및 외부 조회 비활성화 상태로 실행했다.
- **이 절과 지원 표의 file:line은 측정 커밋 `1ddd44d` 기준**이다. 측정 도중 다른 작업이 matcher/VEX/ownership 등의 소스·테스트를 변경했다. 재빌드하지 않았고 초기 source hash가 해당 커밋과 일치함을 확인했다. 이 검토가 제품 소스·테스트를 수정한 것은 아니다. 이후 작업 트리 수정의 효과는 이 수치에 포함되지 않는다.

**카탈로그 갱신**

| 갱신 | records | wall 초 | peak RSS KiB | DB 디렉터리 bytes |
| --- | --- | --- | --- | --- |
| A-default | 765,042 | 157.64 | 731,096 | 3,427,343,574 |
| A-ubuntu | 831,978 | 348.45 | 1,526,104 | 6,656,173,070 |
| B-vex | 748,909 | 402.45 | 1,504,664 | 5,540,126,568 |

A는 `BONGSU_HOME=$W/homeA bscan init` 후 `db update --no-keep-raw`, 이어 `db update --add-ecosystem Ubuntu --no-keep-raw`를 실행했다. 로그에 **`installed catalog + --add-ecosystem`**, 저장 metadata에 기존 sources 4개·Alpine releases 5개·OSV 선택 14개 보존 및 Ubuntu 추가를 확인했다. B는 새 `$W/homeB`에서 `db update --add-source redhat-vex --no-keep-raw`를 실행해 **`defaults + --add-source`**, **`skipping OSV Red Hat feed: redhat-vex supplies authoritative per-CVE data`**를 확인했다. B selection에 Red Hat 이름이 남아도 실제 OSV Red Hat URL은 sources metadata에 없다.

Ubuntu 전체 export는 **701,433,255 bytes(668.9 MiB), 66,936 records**로 기본 **1 GiB** 제한 안에서 성공했다. A 최종 records **831,978**, B **748,909**. A/B 최종 SQLite 자체 크기는 각각 **5,957,746,688 / 5,257,658,368 bytes다. 표의 크기는 변환 cache를 포함한 DB 디렉터리이며 `--no-keep-raw`는 변환 cache를 제거하지 않는다. conversion version **4**를 확인했다.

`db status`는 A **27개**, B **26개** feed 모두 `data through` 행을 표시했다. Ubuntu **2026-09-17**, VEX **2026-09-13**, OSV 나머지는 9월 15–17일이다. Alpine secdb 10개·Debian tracker·RubySec는 날짜가 공급되지 않아 **unknown**이다. 두 갱신/상태 출력에 freshness 경고는 **0건**이었다. unknown을 최신임의 증거로 해석하지 않는다.

VEX 최신 archive는 [csaf_vex_2026-09-13.tar.zst](https://security.access.redhat.com/data/csaf/v2/vex/csaf_vex_2026-09-13.tar.zst), **317,099,481 bytes**다. **42,230 records / 6,279,455 affected entries**, malformed **0**, non-RHEL **25,249**, oversized **2**를 기록했다. 스트리밍 tar 목록으로 oversized 문서를 식별했다: `CVE-2023-39325` **75,392,762 bytes**, `CVE-2026-33186` **106,439,641 bytes**. 다운로드 1 GiB·전체 해제 32 GiB와 별도로 **문서당 64 MiB** 제한이 적용된다 (`internal/vulndb/osv.go:23`, `internal/vulndb/redhat_vex.go:192`). 두 CVE는 이번 7개 이미지의 비교 도구 CVE 쌍에는 없어 측정 차집합의 원인은 아니다.

**인벤토리 — A, B의 UBI 인벤토리는 동일**

| 이미지 | bscan | Trivy | 공통 | bscan만 | Trivy만 | Grype |
| --- | --- | --- | --- | --- | --- | --- |
| ubi9 | 206 | 184 | 182 | 24 | 2 | 202 |
| ubi8 | 207 | 185 | 183 | 24 | 2 | 205 |
| rocky9 | 150 | 141 | 141 | 9 | 0 | 144 |
| alma9 | 171 | 159 | 158 | 13 | 1 | 166 |
| ubuntu24 | 96 | 92 | 92 | 4 | 0 | 92 |
| ubuntu22 | 105 | 101 | 101 | 4 | 0 | 101 |
| centos9 | 158 | 미지원 | — | — | — | 152 |

모든 도구의 정규화 인벤토리가 이전 run과 동일하다. 지원 6개 교집합 **857/862**, 버전 집합 불일치 **0**. 기존 generic 추가 30개·Trivy가 생략한 Python 48개·GPG 키 5개 제외 정책도 동일하다. 예: `generic/glibc@2.34`, `generic/openssl@3.0.7`, `generic/python@3.9.18`; Python `idna@2.10`, `requests@2.25.1`, `urllib3@1.26.5`; GPG `5a6340b3-6229229e`, `fd431d51-4ae0493b`, `d4082792-5b32db75`. 비교 도구의 정책 차이(a)이며 새 인벤토리 누락은 없다.

**패키지별 CVE — 괄호는 round 7 대비 증감**

| 이미지 / catalog | bscan CVE | Trivy | 공통 | bscan만 | Trivy만 | 공통 severity 집합 불일치 |
| --- | --- | --- | --- | --- | --- | --- |
| ubi9 / A | 366 (-10) | 702 | 327 (+0) | 39 (-10) | 375 (+0) | 169 |
| ubi9 / B | 822 (+446) | 702 | 685 (+358) | 137 (+88) | 17 (-358) | 0 |
| ubi8 / A | 0 (-369) | 530 | 0 (+0) | 0 (-369) | 530 (+0) | 0 |
| ubi8 / B | 545 (+176) | 530 | 530 (+530) | 15 (-354) | 0 (-530) | 0 |
| rocky9 / A | 373 (+0) | 365 | 365 (+0) | 8 (+0) | 0 (+0) | 0 |
| alma9 / A | 48 (+8) | 31 | 31 (+0) | 17 (+8) | 0 (+0) | 0 |
| ubuntu24 / A | 58 (+52) | 11 | 11 (+11) | 47 (+41) | 0 (-11) | 0 |
| ubuntu22 / A | 96 (+52) | 33 | 33 (+21) | 63 (+31) | 0 (-21) | 10 |
| centos9 / A | 0 (+0) | 미지원 | 0 (+0) | 0 (+0) | 0 (+0) | 0 |

B의 증감도 이전 기본 카탈로그와 비교했다. Alma 이전 **40**은 errata 수동 보정치였고, 당시 출력만으로는 **0**이었다. 지금은 출력만으로 **48**이며 기존 40쌍 전부를 포함한다. UBI9·Alma에 새로 추가된 각 **libevent 8쌍**은 upstream errata 갱신 효과이며 수정 코드만의 효과로 돌리지 않는다. Rocky는 기존과 동일한 libevent 8쌍이다. Rocky 공통 severity 불일치는 **140→0**, Alma는 **31→0**이다.

**필수 수정 검증 및 skip histogram**

| 이미지 / catalog | module-mismatch | distro-owned | centos-stream-unsupported | unknown-ecosystem | withdrawn | distro-not-affected |
| --- | --- | --- | --- | --- | --- | --- |
| ubi9 / A | 0 | 18 | 0 | 8 | 15 | 0 |
| ubi9 / B | 0 | 18 | 0 | 8 | 4 | 3 |
| ubi8 / A | 190 | 20 | 0 | 6 | 13 | 0 |
| ubi8 / B | 908 | 20 | 0 | 6 | 4 | 0 |
| rocky9 / A | 0 | 3 | 0 | 8 | 0 | 0 |
| alma9 / A | 0 | 7 | 0 | 8 | 0 | 0 |
| ubuntu24 / A | 0 | 0 | 0 | 6 | 134 | 0 |
| ubuntu22 / A | 0 | 0 | 0 | 6 | 174 | 0 |
| centos9 / A | 0 | 7 | 145 | 8 | 0 | 0 |

- UBI8 A는 raw finding **151→0**, 기존 잘못된 Python RPM module CVE **349→0**. `module-mismatch=190`은 제외한 affected 비교 횟수이며 CVE 수 349와 분모가 다르다. B는 `module-mismatch=908`이지만 아래 설명하는 라벨 없는 source 상태 13쌍이 통과한다. 기존 349 중 5쌍도 B에서 재등장한다.
- PyPI는 UBI9 **18**, UBI8 **20**, Rocky **3**, Alma **7**, CentOS **7**개가 모두 SBOM의 **`bscan:owner`**(RPM 이름/버전)를 유지한 채 `distro-owned`로 제외됐다. 총 **55개**, UBI만 **38개**. unowned PyPI는 이 표본에서 0개다. UBI의 기존 PyPI CVE 경고 38쌍은 A/B 모두 0이다. 예: UBI8 `idna@2.5 → rpm:python3-idna@2.5-8.el8_10`, `requests@2.20.0 → rpm:python3-requests@2.20.0-6.el8_10`, `urllib3@1.24.2 → rpm:python3-urllib3@1.24.2-10.el8_10`.
- Ubuntu24/22의 기존 stale 오탐 **2+25=27**은 모두 사라졌고, 누락 **11+21=32**는 모두 복원됐다. 전체 export 보충 실험과 지금의 CVE 집합은 완전히 같다. 남은 bscan 전용 **110쌍**은 **Ignored 27 + Needs evaluation 81 + 잘못된 릴리스 CVE 전파 2**로 전수 분류했다. 81쌍은 원문 미평가 상태인데 출력 `confidence=high`, `distro_status` 없음이므로 확정 취약점으로 해석하면 안 된다. OSV가 이 상태를 `[0,∞)`로 공급하며 상태 자체를 담지 않는 한계다.
- Alma **9 findings = HIGH 5 + MEDIUM 4**, UNKNOWN 0. 기존 8개에 libevent Important 1개가 추가됐다. [coreutils](https://errata.almalinux.org/9/ALSA-2026-66403.html), [expat](https://errata.almalinux.org/9/ALSA-2026-64812.html), [glib2](https://errata.almalinux.org/9/ALSA-2026-64800.html) 등 **7개 errata**의 CVE 목록과 Moderate/Important를 대조했다. CVE 출력 연결 및 title rating 수정이 동작한다 (`internal/vulndb/ingestion.go:181`, `internal/match/severity.go:254`).
- CentOS Stream은 RPM **145**개가 `centos-stream-unsupported`, Python **7**개는 `distro-owned`, 기타 subject 8개는 unknown이다. finding 0은 안전 판정이 아니다.

**VEX 미수정 상태 — 패키지/CVE 쌍 수**

| 이미지 | affected | fix-deferred | will-not-fix | under-investigation | out-of-support-scope | 합계 |
| --- | --- | --- | --- | --- | --- | --- |
| ubi9 | 115 | 338 | 11 | 17 | 2 | 483 |
| ubi8 | 74 | 391 | 47 | 19 | 14 | 545 |

UBI9 B의 822쌍 중 **483쌍**은 수정 버전이 없고, UBI8은 **545쌍 전부** 미수정이다. `affected`와 `fix-deferred`를 합치지 않았으며 `under-investigation`·`out-of-support-scope`는 실제 영향 확정과 구분했다. UBI9 공통 **685/685(100%)**, UBI8 **530/530**에서 Red Hat severity와 Trivy severity가 일치했다. UBI9 A는 공통 327 중 169개가 달랐다. 예: `acl/CVE-2026-54370`, `expat/CVE-2024-8176`, `glib2/CVE-2024-52533`은 A의 HIGH가 B에서 Red Hat Moderate에 해당하는 MEDIUM으로 바뀐다.

**남은 차이 전수 분류와 원문 판정**

분류 문자는 본문과 같다: a cataloger, b 이름·메타데이터, c 공급원·coverage, d 버전 비교, e 릴리스·모듈, f Trivy 오탐·누락. 아래 수치는 비교별로 별도 집계한다. A–Trivy 합계 **1,079쌍(174+905)**, B의 UBI–Trivy 합계 **169쌍(152+17)**. 3개 미만인 분류는 존재하는 모든 사례를 적었다. 순수 EVR 순서 비교 오류(d)는 입증되지 않았다.

- **c / A RHEL 미수정 coverage·정책 889쌍:** `ubi9 bzip2-libs@1.0.8-8.el9 / CVE-2026-42250`, `coreutils-single@8.32-35.el9 / CVE-2026-56391`, `curl-minimal@7.76.1-29.el9_4.1 / CVE-2024-11053`. [Red Hat API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-42250.json)의 Fix deferred/Affected 상태를 RHSA fixed 중심 OSV가 담지 못한다. A의 Trivy 전용 905 중 나머지 16쌍은 아래 f 분류의 공식 비영향 사례다. B가 이 coverage 공백을 대부분 채운다. 기본 source 목록은 `internal/vulndb/source.go:56`, VEX 대체 선택은 `internal/vulndb/redhat_vex.go:73`.
- **b / A binary·branch 범위 40쌍, B UBI 31쌍:** UBI9 RPM 31 + Alma FIPS 9(A). 예: `ubi9 openssl@1:3.0.7-28.el9_4 / CVE-2026-14456`, `alma9 openssl-fips-provider@1:3.5.5-6.el9_8 / CVE-2026-14457`, 같은 provider의 `CVE-2026-18798`. [CVE-2026-14456 Red Hat statement](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-14456.json)은 RHEL 9.8+ OpenSSL 3.5 QUIC server만 영향, 이전 branch와 FIPS module은 비영향이라고 명시한다. UBI9 openssl/openssl-libs 2쌍은 이 조건과 충돌한다. Alma provider 9개 CVE 원문도 모두 FIPS 밖의 코드라고 명시하지만 [ALSA-2026:67165](https://errata.almalinux.org/9/ALSA-2026-67165.html)의 전체 CVE가 provider에 전파된다. 나머지 glibc-common·vim-minimal 등 개별 binary 영향은 보류한다. 원인: source-name 확장 `internal/match/match.go:365`, 전체 aliases 출력 `internal/match/cache.go:294`, VEX의 `[0,fixed)`/`[0,∞)` 범위 `internal/vulndb/redhat_vex.go:424`, `:437`.
- **c/f / libevent 공급원 적재 차이 A 24쌍, B 8쌍:** `ubi9 libevent@2.1.12-8.el9_4 / CVE-2026-63379`, `rocky9 libevent@2.1.12-6.el9 / CVE-2026-63381`, `alma9 libevent@2.1.12-8.el9_4 / CVE-2026-63382`. [Rocky 공식 JSON](https://storage.googleapis.com/resf-osv-data/RLSA-2026:67910.json), [Alma errata](https://errata.almalinux.org/9/ALSA-2026-67910.html), [Red Hat API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-63379.json)의 CVE 8개·fixed `2.1.13-1.el9_8`과 일치하며 Trivy 누락으로 판정한다. B의 9/13 snapshot은 이 8개를 아직 affected/미수정으로 표시하므로 **탐지 여부는 맞지만 현재 fix 정보는 늦다**.
- **c / Ubuntu Ignored 27쌍:** `ubuntu24 coreutils@9.4-3ubuntu6.3 / CVE-2016-2781`, `gpgv@2.4.4-2ubuntu17.6 / CVE-2022-3219`, `libc-bin@2.39-0ubuntu8.9 / CVE-2016-20013`. [coreutils](https://ubuntu.com/security/CVE-2016-2781), [gnupg2](https://ubuntu.com/security/CVE-2022-3219), [glibc](https://ubuntu.com/security/CVE-2016-20013)의 Ignored와 일치하는 정책 차이이며 코드 부재를 뜻하지 않는다.
- **c / Ubuntu Needs evaluation 81쌍:** `ubuntu24 libc6@2.39-0ubuntu8.9 / CVE-2026-89092`, `libpcre2-8-0@10.42-4ubuntu2.1 / CVE-2026-89156`, `util-linux@2.39.3-9ubuntu6.6 / CVE-2026-78408`. [glibc](https://ubuntu.com/security/CVE-2026-89092), [pcre2](https://ubuntu.com/security/CVE-2026-89156), [util-linux](https://ubuntu.com/security/CVE-2026-78408) 모두 vendor 미평가다. Trivy 확정 누락 또는 bscan 확정 오탐으로 판정하지 않는다. OSV 상태 한계와 high confidence 출력의 결합이며 `internal/vulndb/osv.go:130`, `internal/match/match.go:264` 경로다.
- **b / Ubuntu 잘못된 release-CVE 전파 2쌍(전수):** `ubuntu22 libc-bin@2.35-0ubuntu3.14 / CVE-2026-19499`, `libc6@2.35-0ubuntu3.14 / CVE-2026-19499`. [Ubuntu 원문](https://ubuntu.com/security/CVE-2026-19499)은 Jammy Not affected. `USN-8737-1`의 전체 alias에는 이 CVE가 있지만 Jammy `affected.database_specific.cves_map.cves`에는 없다. `internal/match/cache.go:294`가 per-release CVE 목록 대신 전체 alias를 출력한다. 이 2쌍은 오탐이다. 같은 USN의 raw finding 2개는 UNKNOWN이며, 정상 CVE 레코드 MEDIUM과 함께 나타나 공통 CVE 10쌍의 severity **집합** 불일치를 만든다(예: libc-bin의 CVE-2026-19542/6368/6791). `internal/match/severity.go:207`은 cves_map Ubuntu 등급을 읽지 않고 `:172`는 CVSS v4 vector를 점수화하지 않는다. 정상 MEDIUM 결과 자체가 없어진 것은 아니다.
- **c / B Red Hat 미수정 공급원·정책 차이 96쌍:** `ubi9 curl-minimal@7.76.1-29.el9_4.1 / CVE-2026-8458`, `expat@2.5.0-2.el9_4.1 / CVE-2026-56131`, `gawk@5.1.0-6.el9 / CVE-2026-40467`. [curl API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-8458.json), [expat API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-56131.json), [gawk API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-40467.json) 등 전수 조회에서 source 상태 Affected/Fix deferred/Under investigation을 확인했다. 이 중 Under investigation은 확정 취약점으로 판정하지 않는다. API 404 1개 CVE는 다음 별도 분류에 있다.
- **c / B Negligible 정책 4쌍:** UBI9 `gdb-gdbserver@10.2-13.el9 / CVE-2023-2222`, UBI8 `gdb-gdbserver@8.2-20.el8 / CVE-2023-2222`, UBI9 `gdb-gdbserver@10.2-13.el9 / CVE-2026-19582`(UBI8에도 동일 CVE). [CVE-2023-2222 API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-2222.json)의 None와 VEX의 None를 NEGLIGIBLE로 포함하는 정책이다. CVE-2026-19582는 archive 안에 있으나 현재 API/VEX 단건 URL은 모두 404여서 최신 유효성 판정은 보류한다.
- **e/c / B UBI8 라벨 없는 Python 소스 범위 13쌍:** `python3-chardet@3.0.4-7.el8 / CVE-2021-28861`, `python3-idna@2.5-8.el8_10 / CVE-2026-4786`, `python3-six@1.11.0-8.el8 / CVE-2026-5713`. [Red Hat API 28861](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-28861.json)는 python38, [4786](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-4786.json)는 python38/python39를 영향 대상으로 명시한다. 하지만 [VEX 28861](https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-28861.json)은 `python-chardet.src` 등을 module 없는 RHEL 8 known_affected로 제공한다. 5713도 python-six에 대한 API 직접 판정은 없으며 VEX에 source 묶음으로 나타난다. source/module 범위 과대 적용으로 분류하고 실제 exploit은 전수 재현하지 않았다. 원문에 module이 없으면 `internal/vulndb/redhat_vex.go:417`은 라벨을 넣지 못하고 `:437`의 무한 범위를 `internal/match/match.go:232`의 boolean module 검사로 걸러낼 수 없다.
- **f / A와 B 각각 Trivy 오탐 16쌍:** `ubi9 curl-minimal@7.76.1-29.el9_4.1 / CVE-2026-11352`, `libarchive@3.5.3-4.el9 / CVE-2026-16517`, `rpm@4.16.1.3-29.el9 / CVE-2026-44604`. [curl](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-11352.json), [libarchive](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-16517.json), [rpm](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-44604.json) 등 해당 8개 CVE의 API와 VEX가 모두 RHEL9 Not affected를 제공한다. 따라서 이 16개를 bscan 누락으로 세지 않는다.
- **b / VEX 음성 marker EVR 유실 1쌍(유일 사례):** `ubi9 acl@2.3.1-4.el9 / CVE-2026-54369`. [VEX 원문](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-54369.json)의 mainline CPE에서 `acl-0:2.4.0-1.el9_8.src`는 fixed, **`acl-0:2.4.0-1.el9_8.x86_64`**는 known_not_affected다. `internal/vulndb/redhat_vex.go:412`에서 읽은 EVR을 `:435`의 not-affected 분기에서 버려 버전 없는 acl marker가 되고, `internal/match/match.go:196`, `:242`가 구버전에도 적용해 양성 범위를 억제한다. **특정 버전 정보를 전체 버전으로 넓히는 변환 결함**은 확인했지만, 구버전 acl binary 자체의 실제 영향과 source/binary 경계 판정은 보류한다.

**Grype 보조 비교**

| 이미지 / catalog | Grype CVE | bscan 공통 | bscan만 | Grype만 |
| --- | --- | --- | --- | --- |
| ubi9 / A | 804 | 362 | 4 | 442 |
| ubi9 / B | 804 | 802 | 20 | 2 |
| ubi8 / A | 511 | 0 | 0 | 511 |
| ubi8 / B | 511 | 510 | 35 | 1 |
| rocky9 / A | 933 | 371 | 2 | 562 |
| alma9 / A | 557 | 47 | 1 | 510 |
| ubuntu24 / A | 58 | 58 | 0 | 0 |
| ubuntu22 / A | 94 | 94 | 2 | 0 |
| centos9 / A | 495 | 0 | 0 | 495 |

Grype는 Rocky/Alma/CentOS에 Red Hat namespace를 적용하는 공급원·범위 차이가 있다. 설치 PyPI metadata는 인벤토리에 포함하지만 이번 표본에서 PyPI CVE를 보고하지 않았다. 예: Rocky `krb5-libs / CVE-2023-36054`, `CVE-2023-39975`, Alma `pam / CVE-2026-54411`은 vendor errata와 bscan/Trivy가 지지하나 Grype가 놓친다. 반대 방향의 A–Grype 예: UBI9 `bzip2-libs@1.0.8-8.el9 / CVE-2026-42250`, `coreutils-single@8.32-35.el9 / CVE-2026-56391`, `curl-minimal@7.76.1-29.el9_4.1 / CVE-2024-11053`는 Red Hat 미수정 API 상태가 지지하며 B에서 복원된다. 다른 c 분류는 전수 차집합과 공급원 namespace를 기록하되 실제 exploit 여부를 단정하지 않았다. CentOS의 Grype 495쌍 역시 지원 판정의 정답으로 사용하지 않았다. 세 도구의 모든 비교 조합과 분류별 ≥3개 예(3개 미만이면 전수)는 JSON `class_summaries`에 있다.

Grype 대조로 B의 추가 coverage 누락 **2쌍(전수)**도 확인했다: `ubi9 expat@2.5.0-2.el9_4.1 / CVE-2026-66046`, `ubi8 expat@2.5.0-2.el8_10.2 / CVE-2026-66046`. [Red Hat API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-66046.json)는 두 릴리스를 Affected로, [최신 단건 VEX](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-66046.json)는 **2026-09-15** 수정본으로 제공하지만 9/13 archive로 만든 B에는 해당 CVE 레코드가 없다. **c: archive snapshot coverage** 공백이다. `internal/vulndb/redhat_vex.go:50`, `:66`은 archive_latest가 가리키는 archive만 읽고 이후 단건 변경을 보충하지 않는다. 반대로 B만 보고 Grype에는 없는 UBI9 `expat/CVE-2026-56403`, `glibc/CVE-2026-19499`, `glibc/CVE-2026-77117`은 현재 API Under investigation과 일치하며 확정 취약점은 아니다.

**scan+match 성능**

| 이미지 / catalog | wall 초 | peak RSS KiB |
| --- | --- | --- |
| ubi9 / A | 3.99 | 53,820 |
| ubi9 / B | 4.61 | 62,252 |
| ubi8 / A | 2.85 | 39,356 |
| ubi8 / B | 3.98 | 43,620 |
| rocky9 / A | 1.89 | 37,460 |
| alma9 / A | 2.02 | 43,280 |
| ubuntu24 / A | 1.41 | 39,624 |
| ubuntu22 / A | 1.15 | 34,192 |
| centos9 / A | 1.85 | 48,100 |

image pull은 제외하고 로컬 Docker 읽기·SBOM 작성·매칭을 포함한다. 각 1회 실행이며 cold-cache/반복 평균 비교가 아니다. 제품 수정·전체 테스트 suite·다른 CPU architecture·실제 CVE exploit 재현은 수행하지 않았다.

**정리·작성 범위**

Docker 이미지 **7개 전부 `docker rmi` 성공**, digest와 실제 image ID가 더 이상 존재하지 않음을 확인했다. W 안에서 생성한 도구·DB·Go cache·SBOM·스크립트·원문은 검토 결과를 보존한 뒤 삭제했다. 시작 전부터 있던 sandbox mount 디렉터리만 남겼다. 이 작업이 쓴 저장소 파일은 기존 보고서에 이 절을 append한 파일, 새 round7b 상세 JSON, 지원 표의 **3개 문서**다. 초기 본문 바이트는 그대로 유지했다. 다른 작업의 소스·테스트 변경은 그대로 두었다.
