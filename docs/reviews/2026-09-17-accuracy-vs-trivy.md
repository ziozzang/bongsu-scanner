bscan 정확도 실측 — 2026-09-17

**핵심 결과:** 6개 이미지에서 Trivy 대비 인벤토리 교집합은 **803/805개(99.75%)**, 패키지별 CVE 교집합은 **927/977건(94.88%)**였다. 이것은 Trivy와의 일치율이며 실제 재현율·정밀도가 아니다. bscan만 보고한 CVE 23건, Trivy만 보고한 50건, 공통 CVE의 심각도 불일치 450건을 확인했다. 가장 큰 공백은 Ubuntu DB 적재 실패, Ruby의 미설치 lockfile 의존성 포함, Debian의 부정·미확정 상태 유실이다.

모든 차이의 정확한 패키지·버전·CVE·분류·근거와 전체 정규화 집합은 [상세 부록 JSON](2026-09-17-accuracy-vs-trivy-details.json)에 기록했다. 아래 숫자는 이미지별 집합을 합산하므로 같은 패키지가 여러 이미지에 있으면 각각 센다.

**실험 조건**

- bscan: `addf59edf0ca4ffb7676d3369a3b0b64e782a42f`, Go 1.27.1, 빌드 메타데이터 `vcs.modified=false`. `go build -mod=readonly -o /home/ziozzang/.cache/bongsu-work/bin/bscan ./cmd/bscan` 실행.
- Trivy: GitHub 최신 Linux-64bit 릴리스 **0.74.0**. 취약점 DB `2026-09-17 01:13:53 UTC`, Java DB `01:10:53 UTC`.
- Grype: 최신 **0.118.0**, DB `2026-09-16 06:30:57 UTC`. DB 시점과 공급원이 달라 보조 비교로 해석했다.
- 제공 DB: OSV Alpine/npm/PyPI/Go/Debian/crates.io/Maven/RubyGems, Alpine secdb, Debian tracker. 갱신 시각 `2026-09-17 03:30:15 UTC`, 407,454 레코드.
- 제공 DB의 manifest는 없는 `cache/*` 15개를 참조해 처음 매칭이 실패했다. 원본을 보존하고 작업 복사본의 SQLite SHA-256 `377825116c269eddf94f4b09a1e92703acb8ca1fb733de4f55df88c01144830d` 및 `meta.json` 해시를 검증한 다음, 복사본 manifest에 존재하는 두 파일만 남겼다. advisory 내용은 변경하지 않았다. 이는 제공 산출물의 사전 조건 문제다.
- Rocky는 별도 작업 DB에 `db update --source osv --ecosystem 'Rocky Linux' --no-keep-raw`로 4,199 레코드를 적재했다. 기본 DB에서는 Rocky 118개 패키지가 coverage 부족으로 건너뛰어졌고, 적재 후 아래 결과를 얻었다.
- Ubuntu도 `--ecosystem Ubuntu --no-keep-raw --max-feed-bytes 1500000000`으로 시도했다. 668.9MB 피드 다운로드 후 `OSV zip exceeds 4294967296 total uncompressed bytes`로 실패했다. 디스크 부족이 아니라 코드의 압축 해제 합계 제한이다. Ubuntu의 0건을 안전하다는 뜻으로 해석하면 안 된다.
- `db update`는 선택한 피드들로 DB를 재구성하므로, 단일 ecosystem 갱신을 기존 DB에 덮어쓰지 않았다. 스캔 중 bscan은 `BONGSU_OFFLINE=1`; Trivy는 아래 옵션으로 DB·이미지를 고정했다. `TMPDIR`, 빌드 캐시, 도구·DB·결과는 모두 `bongsu-work`에 두었다.

```text
bscan scan --no-sign --format cyclonedx --output OUT docker://IMAGE
bscan match --format json -o MATCH_JSON SBOM
# Rocky의 match에는 --db WORK/rocky-home/db 추가
trivy image --cache-dir WORK/trivy-cache --image-src docker   --offline-scan --skip-db-update --skip-java-db-update --skip-version-check   --scanners vuln --format cyclonedx --output SBOM IMAGE
# 같은 옵션으로 --format json 실행
# Grype: 전용 GRYPE_DB_CACHE_DIR, DB 갱신 후 GRYPE_DB_AUTO_UPDATE=false
```

패키지 키는 `(purl type, namespace 포함 이름, version)`이다. OS 메타 컴포넌트·파일은 제외하고 중복 위치는 합쳤다. Debian/RPM epoch qualifier를 버전에 복원했으며, Debian 소스명과 설치 바이너리명을 혼동하지 않았다. npm scope, Maven `group:artifact`, PyPI 이름 정규화도 적용했다. CVE는 bscan의 `ID`, `RelatedIDs`, `Record.aliases`를 펼쳐 `(패키지 키, CVE)`로 셌다. 따라서 Rocky의 advisory 135건은 CVE 310건이다. TEMP 같은 비-CVE는 별도 부록에 남겼다. epoch를 무시하면 발생하는 가짜 버전 차이는 모두 제거했다.

**이미지별 인벤토리**

| 이미지 | OS | bscan | Trivy | 공통 | bscan만 | Trivy만 | 버전 집합 차이 |
|---|---|---:|---:|---:|---:|---:|---:|
| alpine:3.20 | Alpine 3.20.10 | 14 | 14 | 14 | 0 | 0 | 0 |
| python:3.12-slim | Debian 13.6 | 88 | 88 | 88 | 0 | 0 | 0 |
| node:22-slim | Debian 12.15 | 274 | 275 | 274 | 0 | 1 | 0 |
| tomcat:10.1-jre17 | Ubuntu 24.04 | 178 | 142 | 141 | 37 | 1 | 1 |
| rockylinux:9-minimal | Rocky 9.3 | 118 | 118 | 118 | 0 | 0 | 0 |
| ruby:3.3-slim | Debian 13.6 | 214 | 168 | 168 | 46 | 0 | 13 |

- Node의 Trivy 전용 패키지는 **`npm/yarn@1.22.22`** 하나다. `/opt/yarn-v1.22.22/package.json`과 `/usr/local/bin/yarn` 링크를 확인했다.
- Ruby의 bscan 전용 46개는 설치된 `Gem::Specification` 86개와 대조했을 때 **전부 미설치**였다. 예: `addressable@2.8.5`, `rdoc@6.6.2`, `rexml@3.2.6`. 주된 증거는 설치 gem 안에 번들된 `rbs-3.4.0/Gemfile.lock`이다. 실제 설치 버전은 `rdoc@6.6.3.1`, `rexml@3.4.4`다. 13개 이름에서 설치 버전에 오래된 lockfile 버전이 추가된다.
- Tomcat의 bscan 전용 37개는 ECJ 버전 표현 1개와 추가 아티팩트 36개다. `java-runtime@17.0.20`, i18n JAR 9개, bootstrap 및 Tomcat JAR 26개를 포함한다. Trivy는 Java 패키지 5개만 보고했다. `catalina.jar`·`bootstrap.jar`의 실제 manifest를 확인했다. 이는 측정한 offline 조건에서 Trivy의 인벤토리 누락이며, 누락된 각 Maven 좌표의 정확성까지 보증하는 것은 아니다.
- ECJ는 bscan `org.eclipse.jdt:ecj@3.33.0.v20230218-1114`, Trivy `@3.33.0`. 이미지 `ecj-4.27.jar` SHA-1과 [Maven 3.33.0 배포 해시](https://repo.maven.apache.org/maven2/org/eclipse/jdt/ecj/3.33.0/ecj-3.33.0.jar.sha1)가 `4041d27ffea3c9351e3121f9bfe94dea4723d583`으로 같다. Maven 매칭 좌표로는 Trivy가 맞고, bscan은 OSGi 버전을 그대로 사용한다.

**이미지별 매칭**

| 이미지 | bscan CVE | Trivy CVE | 공통 | bscan만 | Trivy만 | 공통 중 심각도 차이 |
|---|---:|---:|---:|---:|---:|---:|
| alpine:3.20 | 0 | 0 | 0 | 0 | 0 | 0 |
| python:3.12-slim | 182 | 177 | 177 | 5 | 0 | 88 |
| node:22-slim | 242 | 238 | 238 | 4 | 0 | 116 |
| tomcat:10.1-jre17 | 0* | 48 | 0 | 0 | 48 | 0 |
| rockylinux:9-minimal | 310 | 310 | 310 | 0 | 0 | 133 |
| ruby:3.3-slim | 216 | 204 | 202 | 14 | 2 | 113 |

`*` Ubuntu 피드 적재 실패. 원시 findings 개수는 bscan 순서대로 Alpine 0, Python 183, Node 243, Tomcat 0, Rocky 135, Ruby 216; Trivy는 0, 183, 244, 48, 310, 210이다. CVE 별칭 확장·TEMP 제외·중복 제거 후 위 숫자가 된다. `--include-unimportant` 대조에서도 Debian 세 이미지의 CVE 집합은 변하지 않았다.

**영향도순 개선 목록**

분류: (a) cataloger/증거, (b) purl·이름·메타데이터 매핑, (c) DB 공급원·coverage, (d) 버전 비교, (e) 릴리스/ecosystem 매핑, (f) Trivy 오탐·누락. 이번 표본에서 **순수 버전 비교(d), 릴리스 선택(e) 오류는 입증되지 않았다.**

| 우선순위 / ID | 분류 | 구체적 격차와 판정 | 변경할 코드 영역 |
|---|---|---|---|
| P0 / G1 | c: 피드 미적재 | Ubuntu 피드의 4GiB 확장 제한으로 OS 137개를 매칭하지 못함. Trivy 전용 48건. 예: `libexpat1@2.6.1-2ubuntu0.4 / CVE-2025-59375`. 한도를 안전하게 설정 가능하게 하거나 릴리스별 적재를 지원하고 coverage 실패를 결과 상단에 표시. | `internal/vulndb/osv.go`, `internal/vulndb/options.go`, `cmd/bscan/db.go`, `internal/match/match.go` |
| P1 / G2 | a | Ruby 미설치 의존성 46개를 required 패키지처럼 포함해 추가 CVE 9건을 생성. `rexml@3.2.6 / CVE-2024-35176` 등. 이미지 설치 증거와 소스 lockfile 선언을 구분해야 함. | `internal/scan/catalog.go`의 `scanFile`, `scanGemfileLock`, `mergePackage`; `internal/scan/model.go` |
| P1 / G3 | c: 공급원 충돌 | Debian tracker의 `not affected`, `undetermined`를 버려 OSV의 열린 범위가 확정 finding으로 남음. SQLite 오탐 2건, PAM 미확정 경고 12건. 미확정 12건의 실제 취약 여부는 판정 보류하되 `Confidence=high`는 근거 부족. | `internal/vulndb/debian.go`의 `parseDebianTracker`, `internal/vulndb/source.go`, `internal/match/cache.go`, `internal/match/match.go` |
| P1 / G4 | c: 생태계 advisory 부재 | 실제 설치 `resolv@0.3.1`의 **CVE-2026-80212, CVE-2026-80213** 누락. OSV RubyGems query는 빈 결과, 로컬 DB에도 없음. OSV 전체에는 package 없는 GIT 레코드가 존재하므로 “OSV에 전혀 없다”는 뜻은 아님. Ruby advisory 공급원 보강 필요. | `internal/vulndb/source.go`, `internal/vulndb/osv.go`, 신규 Ruby advisory 변환기 |
| P1 / G5 | b, c | 심각도 차이 450건. 예: libc6의 **CVE-2019-1010022: CRITICAL ↔ LOW**, Rocky libxml2의 **CVE-2025-49794: CRITICAL ↔ HIGH**. CVSS와 distro 우선순위, 여러 CVE를 묶은 RLSA 심각도를 분리 표시. 또한 OSV `ecosystem_specific.urgency`를 필터가 읽지 않아 기본 실행에 unimportant 57/44/44건(Node/Python/Ruby)이 남음. | `internal/match/severity.go`, `internal/match/cache.go:prepareRecord`, `internal/vulndb/ingestion.go` |
| P2 / G6 | a | Yarn 1.22.22 누락. `package.json` 인식이 `node_modules` 경로에 한정됨. `/opt`의 설치 배포물·실행 링크 증거 지원. 이번 이미지에서 Yarn에 귀속된 CVE 누락은 없음. | `internal/scan/catalog.go:isInstalledNPMPackage`, `scanInstalledNPM` |
| P2 / G7 | b | ECJ OSGi 버전을 Maven 버전으로 사용. 동일 JAR 해시로 3.33.0 좌표 입증. 원본 버전을 보존하면서 매칭용 좌표를 별도로 정규화. | `internal/scan/jar.go`, `internal/scan/purl.go` |
| P2 / G8 | f, 일부 b | offline Trivy가 놓친 Tomcat 추가 아티팩트 36개. bscan의 장점이지만 `org.apache.catalina:bootstrap` 같은 추론 좌표는 검증 필요. 이 표본에서 Java CVE 정답 누락은 입증하지 못함. | 누락 자체는 bscan 수정 불필요; 추론 좌표 신뢰도는 `internal/scan/jar.go` |
| P2 / G9 | b, f | Node의 `zlib1g@1:1.2.13.dfsg-1 / CVE-2023-45853`는 bscan·Trivy 공통 오탐. Debian은 해당 binary에 취약 minizip 코드를 빌드하지 않는다고 명시. Grype는 보고하지 않음. 소스 패키지 경고를 모든 binary에 확정 전파하지 않도록 증거 보강. | `internal/vulndb/debian.go`, `internal/match/match.go:subjectQueries` |
| P2 / G10 | a, c, 검증 필요 | Grype는 Python 런타임 `generic/python@3.12.14`에 CVE 11건을 추가 보고. bscan/Trivy의 Python 설치 메타데이터 일치만으로 런타임 coverage까지 검증됐다고 할 수 없음. 이 11건의 개별 정오 판정은 미실시. | `internal/scan/catalog.go`, 런타임 binary cataloger 및 advisory 연결 |

G1의 48건 전부가 확정 진양성이라는 주장은 하지 않는다. 공급원 차이와 실제 취약성은 별도로 판정해야 한다. G5 역시 심각도 차이 전부가 계산 오류라는 뜻은 아니다.

**원문 수동 대조 — 16개 CVE**

이미지의 설치 증거와 OSV API의 package/range, 배포판 tracker를 함께 확인했다. 아래 Ruby의 오래된 버전은 실제 설치 목록에 없다는 사실이 판정의 핵심이다.

| # | 패키지 / CVE | 원문 사실 | 판정 |
|---:|---|---|---|
| 1 | rexml 3.2.6 / CVE-2024-35176 | [OSV](https://api.osv.dev/v1/vulns/GHSA-vg3r-rm7w-2xgh): 3.2.7에서 수정; 실제 설치 3.4.4 | Trivy가 맞음; bscan 설치 인벤토리 오탐 |
| 2 | rexml 3.2.6 / CVE-2024-39908 | [OSV](https://api.osv.dev/v1/vulns/GHSA-4xqq-m2hx-25v8): 3.3.2에서 수정 | 동일 |
| 3 | rexml 3.2.6 / CVE-2024-41123 | [OSV](https://api.osv.dev/v1/vulns/GHSA-r55c-59qm-vjw6): 3.3.3에서 수정 | 동일 |
| 4 | rexml 3.2.6 / CVE-2024-41946 | [OSV](https://api.osv.dev/v1/vulns/GHSA-5866-49gr-22v4): 3.3.3에서 수정 | 동일 |
| 5 | rexml 3.2.6 / CVE-2024-43398 | [OSV](https://api.osv.dev/v1/vulns/GHSA-vmwr-mc7x-5vc3): 3.3.6에서 수정 | 동일 |
| 6 | rexml 3.2.6 / CVE-2024-49761 | [OSV](https://api.osv.dev/v1/vulns/GHSA-2rxp-v6pw-ch6m): 3.3.9에서 수정 | 동일 |
| 7 | rexml 3.2.6 / CVE-2025-10990 | [같은 OSV](https://api.osv.dev/v1/vulns/GHSA-2rxp-v6pw-ch6m)의 추가 CVE alias | 동일; 별칭 확장으로 2개 CVE를 셈 |
| 8 | rdoc 6.6.2 / CVE-2024-27281 | [OSV](https://api.osv.dev/v1/vulns/GHSA-592j-995h-p23j): 6.6.3.1에서 수정; 실제 설치가 그 버전 | Trivy가 맞음 |
| 9 | addressable 2.8.5 / CVE-2026-35611 | [OSV](https://api.osv.dev/v1/vulns/GHSA-h27x-rffw-24p4): 2.9.0에서 수정; 패키지는 미설치 | Trivy가 맞음 |
| 10 | PAM 1.5.2-6+deb12u2 / 1.7.0-5 / CVE-2025-8941 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2025-8941): bookworm·trixie 모두 undetermined | bscan 확정 판정 부적절; Trivy 누락을 FN이라고 단정할 수 없음 |
| 11 | libsqlite3-0 3.46.1-7+deb13u1 / CVE-2026-39113 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-39113): 출시된 Debian에 취약 코드 없음, fixed_version=0. OSV는 열린 범위 | Trivy가 맞음; bscan 공급원 충돌 오탐 |
| 12 | resolv 0.3.1 / CVE-2026-80212 | [OSV GIT 레코드](https://api.osv.dev/v1/vulns/CVE-2026-80212), [Ruby 공지](https://www.ruby-lang.org/en/news/2026/08/27/multiple-vulnerabilities-in-resolv/): 0.3.2에서 수정 | Trivy가 맞음; bscan coverage FN |
| 13 | resolv 0.3.1 / CVE-2026-80213 | [OSV GIT 레코드](https://api.osv.dev/v1/vulns/CVE-2026-80213), 같은 Ruby 공지 | 동일 |
| 14 | Ubuntu libexpat1 2.6.1-2ubuntu0.4 / CVE-2025-59375 | [OSV](https://api.osv.dev/v1/vulns/UBUNTU-CVE-2025-59375): Ubuntu 24.04 expat 영향 범위에 포함 | advisory 기준 Trivy 보고가 타당; bscan 피드 미적재 |
| 15 | libc6 / CVE-2019-1010022 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2019-1010022): unimportant, upstream 비보안 이슈 판단 | bscan CRITICAL은 distro 위험도와 불일치; 기본 제외 정책도 실패 |
| 16 | Node zlib1g / CVE-2023-45853 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-45853): bookworm binary에 취약 minizip 미포함 | Grype가 맞음; bscan·Trivy 공통 binary 오탐 |

**Grype 보조 비교**

| 이미지 | Grype 패키지별 CVE | Trivy와 공통 | Grype만 | Trivy만 |
|---|---:|---:|---:|---:|
| alpine:3.20 | 3 | 0 | 3 | 0 |
| python:3.12-slim | 188 | 177 | 11 | 0 |
| node:22-slim | 237 | 237 | 0 | 1 |
| tomcat:10.1-jre17 | 107 | 48 | 59 | 0 |
| rockylinux:9-minimal | 539 | 308 | 231 | 2 |
| ruby:3.3-slim | 202 | 202 | 0 | 2 |

Grype 결과는 별도 ground truth가 아니다. Alpine의 추가 3건은 `busybox`, `busybox-binsh`, `ssl_client`에 대한 **CVE-2025-60876** CPE 매칭이며 정오 판정은 보류했다. Rocky에서는 Grype가 Red Hat 공급원을 사용하므로 Rocky updateinfo/OSV와 공급원이 다르다. Ruby의 resolv 2건은 Grype도 놓쳤다. Grype 전체 설치 인벤토리는 별도로 추출하지 않았고, 위 표는 matching 비교다.

**재현성과 정리**

시작 시 `docker images --no-trunc`를 기록했고 대상 6개 태그는 모두 없었다. 아래 digest를 사용했다. Rocky 태그는 실제로 2023년 빌드의 9.3이므로 최신 Rocky 9 패치 수준으로 일반화하면 안 된다.

| 이미지 | RepoDigest의 SHA-256 |
|---|---|
| alpine:3.20 | `d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` |
| node:22-slim | `83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5` |
| python:3.12-slim | `78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea` |
| rockylinux:9-minimal | `305de618a5681ff75b1d608fd22b10f362867dff2f550a4f1d427d21cd7f42b4` |
| ruby:3.3-slim | `79f7a07363931fde1a5b312dee281fd62ddf56c33bdba0c2622af9b4621182fb` |
| tomcat:10.1-jre17 | `033172811a0e3b7fed4a2f9b2fffe83a5102677c4130aed8ea13b64871ff6d8f` |

원본 DB와 기존 Docker 이미지는 보존했다. 작업 중 사용한 6개 이미지, 검사 컨테이너, bscan/Trivy/Grype 바이너리·다운로드, 작업 DB·빌드 캐시·Trivy cache·임시 결과를 정리했다. 보고서와 상세 부록만 추가했다. 빌드 후 다른 작업의 코드 변경이 나타났으나 수정하거나 되돌리지 않았다. 코드 수정·회귀 테스트 추가는 하지 않았으며, 검증은 실제 이미지 스캔, 설치 gem 조회, JAR 해시 및 advisory 대조로 수행했다.
