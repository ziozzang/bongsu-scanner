# 2026-09-17 CLI 수락 시험

판정: **핵심 로컬 스캔·서명·DB·매칭 흐름은 통과했으나 출시 수락은 보류**한다. 오프라인 설정을 무시하는 registry 다운로드와 기본 컨테이너의 임시 디렉터리 권한이 P1 결함이다. 문서만 수정했으며 코드/Dockerfile/systemd unit은 변경하지 않았다.

## 환경과 시험 범위

- 시험 일자: 2026-09-17, Asia/Seoul. Debian 13, linux/amd64, 일반 사용자 UID/GID 1000, Go 1.27.1, Docker 29.5.2.
- 시작 HEAD: `393e4b26fec1bcbddd82cf6c32ff472413521857`. 작업 중 다른 작업이 HEAD를 `10d2def2d19ba608a5654a24f0422bfebd4304ba`로 진행시켰다. 격리 복제본의 모든 production Go 파일(cmd/internal, *_test.go 제외)은 두 commit 모두와 바이트 단위로 동일함을 확인했다. 타 작업의 변경은 건드리지 않았다.
- 네이티브 binary SHA-256: `563fcdfc36f37f86bd91ac154dd4e48ce4a6268412d425f82ef6ec2371e02fbc`. 버전 `0.6.0-rc1`. Git 메타데이터를 뒤늦게 복구한 격리 복제본이라 version 출력은 후자 commit과 `(modified)`를 표시했다; 제품 결함으로 분류하지 않았다.
- `W=/home/ziozzang/.cache/bongsu-work/u1`, `R=/home/ziozzang/bongsu-scanner`. 기본 cwd는 `$W/run`, 기본 `BONGSU_HOME=$W/home`, PATH 앞부분은 `$W/src/dist`.
- 모든 직접 생성 파일·복제본·원시 로그·Go build cache·TMPDIR/GOTMPDIR·buildx client 상태는 W 아래에 두었다. 기존 Go module cache는 읽어서 사용했다. Docker는 호스트 daemon의 기존 저장소를 사용했다. `/tmp`를 작업 공간으로 사용하지 않았고 `/var/tmp`는 읽기만 했다.
- `BONGSU_NO_UPDATE_CHECK=1`로 시험 중 비결정적인 background check만 껐다. 명시적 `update --check`는 실제 HTTPS GitHub API 조회를 수행했다(없는 repo의 HTTP 404도 확인).
- 처음 빈 HOME에서 init; 별도 빈 config/interrupt/airgap HOME도 사용. Docker daemon에는 alpine:3.20이 이미 존재했다. 실제 버전은 Alpine 3.20.10이며 Docker/registry 모두 17개 패키지였다.
- host는 권한 상승 없이 `--workers 4 --timeout 10m`으로 실행했다. partial=true/denied=167이므로 root 권한의 완전한 host scan을 입증하지 않는다. systemd는 실제 서비스를 설치·기동하지 않고 원본 unit의 dry validation만 했다.
- README의 예시 입력 경로/컨테이너 이름은 W의 실물 fixture로 치환했다. 원본 repo 스캔 결과는 문서만 편집한다는 제약에 맞춰 W로 보냈고, 격리 소스에서는 `bscan scan --output ./scan-results .`도 그대로 실행했다. `rootfs`는 lodash 4.17.20 package-lock.json을 가진 디렉터리; `image.tar`는 `docker save alpine:3.20`, `image-a.tar`는 그 symlink이다.
- 요청된 CLI 수락 절차 외의 release publishing, sudo install/useradd/systemctl, 실제 self-update 설치, 외부 LLM 서버 예제는 실행하지 않았다. 배포 계정/실행 파일/서비스를 변경하거나 제공되지 않은 publisher key·LLM endpoint를 가정하지 않았다. NVD/GHSA opt-in 대용량 수집 및 모든 언어·플랫폼 지원 정확성은 이번 시험의 검증 범위가 아니다.
- 시간은 subprocess 시작부터 종료까지의 wall-clock 초. 일부 독립 시험은 겹쳐 실행했으므로 합계를 전체 소요 시간으로 해석하면 안 된다. timeout harness에 의해 강제 종료된 정상 시험은 없으며 SIGINT는 의도적으로 전송했다.

## 주요 결과

| 단계 | 판정 | 관찰 |
| --- | --- | --- |
| README native build / version / about | PASS | `make build VERSION=0.6.0-rc1`, 11.001초 |
| 전체 도움말·플래그 대조 | PASS / 일부 UX FAIL | root 포함 40개 경로, 문서 169개 항목 = help 165개 + 의도적으로 숨긴 4개; 누락 플래그 0 |
| repo / Docker / registry / host / archive / container scan | PASS | 두 SBOM 형식과 서명, host partial 표시 확인 |
| 기본 DB update/status/verify/lookup/show | PASS | 139.403초, 731,750 records, Disk size 3.4 GB |
| match 7형식 / report 5형식 / scan+match / batch | PASS | 양성 fixture 5 findings; HIGH threshold 2, 결과 보존 |
| export → 새 HOME import → offline match | PASS | export 31.387초/import 17.525초; --network none에서도 양성 매칭 |
| Docker 문서 그대로 build/run | FAIL (환경) | docker0 부재; build --network host/run --network none으로 우회 후 성공 |
| Docker 디렉터리 scan | FAIL → 문서 우회 PASS | `/tmp` root:root 0755; mode=1777 tmpfs로 성공. 이미지 코드 결함은 잔존 |
| systemd 원본 4개 unit dry verify | PASS (설치 경로 격리 후) | 실제 host에 binary 미설치 시 오류; --root에 배치하면 종료 0 |
| 오류·취소·정리 | 대체로 PASS | 0/1/2/3/130 실제 관찰, 음수 workers/jobs는 잘못된 성공 0 |
| offline registry 금지 | FAIL | BONGSU_OFFLINE=1인데 실제 원격 다운로드, 종료 0 |

## 결함과 유지보수 우선순위

| ID / 우선순위 | 재현·정확한 관찰 | 요청 변경 / 문서 조치 |
| --- | --- | --- |
| D1 / P1 | `BONGSU_OFFLINE=1 bscan scan registry://docker.io/library/alpine:3.20`가 `[scan:registry] fetching ...` 후 manifest/layer를 받아 서명 SBOM을 쓰고 **0**. README의 “offline disables network access”와 불일치. 같은 환경의 `update --check`, `db update`는 1로 차단됨. | registry 경로 진입 전에 공통 offline 정책을 검사하고 명확한 오류 1을 반환. scan/batch 및 config offline 적용도 회귀 검증. README에 현재 제한을 명시했지만 코드는 수정하지 않음. |
| D2 / P1 | 배포 문서의 read-only/non-root directory scan이 `walk result spool: open /tmp/bscan-walk-*: permission denied`, **1**. 기본 UID로 tmpfs 없이 실행해도 실패. Docker export 실측 `/tmp` **root:root 0755**; builder의 chmod 1777이 최종 이미지에 보존되지 않음. | 최종 이미지 `/tmp` 권한을 1777로 보장하고 기본 UID directory scan을 container smoke에 포함. docs의 세 tmpfs 예제에 mode=1777 추가 후 실제 성공 확인. directory scan도 임시 저장소가 필요하다고 정정. |
| D3 / P2 | `scan --workers -1`과 `batch --jobs -1` 모두 **0** 및 SBOM 생성. 깨끗한 fixture에서도 재현. timeout/max-files의 음수는 명확한 오류 **1**이므로 입력 정책이 일관되지 않음. | 병렬도 음수 값을 1로 거절하거나 허용되는 정규화 동작을 help/reference에 명시. 현 help는 workers의 0/1 의미만 설명. 현재 성공을 유효한 문서 계약으로 간주하지 않음. |
| D4 / P2 | `init/scan/batch/hash/sign/check/verify/scramble encrypt/decrypt/encrypt/decrypt --help`는 도움말을 **stderr**로 출력. 다른 명령은 stdout. `verify --help` 제목은 **Usage of check**. 모두 종료 0. | 생성 reference의 출력 계약과 도움말 stream/명칭 통일. `docs/commands.md`는 생성 파일이므로 문서 생성기(코드)를 함께 수정해야 하며 이번에는 생성 파일을 임의 변경하지 않음. |
| D5 / P2 | db update 취소 시 종료 130/정리는 맞지만 시작하지 못한 feed들까지 `0 records (0 B); fetched 0001-01-01T00:00:00Z`와 `context canceled`를 다수 출력. strict partial에서도 “SBOM will be marked partial” 직후 출력 없이 3으로 종료. | 취소는 간단한 요약으로 묶고 미조회 시각은 생략. --fail-on-partial 메시지는 실제 “출력하지 않음” 동작과 일치시킬 것. |
| D6 / P3 | 여러 SBOM의 match JSON array를 `report --from`에 주면 `cannot unmarshal array into Go value of type map[string]jsontext.Value`, 종료 1. 단일 입력 제한은 문서에 있으므로 거절 자체는 정상. | “one SBOM result required; split the array”처럼 행동 가능한 오류로 변경. |
| D7 / 문서 수정 | README가 logging 적용을 main.go scan/batch로 제한하고 scan summary 위치를 혼동시킴; RubySec를 기본 소스 요약에서 누락; SQLite schema를 2라고 기술; 항상 private DB copy라고 설명. 실제 match에도 JSON/quiet 적용, SQLite PRAGMA user_version=7/meta schema_version=2. auto/copy 정책은 관찰 후 구현을 읽어 보완 확인. | README의 stdout/stderr 구분, 기본 RubySec, 두 schema 버전, auto/copy/none 및 catalog 옆 snapshot 위치 수정. |
| D8 / P3 관찰 | 같은 HOME에서 db status의 검증과 export가 겹쳤을 때 export가 `database is locked or unavailable: resource temporarily unavailable`, **1**. 순차 실행은 성공. 뒤따른 import/match 최초 실패는 파일 미생성의 연쇄 결과. | lock owner/DB 경로/재시도 안내 또는 bounded wait 검토. 이 결과를 catalog 손상이나 offline import 결함으로 분류하지 않음. |

플래그의 존재/누락 불일치는 **없었다**. `--cpuprofile`/`--memprofile`은 scan과 match에서 각각 문서에 hidden으로 기재되어 있고 실제 파서가 수용한다. 종료 코드 2/3/130 누락이나 스테이징 파일 누수는 재현되지 않았다. D3의 음수 병렬도 성공은 별도 개선 대상으로 남긴다.

환경 실패는 제품 결함과 분리한다: 첫 native build의 VCS 오류는 시험 복제 방식 문제, buildx 경로는 sandbox 읽기 전용, docker0 오류는 host daemon, 최초 systemd verify 오류는 설치 전 `/usr/local/bin/bscan` 부재였다. 해당 환경을 우회했을 때 native/Docker compile과 unit validation은 성공했다.

## 문서 수정 파일

- `README.md`: 로그의 실제 적용 범위/출력 stream, offline registry 제한, 기본 RubySec, catalog envelope 2와 SQLite layout 7 구분, auto/copy/none의 동작 및 임시 snapshot 위치.
- `deploy/README.md`: 세 tmpfs mount에 mode=1777; directory-walk spool에도 writable temp 필요; 현재 이미지 `/tmp` 0755 문제와 우회 방법.
- `docs/reviews/2026-09-17-acceptance.md`: 본 수락 시험 결과와 전체 실행 명령/종료 코드/시간/판정.
- `docs/commands.md`, `CHANGELOG.md`, 코드와 deploy unit/Dockerfile은 변경하지 않음. generated reference의 help 관련 정정은 D4의 코드/생성기 변경과 함께 수행해야 한다.

## 전체 명령 실행표

표의 명령은 실제 실행 문자열이다. 별도 표시가 없는 환경/cwd는 위 기본값을 사용했다. `env` 열은 기본 환경에 추가/덮어쓴 값만 표시한다. FAIL(환경/경합/선행 실패)은 제품 결함 수에 합산하지 않는다. 실패 후 재시도도 생략하지 않았다.

실행 기록 189건: FAIL (환경) 5, PASS 162, FAIL (출력 계약) 10, FAIL (UX) 1, FAIL 6, FAIL (경합) 1, FAIL (선행 실패) 4.

| # / 시험 ID | 실제 명령 | cwd / 추가 env | 종료 | 초 | 판정 | 출력·문서 약속 대조 |
| --- | --- | --- | ---: | ---: | --- | --- |
| 1 / build | `make build VERSION=0.6.0-rc1` | $W/src | 2 | 0.165 | FAIL (환경) | 복제본에 .git이 없어 상위 Git 저장소를 오인. Git 메타데이터 복원 후 동일 명령 성공; 제품 빌드 결함 아님. |
| 2 / docker-info | `docker info` | $W/run | 0 | 0.065 | PASS | Docker 29.5.2, linux/amd64 사용 가능. |
| 3 / docker-build | `docker build --platform linux/amd64 -t bscan:u1-acceptance .` | $W/src | 1 | 0.114 | FAIL (환경) | 기본 buildx activity 경로가 읽기 전용. BUILDX_CONFIG를 작업 폴더로 변경. |
| 4 / build-retry | `make build VERSION=0.6.0-rc1` | $W/src | 0 | 11.001 | PASS | 정확히 make build VERSION=0.6.0-rc1; 네이티브 실행 파일 생성. |
| 5 / docker-build-retry | `docker build --platform linux/amd64 -t bscan:u1-acceptance .` | $W/src; BUILDX_CONFIG=$W/buildx | 1 | 2.620 | FAIL (환경) | docker0 브리지 없음: Device does not exist. Dockerfile 컴파일 단계 실행 전 실패. |
| 6 / version | `bscan version` | $W/run | 0 | 0.008 | PASS | 0.6.0-rc1, commit/build date/Go/platform/module 출력. |
| 7 / about | `bscan about` | $W/run | 0 | 0.008 | PASS | 버전 정보에 author/project/license/notices 추가. |
| 8 / help-root | `bscan --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 9 / help-init | `bscan init --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 10 / help-config | `bscan config --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 11 / help-config-show | `bscan config show --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 12 / help-config-init | `bscan config init --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 13 / help-key | `bscan key --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 14 / help-key-show | `bscan key show --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 15 / help-key-generate | `bscan key generate --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 16 / help-key-trust | `bscan key trust --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 17 / help-scan | `bscan scan --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 18 / help-batch | `bscan batch --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 19 / help-hash | `bscan hash --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 20 / help-sign | `bscan sign --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 21 / help-check | `bscan check --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 22 / help-verify | `bscan verify --help` | $W/run | 0 | 0.008 | FAIL (UX) | D4: 종료 0이나 Usage of check를 표시; help는 stderr. |
| 23 / help-scramble | `bscan scramble --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 24 / help-scramble-encrypt | `bscan scramble encrypt --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 25 / help-scramble-decrypt | `bscan scramble decrypt --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 26 / help-encrypt | `bscan encrypt --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 27 / help-decrypt | `bscan decrypt --help` | $W/run | 0 | 0.008 | FAIL (출력 계약) | D4: 도움말/플래그는 존재, 종료 0; stdout 대신 stderr에 도움말 출력. |
| 28 / help-db | `bscan db --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 29 / help-db-update | `bscan db update --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 30 / help-db-status | `bscan db status --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 31 / help-db-lookup | `bscan db lookup --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 32 / help-db-show | `bscan db show --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 33 / help-db-verify | `bscan db verify --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 34 / help-db-export | `bscan db export --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 35 / help-db-import | `bscan db import --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 36 / help-db-convert | `bscan db convert --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 37 / help-match | `bscan match --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 38 / help-report | `bscan report --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 39 / help-update | `bscan update --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 40 / help-self-update | `bscan self-update --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 41 / help-version | `bscan version --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 42 / help-about | `bscan about --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 43 / help-help | `bscan help --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 44 / help-completion | `bscan completion --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 45 / help-completion-bash | `bscan completion bash --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 46 / help-completion-zsh | `bscan completion zsh --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 47 / help-completion-fish | `bscan completion fish --help` | $W/run | 0 | 0.008 | PASS | 도움말/서브명령 출력, 종료 0; 플래그 비교표 참조. |
| 48 / init | `bscan init --signer ziozzang@gmail.com` | $W/run | 0 | 0.008 | PASS | scaner.yaml, signing.key(0600), signing.pub 생성. |
| 49 / key-show | `bscan key show` | $W/run | 0 | 0.008 | PASS | 개인키 경로, 공개키 및 fingerprint 출력; 개인키 내용 노출 없음. |
| 50 / config-show | `bscan config show` | $W/run | 0 | 0.008 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 51 / config-init-existing | `bscan config init` | $W/run | 1 | 0.008 | PASS | 기존 설정 덮어쓰기 거절, file exists, 종료 1. |
| 52 / config-init | `bscan config init` | $W/run; BONGSU_HOME=$W/config-home | 0 | 0.008 | PASS | 새 설정 템플릿만 생성; 서명키 없음. |
| 53 / config-show-fresh | `bscan config show` | $W/run; BONGSU_HOME=$W/config-home | 0 | 0.008 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 54 / completion-bash | `bscan completion bash > completion.bash` | $W/run | 0 | 0.008 | PASS | bash completion script 파일 생성. |
| 55 / completion-bash-syntax | `bash -n completion.bash` | $W/run | 0 | 0.004 | PASS | bash -n 구문 검증. |
| 56 / update-check | `bscan update --check` | $W/run | 0 | 0.315 | PASS | current: 0.6.0-rc1 / latest: 0.5.0; stdout 버전, stderr up to date; 실제 네트워크 조회. |
| 57 / docker-build-host-network | `docker build --network host --platform linux/amd64 -t bscan:u1-acceptance .` | $W/src; BUILDX_CONFIG=$W/buildx | 0 | 18.525 | PASS | 동일 Dockerfile, --network host로 환경 우회; VERSION 기본값 dev. |
| 58 / systemd-verify | `systemd-analyze verify /home/ziozzang/bongsu-scanner/deploy/systemd/bscan-db-update.service /home/ziozzang/bongsu-scanner/deploy/systemd/bscan-db-update.timer /home/ziozzang/bongsu-scanner/deploy/systemd/bscan-scan.service /home/ziozzang/bongsu-scanner/deploy/systemd/bscan-scan.timer` | $W/run | 1 | 0.064 | FAIL (환경) | 서비스 설치 전이라 /usr/local/bin/bscan 없음; 구문 오류는 아님. |
| 59 / scan-repository | `bscan scan --output /home/ziozzang/.cache/bongsu-work/u1/run/scan-results .` | $R | 0 | 1.267 | PASS | SPDX 2.3 + CycloneDX 1.6 및 각 서명; 17 packages/1052 files; SHA manifest 없음. |
| 60 / scan-docker-literal | `bscan scan docker://alpine:3.20` | $W/run | 0 | 0.115 | PASS | 기존 로컬 alpine:3.20을 docker image save로 읽음; 17 packages, 서명 2개. |
| 61 / scan-registry-literal | `bscan scan registry://docker.io/library/alpine:3.20` | $W/run | 0 | 2.019 | PASS | HTTPS 원격 OCI 다운로드/검증 성공; 17 packages. 같은 basename의 기존 결과를 덮어씀. |
| 62 / scan-docker-results | `bscan scan --output results docker://alpine:3.20` | $W/run | 0 | 0.115 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 63 / scan-host | `bscan scan --output host-scan --workers 4 --timeout 10m host` | $W/run | 0 | 20.016 | PASS | 20.016초; 6,053,400 visited, 54,084 packages, denied=167/partial=true. 비루트 실행이므로 완전한 host inventory 아님. |
| 64 / negative-nonexistent | `bscan scan --output negative-missing no-such-target` | $W/run | 1 | 0.008 | PASS | bscan: stat no-such-target: no such file or directory |
| 65 / negative-unreadable-file | `bscan scan --output negative-file unreadable/go.mod` | $W/run | 1 | 0.008 | PASS | bscan: open unreadable/go.mod: permission denied |
| 66 / negative-unreadable-dir | `bscan scan --output negative-partial unreadable` | $W/run | 0 | 0.019 | PASS | permission denied를 partial=true로 표시하고 SBOM 생성; 기본 정책 종료 0. |
| 67 / negative-unreadable-strict | `bscan scan --fail-on-partial --output negative-strict unreadable` | $W/run | 3 | 0.016 | PASS | --fail-on-partial 종료 3; SBOM 없음. 단, 직전 로그는 SBOM will be marked partial로 혼란. |
| 68 / negative-missing-db | `bscan match corrupt.cdx.json` | $W/run; BONGSU_HOME=$W/missing-db-home | 1 | 0.008 | PASS | bscan: no vulnerability database at /home/ziozzang/.cache/bongsu-work/u1/missing-db-home/db; run 'bscan db update' |
| 69 / negative-scan-missing-db | `bscan scan --match --output negative-no-db unreadable` | $W/run; BONGSU_HOME=$W/missing-db-home | 1 | 0.008 | PASS | bscan: no vulnerability database at /home/ziozzang/.cache/bongsu-work/u1/missing-db-home/db; run 'bscan db update' |
| 70 / negative-unknown | `bscan scan --not-a-flag .` | $W/run | 1 | 0.008 | PASS | bscan: flag provided but not defined: -not-a-flag |
| 71 / negative-format | `bscan scan --format nonsense unreadable` | $W/run | 1 | 0.008 | PASS | bscan: unsupported format "nonsense" |
| 72 / negative-workers-string | `bscan scan --workers four unreadable` | $W/run | 1 | 0.008 | PASS | bscan: invalid value "four" for flag -workers: parse error |
| 73 / negative-workers-negative | `bscan scan --workers -1 --output negative-workers unreadable` | $W/run | 0 | 0.016 | FAIL | D3: --workers -1을 오류 없이 받아 0과 SBOM 반환. |
| 74 / negative-timeout-string | `bscan scan --timeout tomorrow unreadable` | $W/run | 1 | 0.008 | PASS | bscan: invalid value "tomorrow" for flag -timeout: parse error |
| 75 / negative-timeout-negative | `bscan scan --timeout -1s --output negative-timeout unreadable` | $W/run | 1 | 0.008 | PASS | bscan: --max-files and --timeout must not be negative |
| 76 / negative-max-files-negative | `bscan scan --max-files -1 --output negative-max-files unreadable` | $W/run | 1 | 0.008 | PASS | bscan: --max-files and --timeout must not be negative |
| 77 / negative-report-without-match | `bscan scan --report html unreadable` | $W/run | 1 | 0.008 | PASS | bscan: --report requires --match |
| 78 / negative-report-format | `bscan report --from corrupt.cdx.json --format nonsense` | $W/run | 1 | 0.008 | PASS | bscan: unsupported report format "nonsense" |
| 79 / negative-log-format | `bscan --log-format nonsense version` | $W/run | 1 | 0.008 | PASS | bscan: --log-format must be text or json, got "nonsense" |
| 80 / negative-db-source | `bscan db update --source nonsense` | $W/run | 1 | 0.008 | PASS | 동시 DB 갱신의 lock 오류가 source 검증보다 먼저 발생. 별도 HOME에서 unknown source 재검증. |
| 81 / negative-db-isolation | `bscan db status --db-isolation nonsense` | $W/run | 1 | 0.008 | PASS | bscan: invalid database isolation "nonsense" (want auto, copy, or none) |
| 82 / negative-severity | `bscan match --fail-on INVALID corrupt.cdx.json` | $W/run | 1 | 0.008 | PASS | bscan: invalid severity "INVALID" (want UNKNOWN, NEGLIGIBLE, LOW, MEDIUM, HIGH, or CRITICAL) |
| 83 / negative-severity-policy | `bscan match --severity-source INVALID corrupt.cdx.json` | $W/run | 1 | 0.008 | PASS | bscan: invalid severity source "INVALID" (want cvss, distro, or max) |
| 84 / db-update-sigint | `bscan db update` | $W/run; BONGSU_HOME=$W/interrupt-home | 130 | 2.016 | PASS | 2초 후 SIGINT; 종료 130; staging 제거, 0바이트 db.lock만 유지. D5: 취소 로그 다수/0001년 시각. |
| 85 / docker-version | `docker run --rm bscan:u1-acceptance version` | $W/run | 125 | 0.566 | FAIL (환경) | Docker daemon bridge 오류로 125; bscan 실행 전 실패. |
| 86 / docker-version-network-none | `docker run --rm --network none bscan:u1-acceptance version` | $W/run | 0 | 0.265 | PASS | --network none으로 bscan dev/unknown commit/date 출력. |
| 87 / docker-directory | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m --mount "type=bind,src=$PWD,dst=/input,readonly" --mount "type=bind,src=$PWD/scan-results,dst=/reports" bscan:u1-acceptance scan --no-sign --exclude scan-results --workers 2 --output /reports /input` | $W/src | 1 | 0.264 | FAIL | D2: 문서 예제 그대로 실행 시 /tmp/bscan-walk-* permission denied; 종료 1. |
| 88 / docker-save | `docker save -o image.tar alpine:3.20` | $W/run | 0 | 0.065 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 89 / scan-archive | `bscan scan --verbose --output results image.tar` | $W/run | 0 | 0.065 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 90 / check-archive-sig | `bscan check results/image.tar.sha256.sig` | $W/run | 0 | 0.016 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 91 / check-layers | `bscan check --source image.tar results/image.tar.layers.sha256` | $W/run | 0 | 0.064 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 92 / verify-host | `bscan verify --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub host-scan/host.spdx.json.sig host-scan/host.cdx.json.sig` | $W/run | 0 | 0.114 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 93 / verify-directory | `bscan verify --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub scan-results/bongsu-scanner.spdx.json.sig scan-results/bongsu-scanner.cdx.json.sig` | $W/run | 0 | 0.008 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 94 / check-image | `bscan check --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub results/alpine_3.20.cdx.json.sig` | $W/run | 0 | 0.008 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 95 / key-trust | `bscan key trust scanner-01 scanner-01.pub` | $W/run | 0 | 0.008 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 96 / verify-trusted | `bscan verify --pubkey scanner-01 results/alpine_3.20.cdx.json.sig` | $W/run | 0 | 0.008 | PASS | 생성된 artifact의 signature/checksum/content 검증 성공. |
| 97 / scramble-encrypt | `bscan scramble encrypt --chunk-size 4MiB -o payload.bgs payload.bin` | $W/run | 0 | 0.008 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 98 / scramble-decrypt | `bscan scramble decrypt --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub -o restored.bin payload.bgs` | $W/run | 0 | 0.008 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 99 / scramble-roundtrip | `cmp payload.bin restored.bin` | $W/run | 0 | 0.004 | PASS | 복호화 결과가 원본과 byte-for-byte 동일. |
| 100 / scan-verbose-dir | `bscan scan --verbose --output rootfs-results rootfs` | $W/run | 0 | 0.016 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 101 / scan-spdx-dir | `bscan scan --format spdx --output spdx-results rootfs` | $W/run | 0 | 0.016 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 102 / batch | `bscan batch --jobs 4 --sign image-a.tar docker://alpine:3.20 ./rootfs` | $W/run | 0 | 0.117 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 103 / log-json | `bscan --log-format json scan --output json-log-results rootfs` | $W/run | 0 | 0.016 | PASS | stderr 모든 진행 줄 JSON; stdout scan complete/출력 경로 유지. |
| 104 / quiet | `bscan -q scan --output quiet-results rootfs` | $W/run | 0 | 0.016 | PASS | stderr 0 bytes; stdout 결과 유지. |
| 105 / negative-deadline | `bscan scan --timeout 1ns --output deadline-results rootfs` | $W/run | 1 | 0.016 | PASS | context deadline exceeded는 1; SIGINT의 130과 구분. |
| 106 / negative-source-fresh | `bscan db update --source nonsense` | $W/run; BONGSU_HOME=$W/invalid-source-home | 1 | 0.008 | PASS | unknown vulnerability source "nonsense"로 종료 1. |
| 107 / negative-offline-update | `bscan update --check` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | bscan: update disabled: offline mode (BONGSU_OFFLINE or 'offline: true' in config) |
| 108 / negative-offline-registry | `bscan scan --output offline-registry registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 0 | 1.868 | FAIL | D1: BONGSU_OFFLINE=1에서도 원격 registry fetch 및 layer download, 결과 생성 후 0. |
| 109 / hidden-scan-cpuprofile | `bscan scan --cpuprofile= --help` | $W/run | 0 | 0.008 | PASS | 숨김 profiling 옵션을 파서가 수용; 도움말에서 숨김은 문서대로. |
| 110 / hidden-scan-memprofile | `bscan scan --memprofile= --help` | $W/run | 0 | 0.008 | PASS | 숨김 profiling 옵션을 파서가 수용; 도움말에서 숨김은 문서대로. |
| 111 / hidden-match-cpuprofile | `bscan match --cpuprofile= --help` | $W/run | 0 | 0.008 | PASS | 숨김 profiling 옵션을 파서가 수용; 도움말에서 숨김은 문서대로. |
| 112 / hidden-match-memprofile | `bscan match --memprofile= --help` | $W/run | 0 | 0.008 | PASS | 숨김 profiling 옵션을 파서가 수용; 도움말에서 숨김은 문서대로. |
| 113 / db-update-default | `bscan db update` | $W/run | 0 | 139.403 | PASS | 139.403초; 731,750 records, signed manifest. db 경로 stdout, 진행/메타데이터 stderr. |
| 114 / docker-directory-tmp-mode | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 --mount "type=bind,src=$PWD,dst=/input,readonly" --mount "type=bind,src=$PWD/scan-results,dst=/reports" bscan:u1-acceptance scan --no-sign --exclude scan-results --workers 2 --output /reports /input` | $W/src | 0 | 0.265 | PASS | --tmpfs에 mode=1777 추가 후 13 packages/332 files, SBOM 2개 생성. |
| 115 / container-create | `docker run -d --rm --network none --name bscan-u1-acceptance-container alpine:3.20 sleep 600` | $W/run | 0 | 0.115 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 116 / scan-container | `bscan scan --output container-results container://bscan-u1-acceptance-container` | $W/run | 0 | 0.115 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 117 / container-stop | `docker stop bscan-u1-acceptance-container` | $W/run | 0 | 10.091 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 118 / config-show-empty | `bscan config show` | $W/run; BONGSU_HOME=$W/empty-config-home | 0 | 0.008 | PASS | 기본값 출력; BONGSU_HOME 디렉터리도 만들지 않음. |
| 119 / update-network-proof | `bscan update --check --repo ziozzang/bongsu-u1-does-not-exist-20260917` | $W/run | 1 | 0.265 | PASS | 존재하지 않는 --repo로 GitHub API HTTP 404 확인; 네트워크 실패는 1. |
| 120 / db-export | `bscan db export --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub catalog.tar.gz` | $W/run | 1 | 0.008 | FAIL (경합) | db status와 겹쳐 lock 오류. 같은 HOME의 명령들을 순차 실행하여 재시도 성공. |
| 121 / db-import-offline | `bscan db import --pubkey publisher.pub catalog.tar.gz` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 1 | 0.008 | FAIL (선행 실패) | 앞선 export 실패로 catalog.tar.gz 없음; 순차 재시도 성공. |
| 122 / db-verify-offline | `bscan db verify --pubkey publisher.pub` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 1 | 0.008 | FAIL (선행 실패) | 앞선 import 미완료로 manifest 없음; 순차 재시도 성공. |
| 123 / match-offline | `bscan match --pubkey publisher.pub --format json -o offline-findings.json results/alpine_3.20.cdx.json` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 1 | 0.008 | FAIL (선행 실패) | 앞선 import 미완료로 DB 없음; 순차 재시도 성공. |
| 124 / scan-match-offline | `bscan scan --match --report html --output offline-scan-results rootfs` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 1 | 0.008 | FAIL (선행 실패) | 앞선 import 미완료로 DB 없음; 순차 재시도 성공. |
| 125 / db-status | `bscan db status` | $W/run | 0 | 2.219 | PASS | Records 731,750, Disk size 3.4 GB, Signature valid, source별 metadata 출력. |
| 126 / db-verify | `bscan db verify --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub` | $W/run | 0 | 2.220 | PASS | database checksums and trusted signature verified. |
| 127 / db-lookup-npm | `bscan db lookup npm lodash` | $W/run | 0 | 2.169 | PASS | lodash advisory JSON; 전체 advisory의 여러 affected 항목 포함. |
| 128 / db-lookup-alpine | `bscan db lookup Alpine:v3.20 openssl` | $W/run | 0 | 0.615 | PASS | Alpine:v3.20 openssl advisory JSON; 병합된 advisory 전체를 반환. |
| 129 / db-show | `bscan db show GHSA-29mw-wpgm-hmr9` | $W/run | 0 | 0.565 | PASS | 요청한 GHSA의 상세 JSON 반환. |
| 130 / match-table | `bscan match --format table -o match.txt results/alpine_3.20.cdx.json` | $W/run | 0 | 0.615 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 131 / match-json | `bscan match --format json -o match.json results/alpine_3.20.cdx.json` | $W/run | 0 | 0.615 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 132 / match-cyclonedx | `bscan match --format cyclonedx -o match.cdx.json results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 133 / match-html | `bscan match --format html -o match.html results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 134 / match-markdown | `bscan match --format markdown -o match.md results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 135 / match-csv | `bscan match --format csv -o match.csv results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 136 / match-sarif | `bscan match --format sarif -o match.sarif results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 137 / match-spdx-json | `bscan match --format json -o findings.json results/alpine_3.20.spdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 138 / match-fail-on-alpine | `bscan match --fail-on HIGH --only-fixed results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 현재 alpine:3.20.10은 0 findings여서 0; --fail-on을 줘도 무조건 2가 아님. |
| 139 / match-fail-on-fixture | `bscan match --fail-on HIGH --only-fixed rootfs-results/rootfs.cdx.json` | $W/run | 2 | 0.566 | PASS | lodash 4.17.20: 5 findings(HIGH 2); 출력 후 임계값 종료 2. |
| 140 / report-html | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format html -o report.html --title alpine:3.20` | $W/run | 0 | 0.008 | PASS | 저장 match JSON으로 지정 형식 재생성; SBOM metadata/title 포함. |
| 141 / report-markdown | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format markdown -o report.markdown --title alpine:3.20` | $W/run | 0 | 0.008 | PASS | 저장 match JSON으로 지정 형식 재생성; SBOM metadata/title 포함. |
| 142 / report-json | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format json -o report.json --title alpine:3.20` | $W/run | 0 | 0.008 | PASS | 저장 match JSON으로 지정 형식 재생성; SBOM metadata/title 포함. |
| 143 / report-csv | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format csv -o report.csv --title alpine:3.20` | $W/run | 0 | 0.008 | PASS | 저장 match JSON으로 지정 형식 재생성; SBOM metadata/title 포함. |
| 144 / report-sarif | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format sarif -o report.sarif --title alpine:3.20` | $W/run | 0 | 0.008 | PASS | 저장 match JSON으로 지정 형식 재생성; SBOM metadata/title 포함. |
| 145 / scan-match-repo | `bscan scan --match --report html,sarif --fail-on HIGH --output /home/ziozzang/.cache/bongsu-work/u1/run/matched-repo .` | $R | 2 | 1.417 | PASS | 93 findings(CRITICAL 4/HIGH 43); SBOM/서명/findings/HTML/SARIF 저장 후 2. |
| 146 / scan-match-fixture | `bscan scan --match --report html,sarif --fail-on HIGH --output matched-fixture rootfs` | $W/run | 2 | 0.616 | PASS | 5 findings(HIGH 2); 7개 결과 파일을 모두 남기고 2. |
| 147 / systemd-verify-isolated | `systemd-analyze --root=/home/ziozzang/.cache/bongsu-work/u1/system-root --generators=no --man=no --recursive-errors=no verify bscan-db-update.service bscan-db-update.timer bscan-scan.service bscan-scan.timer` | $W/run | 0 | 0.016 | PASS | 격리 --root에 원본 unit/시스템 unit/빌드 binary 복사 후 4개 unit verify 성공; 실제 서비스 미기동. |
| 148 / batch-match-fixture | `bscan batch --match --report html,sarif --fail-on HIGH --output batch-matched rootfs docker://alpine:3.20` | $W/run | 2 | 0.717 | PASS | 두 타깃의 결과/보고서를 모두 저장하고 HIGH 임계값 종료 2. |
| 149 / negative-corrupt-sbom | `bscan match corrupt.cdx.json` | $W/run | 1 | 0.566 | PASS | bscan: corrupt.cdx.json: invalid character 'B' looking for beginning of value |
| 150 / negative-match-format | `bscan match --format nonsense results/alpine_3.20.cdx.json` | $W/run | 1 | 0.008 | PASS | bscan: unsupported format "nonsense" |
| 151 / match-json-log | `bscan --log-format json match --format json rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | stdout 유효 match JSON, stderr JSON log; README의 scan/batch 전용 설명과 달리 적용됨. |
| 152 / match-quiet | `bscan -q match rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | stderr 0 bytes; table은 stdout 유지. |
| 153 / match-multiple | `bscan match --format json -o multiple-findings.json rootfs-results/rootfs.cdx.json results/alpine_3.20.cdx.json` | $W/run | 0 | 0.616 | PASS | 문서의 결과 형식으로 생성; alpine은 0 findings. |
| 154 / report-multiple | `bscan report --from multiple-findings.json --format html` | $W/run | 1 | 0.008 | PASS | 단일 SBOM 입력 제약대로 1; D6: 사용자 대신 Go 타입 명칭을 보여주는 오류. |
| 155 / db-export-retry | `bscan db export --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub catalog.tar.gz` | $W/run | 0 | 31.387 | PASS | 서명 pin 검증 후 1.8 GiB catalog.tar.gz 생성; 31.387초. |
| 156 / db-update-selected | `bscan db update --source osv,alpine --ecosystem npm,PyPI,Go --alpine-release v3.20` | $W/run; BONGSU_HOME=$W/selected-home | 0 | 31.637 | PASS | README의 source/ecosystem 제한 예제 성공; 별도 HOME 270,764 records. |
| 157 / db-import-offline-retry | `bscan db import --pubkey publisher.pub catalog.tar.gz` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 17.525 | PASS | 새 BONGSU_HOME + BONGSU_OFFLINE=1, 공개키 pin 검증 후 import; 17.525초. |
| 158 / db-verify-offline-retry | `bscan db verify --pubkey publisher.pub` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 0.616 | PASS | 가져온 DB 체크섬/신뢰 서명 검증. |
| 159 / match-offline-retry | `bscan match --pubkey publisher.pub --format json -o offline-findings.json results/alpine_3.20.cdx.json` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 0.666 | PASS | online matching과 Findings 동일; 로컬 DB만 사용. |
| 160 / scan-match-offline-retry | `bscan scan --match --report html --output offline-scan-results rootfs` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 2.320 | PASS | 키가 없는 새 HOME에서 unsigned SBOM/findings/HTML 생성; 5 findings. |
| 161 / db-convert | `bscan db convert --db /home/ziozzang/.cache/bongsu-work/u1/selected-home/db /home/ziozzang/.cache/bongsu-work/u1/converted-db` | $W/run; BONGSU_OFFLINE=1 | 0 | 22.014 | PASS | BONGSU_OFFLINE=1, 별도 목적지로 변환 및 로컬 identity 서명; refresh 시각 보존. |
| 162 / db-lookup-converted | `bscan db lookup --db /home/ziozzang/.cache/bongsu-work/u1/converted-db npm lodash` | $W/run | 0 | 0.566 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 163 / fixture-format-table | `bscan match --format table -o fixture.table rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.966 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 164 / fixture-format-json | `bscan match --format json -o fixture.json rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 165 / fixture-format-cyclonedx | `bscan match --format cyclonedx -o fixture.cyclonedx rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.565 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 166 / fixture-format-html | `bscan match --format html -o fixture.html rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 167 / fixture-format-markdown | `bscan match --format markdown -o fixture.markdown rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 168 / fixture-format-csv | `bscan match --format csv -o fixture.csv rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 169 / fixture-format-sarif | `bscan match --format sarif -o fixture.sarif rootfs-results/rootfs.cdx.json` | $W/run | 0 | 0.566 | PASS | 5개 findings의 형식별 결과 생성; 구조/행 수/ID 확인. |
| 170 / negative-workers-clean | `bscan scan --workers -1 --output negative-workers-clean rootfs` | $W/run | 0 | 0.032 | FAIL | D3 재현: 읽기 권한 문제가 없는 rootfs에서도 --workers -1 성공(0). |
| 171 / negative-jobs | `bscan batch --jobs -1 --output negative-jobs rootfs` | $W/run | 0 | 0.016 | FAIL | D3: --jobs -1도 성공(0); 음수 병렬도 검증/문서화 필요. |
| 172 / quiet-error | `bscan -q scan no-such-target` | $W/run | 1 | 0.008 | PASS | quiet에도 종료 오류는 stderr에 표시, 종료 1. |
| 173 / negative-signature-tamper-prepare | `cp results/alpine_3.20.cdx.json tampered.cdx.json` | $W/run | 0 | 0.004 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 174 / negative-signature-tamper | `bscan verify --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub tamper/alpine_3.20.cdx.json.sig` | $W/run | 1 | 0.008 | PASS | 서명 대상에 개행 추가 후 signed target checksum mismatch, 종료 1. |
| 175 / negative-signature-untrusted | `bscan verify results/alpine_3.20.cdx.json.sig` | $W/run; BONGSU_HOME=$W/untrusted-home | 1 | 0.008 | PASS | 새 HOME에서 untrusted key 거절, --pubkey/key trust 안내, 종료 1. |
| 176 / offline-no-network-container | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 --mount type=bind,src=/home/ziozzang/.cache/bongsu-work/u1/airgap-home,dst=/var/lib/bscan --mount type=bind,src=/home/ziozzang/.cache/bongsu-work/u1/run,dst=/input,readonly -e BONGSU_OFFLINE=1 bscan:u1-acceptance match --pubkey /input/publisher.pub --format json /input/rootfs-results/rootfs.cdx.json` | $W/run | 0 | 2.420 | PASS | Docker --network none으로 네트워크 자체를 차단한 상태에서도 서명 pin + 5 findings. |
| 177 / db-verify-copy | `bscan db verify --db /home/ziozzang/.cache/bongsu-work/u1/converted-db --db-isolation copy --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub` | $W/run | 0 | 1.417 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 178 / db-update-offline | `bscan db update` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline DB 갱신을 1로 거절. |
| 179 / scan-literal-cwd | `bscan scan --output ./scan-results .` | $W/src | 0 | 0.064 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 180 / docker-directory-default-tmp | `docker run --rm --network none --mount type=bind,src=/home/ziozzang/.cache/bongsu-work/u1/run/rootfs,dst=/input,readonly bscan:u1-acceptance scan --no-sign /input` | $W/run | 1 | 0.215 | FAIL | D2: 기본 UID 65532, 기본 이미지 /tmp에서도 unsigned directory scan 실패. |
| 181 / docker-rootfs-create | `docker create --network none --name bscan-u1-inspect bscan:u1-acceptance version` | $W/run | 0 | 0.032 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 182 / docker-rootfs-modes | `docker export bscan-u1-inspect \| python3 -c 'import tarfile,sys; t=tarfile.open(fileobj=sys.stdin.buffer,mode="r\|"); print([(m.name, oct(m.mode),m.uid,m.gid) for m in t if m.name in ["tmp","reports","var/lib/bscan"]])'` | $W/run | 0 | 0.064 | PASS | 이미지 실측: /tmp root:root 0755; /reports, /var/lib/bscan 65532:65532 0755. |
| 183 / docker-rootfs-remove | `docker rm bscan-u1-inspect` | $W/run | 0 | 0.032 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |
| 184 / artifact-validation | `python3 /home/ziozzang/.cache/bongsu-work/u1/check_artifacts.py` | $W/run | 0 | 0.065 | PASS | SBOM/JSON/SARIF/CSV/HTML/서명 파일/키 권한/partial/잔여 파일 24개 검증 통과. |
| 185 / completion-source | `bash -c 'source completion.bash; complete -p bscan'` | $W/run | 0 | 0.004 | PASS | source 후 complete -o default -F _bscan bscan 등록 확인. |
| 186 / db-update-sigint-existing | `bscan db update` | $W/run | 130 | 3.317 | PASS | 기존 DB 갱신 중 SIGINT; 종료 130; installed manifest 동일, 이후 서명 검증 성공. |
| 187 / db-verify-after-sigint | `bscan db verify --pubkey /home/ziozzang/.cache/bongsu-work/u1/home/signing.pub` | $W/run | 0 | 2.521 | PASS | 취소 전 DB가 손상 없이 유지됨. |
| 188 / artifact-validation-final | `python3 /home/ziozzang/.cache/bongsu-work/u1/check_artifacts.py` | $W/run | 0 | 0.064 | PASS | 기존 DB 취소 시험 뒤 동일 24개 검증 재통과. |
| 189 / docker-image-cleanup | `docker image rm bscan:u1-acceptance` | $W/run | 0 | 0.032 | PASS | 요청한 결과 생성/동작 완료; 종료 0. |

## docs/commands.md ↔ 실제 --help 대조

숫자는 command별 옵션 항목 수이며 alias는 별도로 센다. 암묵적인 -h/--help는 본문에 공통 옵션으로 이미 설명되어 있어 표의 옵션 수에서는 제외했다. `help --help`는 root 도움말을 다시 보여주므로 전역 플래그를 새로운 하위 명령 플래그로 세지 않는다.

| command | 문서 | help 노출 | 의도적 hidden | 문서에만 존재 | help에만 존재 | 도움말 stream |
| --- | ---: | ---: | --- | --- | --- | --- |
| bscan (root) | 7 | 7 | — | 없음 | 없음 | stdout |
| bscan init | 1 | 1 | — | 없음 | 없음 | stderr |
| bscan config | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan config show | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan config init | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan key | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan key show | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan key generate | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan key trust | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan scan | 36 | 34 | --cpuprofile, --memprofile | 없음 | 없음 | stderr |
| bscan batch | 35 | 35 | — | 없음 | 없음 | stderr |
| bscan hash | 1 | 1 | — | 없음 | 없음 | stderr |
| bscan sign | 1 | 1 | — | 없음 | 없음 | stderr |
| bscan check | 2 | 2 | — | 없음 | 없음 | stderr |
| bscan verify | 2 | 2 | — | 없음 | 없음 | stderr |
| bscan scramble | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan scramble encrypt | 3 | 3 | — | 없음 | 없음 | stderr |
| bscan scramble decrypt | 3 | 3 | — | 없음 | 없음 | stderr |
| bscan encrypt | 3 | 3 | — | 없음 | 없음 | stderr |
| bscan decrypt | 3 | 3 | — | 없음 | 없음 | stderr |
| bscan db | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan db update | 11 | 11 | — | 없음 | 없음 | stdout |
| bscan db status | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db lookup | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db show | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db verify | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db export | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db import | 3 | 3 | — | 없음 | 없음 | stdout |
| bscan db convert | 4 | 4 | — | 없음 | 없음 | stdout |
| bscan match | 26 | 24 | --cpuprofile, --memprofile | 없음 | 없음 | stdout |
| bscan report | 5 | 5 | — | 없음 | 없음 | stdout |
| bscan update | 4 | 4 | — | 없음 | 없음 | stdout |
| bscan self-update | 4 | 4 | — | 없음 | 없음 | stdout |
| bscan version | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan about | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan help | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan completion | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan completion bash | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan completion zsh | 0 | 0 | — | 없음 | 없음 | stdout |
| bscan completion fish | 0 | 0 | — | 없음 | 없음 | stdout |

## 결과 파일과 정리 검증

정상 종료 코드만으로 PASS를 정하지 않았다. 다음은 실제 산출물/디렉터리를 추가 확인한 결과다. HTML 검증은 외부 script/link/img 리소스 참조가 없음을 정적으로 확인했으며 브라우저 UI 자동화/전체 SBOM schema validator까지 실행한 것은 아니다.

| 추가 확인 | 판정 | 관찰 |
| --- | --- | --- |
| SBOM versions | PASS | 조건 충족 |
| positive fixture | PASS | 5 |
| SARIF | PASS | 조건 충족 |
| CycloneDX vulnerabilities | PASS | 조건 충족 |
| CSV rows | PASS | 조건 충족 |
| Markdown | PASS | 조건 충족 |
| HTML resources | PASS | 조건 충족 |
| JSON parse match.json | PASS | 조건 충족 |
| JSON parse findings.json | PASS | 조건 충족 |
| JSON parse report.json | PASS | 조건 충족 |
| JSON parse report.sarif | PASS | 조건 충족 |
| JSON parse offline-findings.json | PASS | 조건 충족 |
| JSON parse multiple-findings.json | PASS | 조건 충족 |
| offline findings identical | PASS | 조건 충족 |
| scan threshold artifacts | PASS | 조건 충족 |
| strict partial no SBOM | PASS | 조건 충족 |
| key mode | PASS | 조건 충족 |
| config init no keys | PASS | 조건 충족 |
| config show no files | PASS | 조건 충족 |
| TMPDIR empty | PASS | 조건 충족 |
| GOTMPDIR empty | PASS | 조건 충족 |
| BONGSU_HOME transient leftovers | PASS | [] |
| /var/tmp new entries | PASS | [] |
| SIGINT lock only | PASS | 조건 충족 |

`db.lock` 및 `.bscan-db-readers.lock`은 0바이트 지속 동기화 파일로 남는다. 이를 임시 스테이징 누수로 판정하지 않았다. 새 HOME의 SIGINT 시험 후에는 db.lock 하나만 남았고 DB staging은 없었다. 기존 DB 갱신 중 취소도 원래 manifest를 보존하고 이후 trusted signature verify가 성공했다. `$W/tmp`, `$W/go-tmp`는 비어 있었고 각 HOME의 db.tmp-*, .bscan-db-reader-*, *.tmp, SQLite WAL/SHM 잔여물은 없었다. `/var/tmp`의 최상위 항목 집합도 전후 동일했고 기존 systemd-private 디렉터리는 건드리지 않았다.

최종 정리와 문서 검증 결과는 아래에 기록한다.

| 최종 작업 | 실제 수행 | 종료 | 초 | 판정 |
| --- | --- | ---: | ---: | --- |
| 작업 폴더 삭제 | `shutil.rmtree("/home/ziozzang/.cache/bongsu-work/u1")`; `not Path(...).exists()` 확인 | 0 | 1.339 | PASS |
| 문서 diff 검사 | `git diff --check -- README.md deploy/README.md docs/reviews/2026-09-17-acceptance.md` | 0 | 0.004 | PASS |

시험용 컨테이너 두 개와 `bscan:u1-acceptance` 이미지 태그/이미지를 제거했다. 원시 로그·SBOM·호스트 메타데이터·개인키·DB·아카이브·빌드 캐시를 포함한 W 전체를 삭제했다. 공유 Docker build cache와 기존 Alpine/Go builder 이미지 및 기존 사용자 파일은 정리 대상에서 제외했다. 삭제 후에도 `/var/tmp`에 새 항목은 []였다. 원시 로그의 실행 명령·시간·판정과 필요한 오류 증거는 이 보고서에 보존했다.


## Re-test after fixes

재시험 일자: **2026-09-17 (Asia/Seoul)**. 최종 판정: **reject**.
기존 D1–D8은 모두 수정 확인했다. 핵심 스캔·DB·매칭·보고서·서명 흐름과 lint/short/CI도 통과했다. 그러나 새 `--findings-exit-code`가 실제 프로세스 종료 코드에 반영되지 않는 **D9/P2**가 있어 요청된 신규 기능을 수락할 수 없다. root 도움말의 신규 옵션 누락은 **D10/P3**이다. 코드, Dockerfile, Makefile 및 generated reference는 수정하지 않았다.

### 시험 대상과 재현 조건

- 전체 시험의 격리 snapshot: `bd5ee410123edd44b4fe004af1e771979483a466`. native binary SHA-256 `ffe2219e0ab6575948369e06b0498ee8af006185b7a56629d0c4a2d661977951`, `make build VERSION=0.6.0-rc1`. 최초 조사 HEAD `4e78220d50d120df627ae4de550973a92336f356` 이후 문서 commit이 들어와 clone HEAD가 달라졌으나 production 코드는 동일하다.
- 시험 도중 원본 HEAD가 `8bae539827430d666ecd4e4ba41039d1ba1917d2`로 진행됐으며 변경은 SBOM/findings/report 출력 권한과 관련 테스트였다. 최초 snapshot은 계속 고정했고, 최신 commit도 별도 clone/build하여 D9·D10을 재확인했다. 최신 snapshot 전체에 대해 CI를 다시 돌렸다는 의미는 아니다.
- `W=/home/ziozzang/.cache/bongsu-work/u3`, 기본 cwd `$W/run`, PATH 앞에 `$W/src/dist`. 기본 `BONGSU_HOME=$W/home`, `BONGSU_NO_UPDATE_CHECK=1`. Go 1.27.1, 일반 사용자 UID 1000. Python harness는 stdout/stderr를 분리하고 wall-clock 시간과 실제 프로세스 종료값을 기록했다. 독립 build/lint/CI/DB 작업 일부는 동시에 실행했으므로 시간 합계는 전체 소요 시간이 아니다.
- 원본 repository는 읽기만 하고 clone에서 build/check를 실행했다. `TMPDIR=$W/tmp`, `GOTMPDIR=$W/go-tmp`, `GOCACHE=$W/go-cache`, `GOMODCACHE=$W/mod-cache`, `GOPATH=$W/go`, `BUILDX_CONFIG=$W/buildx`. lint 재실행은 `XDG_CACHE_HOME=$W/xdg-cache`. `/tmp`에 직접 작업 파일을 만들지 않았다. Docker daemon의 공용 저장소/build cache는 기존대로 사용했다.
- 허용된 `e2e/home`을 복사했으나 catalog가 SQLite schema 5라 현재 binary가 명확한 오류로 거절했다. 이 입력으로 발생한 DB/매칭 실패와 보고서 입력 미생성은 아래에 모두 남겼다. 별도 `$W/update-home`에서 init 후 **선택 옵션 없는 `bscan db update`**를 실행하고, 해당 HOME에서 관련 명령을 전부 재실행했다. 원본 catalog는 변경하지 않았다.
- 기존 명령의 `u1` 경로·이미지 태그만 `u3`로 치환했다. `rootfs/package-lock.json`은 `{"name":"fixture","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`. `image.tar`는 `docker save alpine:3.20`, `image-a.tar`는 그 symlink. unreadable fixture의 올바른 조건은 읽을 수 있는 루트 안에 mode 000의 `denied` 하위 디렉터리다. 처음 루트 자체를 mode 000으로 만든 실행은 오류 1이므로 partial 재현에 부적합했고, 조건을 정정해 같은 CLI 명령으로 재실행했다.
- Docker build는 host의 docker0 부재 이력을 반영해 `--network=host`, 실행은 `--network none`을 사용했다. native offline 시험은 허용된 **`unshare -rn`** 안에서 실행해 외부 네트워크 자체가 없는 상태였다. `strace`를 사용한 socket 호출 추적은 하지 않았으며, 네트워크 오류가 아니라 즉시 `offline mode` 정책 오류 1로 종료하는 것을 확인했다.

### D1–D8 재시험

종료값은 기대한 실패 코드도 PASS로 판정한다. 시간은 아래 실제 재현 명령의 wall-clock 초이며 `/`는 독립 실행 순서다.

| ID / 시험 | 판정 | 종료 | 초 | 실제 관찰 |
| --- | --- | ---: | ---: | --- |
| D1 / offline registry | PASS | 1, 1 | 0.008 / 0.008 | 원래 두 명령 모두 network namespace 안에서 offline 정책으로 즉시 거절; stdout·SBOM·fetch 로그 없음. env/config, scan/batch, registry/oci, --match 및 혼합 batch도 모두 1. |
| D2 / container /tmp·non-root | PASS | 0, 0, 0 | 0.367 / 0.369 / 0.465 | 최종 이미지 export 실측 `/tmp root:root 1777`. 기본 UID 65532에서 tmpfs 없이 성공. readonly+UID 1000 문서 명령 및 mode를 생략한 이전 명령도 성공. |
| D3 / negative workers/jobs | PASS | 1, 1, 1, 1 | 0.008 / 0.008 / 0.008 / 0.008 | 각각 해당 옵션의 negative 오류, stdout·SBOM 없음. |
| D4 / help stream·명칭 | PASS | 전부 0 | 합계 0.320 | 40개 경로 모두 stdout 비어 있지 않음/stderr 0 bytes. `Usage of verify:`, scramble/alias 명칭도 일치. 새 옵션의 내용 누락은 D10으로 별도 분류. |
| D5 / cancel·strict partial | PASS | 130, 130, 3 | 2.032 / 3.064 / 0.016 | 취소는 `19 feeds not started; 3 feeds interrupted` 요약 및 마지막 `bscan: interrupted` 1회; 0001년/context canceled 반복 없음. 기존 manifest 동일/서명 검증 성공. strict는 `partial scan; no SBOM written (--fail-on-partial)` 및 출력 없음. |
| D6 / report array | PASS | 1 | 0.008 | `match output for 2 SBOMs; pass a single result (use --format json with one SBOM or split the array)`로 사용자가 취할 행동을 안내. |
| D7 / README 사실 검증 | PASS | 0, 0, 0, 0 | 0.566 / 0.566 / 6.229 / 2.170 | stdout 결과/stderr 로그·quiet 검증, 기본 소스 OSV/Alpine/Debian/RubySec, envelope 2/SQLite 7 실측. auto/copy/none·snapshot 설명은 코드/실행과 일치. README/deploy 추가 정정 불필요. |
| D8 / lock 보유 중 export | PASS | 0, 1 | 32.296 / 10.041 | 별도 Python process가 db.lock의 exclusive flock을 보유. 2초 뒤 해제하면 1회 retry 안내 후 archive 생성. 12초 보유 시 약 10초에 오류 1/재시도 안내, 미완성 archive 없음. |

D8의 32초는 lock 대기뿐 아니라 1.733 GiB archive 생성까지 포함한다. lock 대기 한도는 작업 전체 timeout이 아니다. 재현 시 export를 시작하기 전에 holder의 `locked` stdout을 읽어 lock 획득을 동기화했다. holder는 아래 로직을 별도 process로 실행했고, `seconds=2`와 `12`를 각각 사용했다.

```python
f = open(W + "/update-home/db.lock", "a")
fcntl.flock(f, fcntl.LOCK_EX)
print("locked", flush=True)
time.sleep(seconds)
```

### 핵심 흐름 및 새 옵션 회귀 sweep

| 시험 | 판정 | 종료 | 초 | 산출물·관찰 |
| --- | --- | ---: | ---: | --- |
| native build | PASS | 0 | 32.757 | 버전 0.6.0-rc1 binary 생성. |
| Docker build | PASS | 0 | 16.219 | --network=host; scratch 최종 이미지. |
| directory / Docker / registry scan | PASS | 0, 0, 0 | 0.019 / 0.166 / 1.975 | directory lodash 1개, Docker/registry Alpine 패키지 17개. SBOM의 OS component를 포함하면 Alpine components 18개. SPDX/CycloneDX와 서명 생성. |
| repo / SPDX / archive scan | PASS | 0, 0, 0 | 0.968 / 0.016 / 0.064 | 원본 repo 출력은 W로 지정; SPDX 및 archive/layer 산출물 생성. |
| 기본 DB update | PASS | 0 | 155.479 | OSV+Alpine+Debian+RubySec, 731,758 records, Disk size 3.4 GB. 서명 catalog 생성. |
| DB status / verify / lookup / show | PASS | 0, 0, 0, 0 | 2.170 / 2.169 / 2.120 / 0.565 | 새 catalog 서명/체크섬과 npm lodash/GHSA 조회 확인. |
| match 7형식 | PASS | 0, 0, 0, 0, 0, 0, 0 | 0.566 / 0.566 / 0.616 / 0.616 / 0.616 / 0.616 / 0.616 | 모든 형식에서 양성 fixture 5 findings. CSV 5행/SARIF 5 results/CycloneDX 5 vulnerabilities 및 ID 일치. |
| SPDX match / HIGH threshold | PASS | 0, 2 | 0.616 / 0.616 | SPDX 입력 성공; lodash HIGH 임계값은 기본 종료 2. |
| report 5형식 | PASS | 0, 0, 0, 0, 0 | 0.016 / 0.008 / 0.008 / 0.008 / 0.008 | HTML/Markdown/JSON/CSV/SARIF 저장, JSON 파싱/title 확인. 양성 HTML의 외부 resource 없음도 검사. |
| verify / check / layer check | PASS | 0, 0, 0, 1 | 0.016 / 0.016 / 0.066 / 0.008 | 정상 서명·체크섬 확인; 변조는 오류 1로 거절. |
| batch / scan+match / batch+match | PASS | 0, 2, 2 | 0.169 / 0.565 / 0.716 | 모든 타깃 출력 완료, 취약점 임계값 2여도 SBOM/findings/reports 보존. |
| config show/init | PASS | 0, 1, 0, 0, 0 | 0.008 / 0.016 / 0.016 / 0.008 / 0.017 | 기존 설정 덮어쓰기 거절 1, 새 템플릿에 키 없음, 빈 HOME show는 파일 생성 없음. |
| completion bash/zsh/fish | PASS | 0, 0, 0, 0 | 0.016 / 0.008 / 0.017 / 0.008 | 세 스크립트 생성, bash source 후 complete 등록 확인. zsh/fish shell 실행까지는 하지 않음. |
| offline export/import/match | PASS | 0, 0, 0, 0 | 32.296 / 15.302 / 0.565 / 0.565 | import/verify/match는 unshare -rn; 공개키 pin 성공, online 5 findings와 동일. |
| --memory-limit / BSCAN_MEMORY_LIMIT | PASS | 0, 0, 0, 0 | 0.067 / 0.615 / 0.616 / 0.616 | 64MiB 지정 및 env로 scan/match/batch 성공, match 결과 동일. 잘못된 값은 1, CLI가 잘못된 env를 override. soft Go heap limit이며 RSS 상한/OOM 방지 보장 시험은 아님. |
| --findings-exit-code 7 | FAIL | 2, 2, 2 | 0.565 / 0.616 / 0.716 | 기대 7, 실제 모두 2. 파일은 보존되나 사용자 지정 종료값을 무시(D9). |
| findings code 입력·기타 상태 | PASS | 0, 0, 0, 1, 3, 130 | 0.008 / 0.008 / 0.616 / 0.033 / 0.018 / 1.016 | 허용 범위 1..125 파싱, 잘못된 값은 1. 무취약점 0/실행 오류 1/partial 3/SIGINT 130 유지. |
| root help 새 옵션 | FAIL | 0 | 0.008 | 종료 0이지만 --findings-exit-code/--memory-limit 둘 다 누락(D10). |

### lint / short / CI

| 명령 | 판정 | 종료 | 초 | 관찰 |
| --- | --- | ---: | ---: | --- |
| make lint (첫 실행) | FAIL (환경) | 2 | 34.351 | staticcheck 기본 캐시 `/home/ziozzang/.cache/staticcheck` 쓰기 제한. 소스 분석 결함이 아님. |
| make lint (cache 격리 후) | PASS | 0 | 31.616 | XDG_CACHE_HOME을 W 아래로 지정. staticcheck v0.8.1 및 gosec v2.29.0 모두 완료. |
| make test-short | PASS | 0 | 65.430 | gofmt 검사, go vet, go test -short -race -count=1 ./... 완료. |
| make ci | PASS | 0 | 30.073 | test-short 재실행과 linux/amd64·linux/arm64 정적 binary build 완료. lint는 ci 의존성이 아니므로 별도로 실행. |

### 새 결함과 재현

**D9 / P2 — `--findings-exit-code`가 프로세스 종료에 반영되지 않음.**

새 catalog와 위 lodash fixture를 준비한 뒤 다음 명령을 실행한다. 글로벌 옵션 위치도 명세대로 command 앞이다.

```sh
BONGSU_HOME="$W/update-home" bscan --findings-exit-code 7 match   --fail-on HIGH --format json -o findings7-repro.json rootfs-results/rootfs.cdx.json
# 기대: 7, 실제: 2
BONGSU_HOME="$W/update-home" bscan --findings-exit-code 7 scan   --match --fail-on HIGH --output findings7-scan rootfs
BONGSU_HOME="$W/update-home" bscan --findings-exit-code 7 batch   --match --fail-on HIGH --output findings7-batch rootfs docker://alpine:3.20
# 두 명령 모두 기대: 7, 실제: 2
```

stderr는 `bscan: vulnerabilities meet --fail-on HIGH`(batch는 rootfs prefix 포함). JSON/관련 산출물은 생성된다. 별도 재실행에서도 같은 결과다. `cmd/bscan/main.go`의 `run()`이 `defer restore()`로 `findingsExitCode`를 기본값 2로 복원한 **뒤에** `main()`이 `exitCode(err)`를 호출한다. `findings_exit_code_test.go`는 restore 전의 helper만 검사하므로 test-short/ci가 이 결함을 잡지 못한다. 명령 오류에 선택한 종료값을 보존하거나 process 종료값을 복원 전에 결정하고, 실제 subprocess의 종료값을 검사하는 회귀 테스트가 필요하다. QA의 read-only 범위에 맞춰 수정하지 않았다.

**D10 / P3 — root 도움말에 새 글로벌 옵션 두 개 누락.**

`bscan --help`는 종료 0/stdout이지만 Global flags 목록에 `--findings-exit-code`, `--memory-limit`가 없다. `docs/commands.md`에는 두 옵션이 있고 실제 파서는 수용한다. `globalFlagSet()`과 수동 작성 `usage()`가 불일치한다. stream/verify 명칭을 고친 D4는 통과지만, 옵션 발견 가능성과 generated reference 일치 계약은 새로 실패했다. root help를 같은 flag registry로 생성하거나 목록을 동기화해야 한다.

최신 `8bae539827430d666ecd4e4ba41039d1ba1917d2` 별도 build도 종료 0, 0.866초. 같은 D9 명령은 **2** (0.615초), 최신 root help에도 두 옵션이 없어 두 결함이 남아 있음을 재확인했다.

### D9/D10 수정 (재시험 직후)

- **D9:** `run()`이 글로벌 플래그를 복원하기 전에 종료 상태를 확정하도록 `exitStatusError`로 감싸고, `main()`은 `processExitCode()`로 그 값을 사용한다 (`cmd/bscan/main.go`). 실제 subprocess 종료값을 검사하는 `TestFindingsExitCodeReachesProcessExit`와 in-process 검사를 추가했다.
- **D10:** root 도움말에 `--findings-exit-code`, `--memory-limit`를 추가하고, `globalFlagSet()`의 모든 플래그가 root 도움말에 나타나는지 검사하는 `TestRootHelpListsEveryGlobalFlag`를 추가했다.

### 전체 재실행 기록

아래는 준비 실패/선행 실패를 포함한 실제 실행 기록이다. `$W` 치환 외 명령과 argv를 보존했다. `exec bscan`은 SIGINT를 정확한 프로세스에 전달하기 위한 shell 실행 방식이며 bscan argv는 원래와 같다. `fresh`는 새 signed catalog HOME로 같은 명령을 재실행했다는 뜻이다. `PASS`는 종료값 외에 앞의 산출물 검증을 반영한다. D2의 옛 tmpfs 명령은 실제 성공을 기준으로 PASS다.

| # / 시험 ID | 실제 명령 | cwd / 추가 env | 종료 | 초 | 판정 | 출력·관찰 |
| --- | --- | --- | ---: | ---: | --- | --- |
| 1 / docker-build | `docker build --network=host --platform linux/amd64 -t bscan:u3-acceptance .` | $W/src | 0 | 16.219 | PASS | 기대한 종료값과 동작 확인. |
| 2 / build | `make build VERSION=0.6.0-rc1` | $W/src | 0 | 32.757 | PASS | 기대한 종료값과 동작 확인. |
| 3 / lint | `make lint` | $W/src | 2 | 34.351 | FAIL (환경) | staticcheck 기본 캐시 쓰기 제한; XDG_CACHE_HOME 재지정 후 PASS. |
| 4 / test-short | `make test-short` | $W/src | 0 | 65.430 | PASS | 기대한 종료값과 동작 확인. |
| 5 / D2-default | `docker run --rm --network none --mount type=bind,src=$W/run/rootfs,dst=/input,readonly bscan:u3-acceptance scan --no-sign /input` | $W/run | 0 | 0.367 | PASS | 기대한 종료값과 동작 확인. |
| 6 / D2-create | `docker create --network none --name bscan-u3-inspect bscan:u3-acceptance version` | $W/run | 0 | 0.132 | PASS | 기대한 종료값과 동작 확인. |
| 7 / D2-modes | `docker export bscan-u3-inspect \| python3 -c 'import tarfile,sys; t=tarfile.open(fileobj=sys.stdin.buffer,mode="r\|"); print([(m.name, oct(m.mode),m.uid,m.gid) for m in t if m.name in ["tmp","reports","var/lib/bscan"]])'` | $W/run | 0 | 0.122 | PASS | 기대한 종료값과 동작 확인. |
| 8 / D2-remove | `docker rm bscan-u3-inspect` | $W/run | 0 | 0.116 | PASS | 기대한 종료값과 동작 확인. |
| 9 / D2-readonly | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 --mount "type=bind,src=$PWD,dst=/input,readonly" --mount "type=bind,src=$PWD/scan-results,dst=/reports" bscan:u3-acceptance scan --no-sign --exclude scan-results --workers 2 --output /reports /input` | $W/src | 0 | 0.369 | PASS | 기대한 종료값과 동작 확인. |
| 10 / ci | `make ci` | $W/src | 0 | 30.073 | PASS | 기대한 종료값과 동작 확인. |
| 11 / init | `bscan init --signer ziozzang@gmail.com` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 12 / version | `bscan version` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 13 / about | `bscan about` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 14 / D1-original | `unshare -rn bscan scan registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 15 / D1-output | `unshare -rn bscan scan --output offline-registry registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 16 / D1-env-scan-registry | `unshare -rn bscan scan --output offline-env-scan-registry registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 17 / D1-env-scan-oci | `unshare -rn bscan scan --output offline-env-scan-oci oci://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 18 / D1-env-batch-registry | `unshare -rn bscan batch --output offline-env-batch-registry registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 19 / D1-env-batch-oci | `unshare -rn bscan batch --output offline-env-batch-oci oci://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 20 / D1-config-scan-registry | `unshare -rn bscan --config $W/offline.yaml scan --output offline-config-scan-registry registry://docker.io/library/alpine:3.20` | $W/run | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 21 / D1-config-scan-oci | `unshare -rn bscan --config $W/offline.yaml scan --output offline-config-scan-oci oci://docker.io/library/alpine:3.20` | $W/run | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 22 / D1-config-batch-registry | `unshare -rn bscan --config $W/offline.yaml batch --output offline-config-batch-registry registry://docker.io/library/alpine:3.20` | $W/run | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 23 / D1-config-batch-oci | `unshare -rn bscan --config $W/offline.yaml batch --output offline-config-batch-oci oci://docker.io/library/alpine:3.20` | $W/run | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 24 / D3-workers | `bscan scan --workers -1 --output negative-workers unreadable` | $W/run | 1 | 0.008 | PASS | 음수 병렬도 오류, SBOM 없음. |
| 25 / D3-workers-clean | `bscan scan --workers -1 --output negative-workers-clean rootfs` | $W/run | 1 | 0.008 | PASS | 음수 병렬도 오류, SBOM 없음. |
| 26 / D3-jobs | `bscan batch --jobs -1 --output negative-jobs rootfs` | $W/run | 1 | 0.008 | PASS | 음수 병렬도 오류, SBOM 없음. |
| 27 / D3-batch-workers | `bscan batch --workers -1 --output negative-batch-workers rootfs` | $W/run | 1 | 0.008 | PASS | 음수 병렬도 오류, SBOM 없음. |
| 28 / D4-help-root | `bscan  --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 29 / D4-help-init | `bscan init --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 30 / D4-help-config | `bscan config --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 31 / D4-help-config-show | `bscan config show --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 32 / D4-help-config-init | `bscan config init --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 33 / D4-help-key | `bscan key --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 34 / D4-help-key-show | `bscan key show --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 35 / D4-help-key-generate | `bscan key generate --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 36 / D4-help-key-trust | `bscan key trust --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 37 / D4-help-scan | `bscan scan --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 38 / D4-help-batch | `bscan batch --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 39 / D4-help-hash | `bscan hash --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 40 / D4-help-sign | `bscan sign --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 41 / D4-help-check | `bscan check --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 42 / D4-help-verify | `bscan verify --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 43 / D4-help-scramble | `bscan scramble --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 44 / D4-help-scramble-encrypt | `bscan scramble encrypt --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 45 / D4-help-scramble-decrypt | `bscan scramble decrypt --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 46 / D4-help-encrypt | `bscan encrypt --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 47 / D4-help-decrypt | `bscan decrypt --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 48 / D4-help-db | `bscan db --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 49 / D4-help-db-update | `bscan db update --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 50 / D4-help-db-status | `bscan db status --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 51 / D4-help-db-lookup | `bscan db lookup --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 52 / D4-help-db-show | `bscan db show --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 53 / D4-help-db-verify | `bscan db verify --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 54 / D4-help-db-export | `bscan db export --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 55 / D4-help-db-import | `bscan db import --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 56 / D4-help-db-convert | `bscan db convert --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 57 / D4-help-match | `bscan match --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 58 / D4-help-report | `bscan report --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 59 / D4-help-update | `bscan update --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 60 / D4-help-self-update | `bscan self-update --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 61 / D4-help-version | `bscan version --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 62 / D4-help-about | `bscan about --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 63 / D4-help-help | `bscan help --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 64 / D4-help-completion | `bscan completion --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 65 / D4-help-completion-bash | `bscan completion bash --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 66 / D4-help-completion-zsh | `bscan completion zsh --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 67 / D4-help-completion-fish | `bscan completion fish --help` | $W/run | 0 | 0.008 | PASS | stdout 도움말/stderr 0 bytes, 명칭 확인. |
| 68 / update-init | `bscan init --signer ziozzang@gmail.com` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 69 / D5-cancel-fresh | `exec bscan db update` | $W/run; BONGSU_HOME=$W/interrupt-home | 130 | 2.032 | PASS | 기대한 종료값과 동작 확인. |
| 70 / D5-partial | `bscan scan --fail-on-partial --output negative-strict unreadable` | $W/run | 1 | 0.016 | FAIL (fixture 조건) | target 루트 자체 mode 000; readable root/denied child로 정정 후 재시험. |
| 71 / partial-default | `bscan scan --output negative-partial unreadable` | $W/run | 1 | 0.016 | FAIL (fixture 조건) | target 루트 자체 mode 000; readable root/denied child로 정정 후 재시험. |
| 72 / scan-dir | `bscan scan --verbose --output rootfs-results rootfs` | $W/run | 0 | 0.019 | PASS | 기대한 종료값과 동작 확인. |
| 73 / scan-spdx | `bscan scan --format spdx --output spdx-results rootfs` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 74 / scan-repo | `bscan scan --output $W/run/scan-results .` | $R | 0 | 0.968 | PASS | 기대한 종료값과 동작 확인. |
| 75 / scan-docker | `bscan scan --output results docker://alpine:3.20` | $W/run | 0 | 0.166 | PASS | 기대한 종료값과 동작 확인. |
| 76 / scan-registry | `bscan scan --output registry-results registry://docker.io/library/alpine:3.20` | $W/run | 0 | 1.975 | PASS | 기대한 종료값과 동작 확인. |
| 77 / docker-save | `docker save -o image.tar alpine:3.20` | $W/run | 0 | 0.114 | PASS | 기대한 종료값과 동작 확인. |
| 78 / scan-archive | `bscan scan --verbose --output results image.tar` | $W/run | 0 | 0.064 | PASS | 기대한 종료값과 동작 확인. |
| 79 / check-archive | `bscan check results/image.tar.sha256.sig` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 80 / check-layers | `bscan check --source image.tar results/image.tar.layers.sha256` | $W/run | 0 | 0.066 | PASS | 기대한 종료값과 동작 확인. |
| 81 / verify-dir | `bscan verify --pubkey $W/home/signing.pub rootfs-results/rootfs.spdx.json.sig rootfs-results/rootfs.cdx.json.sig` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 82 / check-docker | `bscan check --pubkey $W/home/signing.pub results/alpine_3.20.cdx.json.sig` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 83 / config-show | `bscan config show` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 84 / config-init-existing | `bscan config init` | $W/run | 1 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 85 / config-init | `bscan config init` | $W/run; BONGSU_HOME=$W/config-home | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 86 / config-show-fresh | `bscan config show` | $W/run; BONGSU_HOME=$W/config-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 87 / config-show-empty | `bscan config show` | $W/run; BONGSU_HOME=$W/empty-config-home | 0 | 0.017 | PASS | 기대한 종료값과 동작 확인. |
| 88 / completion-bash | `bscan completion bash > completion.bash` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 89 / completion-zsh | `bscan completion zsh > completion.zsh` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 90 / completion-fish | `bscan completion fish > completion.fish` | $W/run | 0 | 0.017 | PASS | 기대한 종료값과 동작 확인. |
| 91 / completion-source | `bash -c 'source completion.bash; complete -p bscan'` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 92 / batch | `bscan batch --jobs 4 --sign image-a.tar docker://alpine:3.20 ./rootfs` | $W/run | 0 | 0.169 | PASS | 기대한 종료값과 동작 확인. |
| 93 / db-status | `bscan db status` | $W/run | 1 | 0.828 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 94 / db-verify | `bscan db verify` | $W/run | 1 | 0.114 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 95 / db-lookup | `bscan db lookup npm lodash` | $W/run | 1 | 0.114 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 96 / db-show | `bscan db show GHSA-29mw-wpgm-hmr9` | $W/run | 1 | 0.166 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 97 / fixture-table | `bscan match --format table -o fixture.table rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.179 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 98 / fixture-json | `bscan match --format json -o fixture.json rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.118 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 99 / fixture-cyclonedx | `bscan match --format cyclonedx -o fixture.cyclonedx rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.118 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 100 / fixture-html | `bscan match --format html -o fixture.html rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.166 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 101 / fixture-markdown | `bscan match --format markdown -o fixture.markdown rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.189 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 102 / fixture-csv | `bscan match --format csv -o fixture.csv rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.126 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 103 / fixture-sarif | `bscan match --format sarif -o fixture.sarif rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.120 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 104 / match-spdx | `bscan match --format json -o findings.json results/alpine_3.20.spdx.json` | $W/run | 1 | 0.118 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 105 / match-fail | `bscan match --fail-on HIGH --only-fixed rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.117 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 106 / report-html | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format html -o report.html --title alpine:3.20` | $W/run | 1 | 0.016 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 107 / report-markdown | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format markdown -o report.markdown --title alpine:3.20` | $W/run | 1 | 0.016 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 108 / report-json | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format json -o report.json --title alpine:3.20` | $W/run | 1 | 0.016 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 109 / report-csv | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format csv -o report.csv --title alpine:3.20` | $W/run | 1 | 0.016 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 110 / report-sarif | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format sarif -o report.sarif --title alpine:3.20` | $W/run | 1 | 0.023 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 111 / match-multiple | `bscan match --format json -o multiple-findings.json rootfs-results/rootfs.cdx.json results/alpine_3.20.cdx.json` | $W/run | 1 | 0.170 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 112 / D6-array | `bscan report --from multiple-findings.json --format html` | $W/run | 1 | 0.011 | FAIL (선행 실패) | 구형 catalog 매칭 실패로 입력 미생성; 새 DB로 재실행. |
| 113 / scan-match | `bscan scan --match --report html,sarif --fail-on HIGH --output matched-fixture rootfs` | $W/run | 1 | 0.120 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 114 / batch-match | `bscan batch --match --report html,sarif --fail-on HIGH --output batch-matched rootfs docker://alpine:3.20` | $W/run | 1 | 0.170 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 115 / log-json | `bscan --log-format json match --format json rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.173 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 116 / log-quiet | `bscan -q match rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.171 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 117 / findings7-match | `bscan --findings-exit-code 7 match --fail-on HIGH rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.120 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 118 / findings7-scan | `bscan --findings-exit-code 7 scan --match --fail-on HIGH --output findings7-scan rootfs` | $W/run | 1 | 0.120 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 119 / findings7-batch | `bscan --findings-exit-code 7 batch --match --fail-on HIGH --output findings7-batch rootfs docker://alpine:3.20` | $W/run | 1 | 0.224 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 120 / findings7-no-findings | `bscan --findings-exit-code 7 match --fail-on HIGH results/alpine_3.20.cdx.json` | $W/run | 1 | 0.225 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 121 / findings7-error | `bscan --findings-exit-code 7 scan no-such-target` | $W/run | 1 | 0.033 | PASS | 기대한 종료값과 동작 확인. |
| 122 / findings7-partial | `bscan --findings-exit-code 7 scan --fail-on-partial --output findings7-partial unreadable` | $W/run | 1 | 0.037 | FAIL (fixture 조건) | target 루트 자체 mode 000; readable root/denied child로 정정 후 재시험. |
| 123 / findings-invalid-0 | `bscan --findings-exit-code 0 version` | $W/run | 1 | 0.044 | PASS | 기대한 종료값과 동작 확인. |
| 124 / findings-invalid--1 | `bscan --findings-exit-code -1 version` | $W/run | 1 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 125 / findings-invalid-126 | `bscan --findings-exit-code 126 version` | $W/run | 1 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 126 / findings-invalid-130 | `bscan --findings-exit-code 130 version` | $W/run | 1 | 0.039 | PASS | 기대한 종료값과 동작 확인. |
| 127 / findings-invalid-nonsense | `bscan --findings-exit-code nonsense version` | $W/run | 1 | 0.074 | PASS | 기대한 종료값과 동작 확인. |
| 128 / memory-invalid-0 | `bscan --memory-limit 0 version` | $W/run | 1 | 0.032 | PASS | 잘못된 memory-limit 값 거절. |
| 129 / memory-invalid--1 | `bscan --memory-limit -1 version` | $W/run | 1 | 0.023 | PASS | 잘못된 memory-limit 값 거절. |
| 130 / memory-invalid-nonsense | `bscan --memory-limit nonsense version` | $W/run | 1 | 0.036 | PASS | 잘못된 memory-limit 값 거절. |
| 131 / memory-invalid-999999999999999999999GiB | `bscan --memory-limit 999999999999999999999GiB version` | $W/run | 1 | 0.017 | PASS | 잘못된 memory-limit 값 거절. |
| 132 / memory-scan | `bscan --memory-limit 64MiB scan --output memory-scan rootfs` | $W/run | 0 | 0.067 | PASS | 기대한 종료값과 동작 확인. |
| 133 / memory-match | `bscan --memory-limit 64MiB match --format json -o memory.json rootfs-results/rootfs.cdx.json` | $W/run | 1 | 0.169 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 134 / memory-env | `bscan match --format json -o memory-env.json rootfs-results/rootfs.cdx.json` | $W/run; BSCAN_MEMORY_LIMIT=64MiB | 1 | 0.118 | FAIL (구형 fixture) | 복사 catalog schema 5 거절; 새 DB로 재실행. |
| 135 / memory-override | `bscan --memory-limit 128MiB version` | $W/run; BSCAN_MEMORY_LIMIT=bad | 0 | 0.018 | PASS | 기대한 종료값과 동작 확인. |
| 136 / memory-invalid-env | `bscan version` | $W/run; BSCAN_MEMORY_LIMIT=bad | 1 | 0.016 | PASS | 잘못된 memory-limit 값 거절. |
| 137 / D5-partial-retry | `bscan scan --fail-on-partial --output negative-strict unreadable` | $W/run | 3 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 138 / partial-default-retry | `bscan scan --output negative-partial unreadable` | $W/run | 0 | 0.033 | PASS | 기대한 종료값과 동작 확인. |
| 139 / findings7-partial-retry | `bscan --findings-exit-code 7 scan --fail-on-partial --output findings7-partial unreadable` | $W/run | 3 | 0.018 | PASS | 기대한 종료값과 동작 확인. |
| 140 / lint-retry | `make lint` | $W/src; XDG_CACHE_HOME=$W/xdg-cache | 0 | 31.616 | PASS | 기대한 종료값과 동작 확인. |
| 141 / D2-original-tmpfs | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m --mount "type=bind,src=$PWD,dst=/input,readonly" --mount "type=bind,src=$PWD/scan-results,dst=/reports" bscan:u3-acceptance scan --no-sign --exclude scan-results --workers 2 --output /reports /input` | $W/src | 0 | 0.465 | PASS | 이전 명령 그대로 성공; 이미지 /tmp 수정 확인. |
| 142 / offline-db-update | `unshare -rn bscan db update` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 143 / offline-release-update | `unshare -rn bscan update --check` | $W/run; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 144 / verify-tamper-prepare | `cp rootfs-results/rootfs.cdx.json tampered.cdx.json` | $W/run | 0 | 0.004 | PASS | 기대한 종료값과 동작 확인. |
| 145 / verify-tamper | `bscan verify --pubkey $W/home/signing.pub tamper/rootfs.cdx.json.sig` | $W/run | 1 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 146 / db-update-default | `bscan db update` | $W/run; BONGSU_HOME=$W/update-home | 0 | 155.479 | PASS | 731,758 records; 기본 소스 네 종류; signed catalog. |
| 147 / updated-status | `bscan db status` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.169 | PASS | 기대한 종료값과 동작 확인. |
| 148 / updated-verify | `bscan db verify --pubkey $W/update-home/signing.pub` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.169 | PASS | 기대한 종료값과 동작 확인. |
| 149 / D5-cancel-existing | `exec bscan db update` | $W/run; BONGSU_HOME=$W/update-home | 130 | 3.064 | PASS | 기대한 종료값과 동작 확인. |
| 150 / verify-after-cancel | `bscan db verify --pubkey $W/update-home/signing.pub` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 151 / D8-release | `bscan db export --pubkey $W/update-home/signing.pub catalog.tar.gz` | $W/run; BONGSU_HOME=$W/update-home | 0 | 32.296 | PASS | 2초 lock 후 release, retry 1회, archive 생성. |
| 152 / D8-timeout | `bscan db export --pubkey $W/update-home/signing.pub catalog-busy.tar.gz` | $W/run; BONGSU_HOME=$W/update-home | 1 | 10.041 | PASS | 12초 lock 보유 중 10초 bounded timeout; archive 없음. |
| 153 / db-status-fresh | `bscan db status` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.170 | PASS | 기대한 종료값과 동작 확인. |
| 154 / offline-import | `unshare -rn bscan db import --pubkey $W/update-home/signing.pub catalog.tar.gz` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 15.302 | PASS | 기대한 종료값과 동작 확인. |
| 155 / offline-verify | `unshare -rn bscan db verify --pubkey $W/update-home/signing.pub` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 0.565 | PASS | 기대한 종료값과 동작 확인. |
| 156 / offline-match | `unshare -rn bscan match --pubkey $W/update-home/signing.pub --format json -o offline-findings.json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/airgap-home; BONGSU_OFFLINE=1 | 0 | 0.565 | PASS | 기대한 종료값과 동작 확인. |
| 157 / db-verify-fresh | `bscan db verify` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.169 | PASS | 기대한 종료값과 동작 확인. |
| 158 / db-lookup-fresh | `bscan db lookup npm lodash` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.120 | PASS | 기대한 종료값과 동작 확인. |
| 159 / db-show-fresh | `bscan db show GHSA-29mw-wpgm-hmr9` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.565 | PASS | 기대한 종료값과 동작 확인. |
| 160 / fixture-table-fresh | `bscan match --format table -o fixture.table rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.566 | PASS | 기대한 종료값과 동작 확인. |
| 161 / fixture-json-fresh | `bscan match --format json -o fixture.json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.566 | PASS | 기대한 종료값과 동작 확인. |
| 162 / fixture-cyclonedx-fresh | `bscan match --format cyclonedx -o fixture.cyclonedx rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 163 / fixture-html-fresh | `bscan match --format html -o fixture.html rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 164 / fixture-markdown-fresh | `bscan match --format markdown -o fixture.markdown rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 165 / fixture-csv-fresh | `bscan match --format csv -o fixture.csv rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 166 / fixture-sarif-fresh | `bscan match --format sarif -o fixture.sarif rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 167 / match-spdx-fresh | `bscan match --format json -o findings.json results/alpine_3.20.spdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 168 / match-fail-fresh | `bscan match --fail-on HIGH --only-fixed rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 169 / report-html-fresh | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format html -o report.html --title alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |
| 170 / report-markdown-fresh | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format markdown -o report.markdown --title alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 171 / report-json-fresh | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format json -o report.json --title alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 172 / report-csv-fresh | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format csv -o report.csv --title alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 173 / report-sarif-fresh | `bscan report --from findings.json --sbom results/alpine_3.20.cdx.json --format sarif -o report.sarif --title alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 174 / match-multiple-fresh | `bscan match --format json -o multiple-findings.json rootfs-results/rootfs.cdx.json results/alpine_3.20.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 175 / D6-array-fresh | `bscan report --from multiple-findings.json --format html` | $W/run; BONGSU_HOME=$W/update-home | 1 | 0.008 | PASS | 2 SBOMs; single result/split array 안내. |
| 176 / scan-match-fresh | `bscan scan --match --report html,sarif --fail-on HIGH --output matched-fixture rootfs` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.565 | PASS | 기대한 종료값과 동작 확인. |
| 177 / batch-match-fresh | `bscan batch --match --report html,sarif --fail-on HIGH --output batch-matched rootfs docker://alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.716 | PASS | 기대한 종료값과 동작 확인. |
| 178 / log-json-fresh | `bscan --log-format json match --format json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.566 | PASS | 기대한 종료값과 동작 확인. |
| 179 / log-quiet-fresh | `bscan -q match rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.566 | PASS | 기대한 종료값과 동작 확인. |
| 180 / findings7-match-fresh | `bscan --findings-exit-code 7 match --fail-on HIGH rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.565 | FAIL (D9) | 기대 7, 실제 2; findings 산출물 보존. |
| 181 / findings7-scan-fresh | `bscan --findings-exit-code 7 scan --match --fail-on HIGH --output findings7-scan rootfs` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.616 | FAIL (D9) | 기대 7, 실제 2; findings 산출물 보존. |
| 182 / findings7-batch-fresh | `bscan --findings-exit-code 7 batch --match --fail-on HIGH --output findings7-batch rootfs docker://alpine:3.20` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.716 | FAIL (D9) | 기대 7, 실제 2; findings 산출물 보존. |
| 183 / findings7-no-findings-fresh | `bscan --findings-exit-code 7 match --fail-on HIGH results/alpine_3.20.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 184 / memory-match-fresh | `bscan --memory-limit 64MiB match --format json -o memory.json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.615 | PASS | 기대한 종료값과 동작 확인. |
| 185 / memory-env-fresh | `bscan match --format json -o memory-env.json rootfs-results/rootfs.cdx.json` | $W/run; BSCAN_MEMORY_LIMIT=64MiB; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 186 / memory-batch | `bscan --memory-limit 64MiB batch --match --output memory-batch rootfs` | $W/run; BONGSU_HOME=$W/update-home | 0 | 0.616 | PASS | 기대한 종료값과 동작 확인. |
| 187 / findings7-cancel | `exec bscan --findings-exit-code 7 db update` | $W/run; BONGSU_HOME=$W/findings-cancel-home | 130 | 1.016 | PASS | 기대한 종료값과 동작 확인. |
| 188 / findings-valid-1 | `bscan --findings-exit-code 1 version` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 189 / findings-valid-125 | `bscan --findings-exit-code 125 version` | $W/run | 0 | 0.008 | PASS | 기대한 종료값과 동작 확인. |
| 190 / D1-match-scan | `unshare -rn bscan scan --match --output offline-match-scan registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1; BONGSU_HOME=$W/update-home | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 191 / D1-match-batch | `unshare -rn bscan batch --match --output offline-match-batch registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1; BONGSU_HOME=$W/update-home | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 192 / D1-mixed-batch | `unshare -rn bscan batch --match --fail-on HIGH --output offline-mixed rootfs registry://docker.io/library/alpine:3.20` | $W/run; BONGSU_OFFLINE=1; BONGSU_HOME=$W/update-home | 1 | 0.008 | PASS | offline mode 오류; 외부 네트워크 없는 namespace에서 종료 1. |
| 193 / findings7-repro | `bscan --findings-exit-code 7 match --fail-on HIGH --format json -o findings7-repro.json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.615 | FAIL (D9) | 기대 7, 실제 2; findings 산출물 보존. |
| 194 / new-options-root-help | `bscan --help` | $W/run | 0 | 0.008 | FAIL (D10) | stdout 정상이나 새 글로벌 옵션 2개 누락. |
| 195 / latest-build | `make build VERSION=0.6.0-rc1` | $W/latest-src | 0 | 0.866 | PASS | 기대한 종료값과 동작 확인. |
| 196 / latest-findings7 | `$W/latest-src/dist/bscan --findings-exit-code 7 match --fail-on HIGH --format json -o latest-findings.json rootfs-results/rootfs.cdx.json` | $W/run; BONGSU_HOME=$W/update-home | 2 | 0.615 | FAIL (D9) | 기대 7, 실제 2; findings 산출물 보존. |
| 197 / latest-help | `$W/latest-src/dist/bscan --help` | $W/run | 0 | 0.008 | FAIL (D10) | stdout 정상이나 새 글로벌 옵션 2개 누락. |
| 198 / db-verify-copy | `bscan db verify --db-isolation copy --pubkey $W/update-home/signing.pub` | $W/run; BONGSU_HOME=$W/update-home | 0 | 6.229 | PASS | 기대한 종료값과 동작 확인. |
| 199 / db-verify-none | `bscan db verify --db-isolation none --pubkey $W/update-home/signing.pub` | $W/run; BONGSU_HOME=$W/update-home | 0 | 2.170 | PASS | 기대한 종료값과 동작 확인. |
| 200 / artifact-validation | `python3 $W/validate_final.py` | $W/run | 0 | 0.064 | PASS | 기대한 종료값과 동작 확인. |
| 201 / docker-cleanup | `docker image rm bscan:u3-acceptance` | $W/run | 0 | 0.016 | PASS | 기대한 종료값과 동작 확인. |

### 산출물 검증과 정리

추가 assertion **76개 중 76개 통과**. help stream/title, 서명키 0600, config 부작용, strict partial 출력 없음, SPDX/CycloneDX, 양성 finding IDs와 각 형식의 행 수, HTML 외부 resource 부재, offline/memory 결과 동일, 취소 후 manifest 보존, lock timeout 미완성 파일 부재를 확인했다. `$W/tmp`와 `$W/go-tmp`가 비어 있고 catalog의 db.tmp-*/reader snapshot/SQLite WAL·SHM 잔여물이 없었다. 지속되는 0바이트 lock 파일은 정상이다. memory 시험은 Go soft heap 옵션의 CLI 수용/오류/작업 완료 검증이며 OS RSS 제한 또는 OOM 방지 보장을 입증하지 않는다.

본 재시험은 host 전체·실행 중 container·systemd 설치·self-update 설치·외부 LLM·opt-in NVD/GHSA를 다시 검증하는 범위는 아니다. archive는 directory/docker/registry에 추가해 검사했다. README/deploy의 기존 D7 정정은 사실과 맞아 추가 편집하지 않았고, 이 보고서에만 append했다.

최종 정리: `docker image rm bscan:u3-acceptance` 종료 0 (0.016초), 검사 컨테이너 `bscan-u3-inspect`도 제거했다. `chmod -R u+w "$W"` 후 `shutil.rmtree(W)`로 u3 전체를 삭제하고 경로 부재를 확인했다(종료 0, 2.891초). 원시 로그·키·catalog·archive·clone·모든 작업 캐시를 함께 삭제했다. 기존 Alpine/Go 이미지와 공용 Docker build cache는 유지했다. 원본 보고서 내용은 보존했고 변경 파일은 이 보고서 하나뿐이다.
최종 `git diff --check -- docs/reviews/2026-09-17-acceptance.md`도 종료 0 (0.003초)으로 통과했다.

## Round 7 acceptance (U4)

판정: **reject**. 실제 스캔·서명·CI 종료 코드·오프라인 차단은 통과했지만, findings JSON의 문서 계약과 출력의 차이, 선택 내역의 잘림, 기본 카탈로그 변환의 큰 메모리 사용을 확인했다. 요청한 scan의 `--report json`도 지원하지 않았다. 다음 결과는 이전 회차의 판정을 재사용한 것이 아니라 새 HOME·새 빌드로 직접 실행한 결과다.

### 시험 대상과 재현 조건

- 원본 `/home/ziozzang/bongsu-scanner`, HEAD `2cf5064cd007d683f5a56298ad93de07c948bdc5`. tracked files를 `$W/src`로 복사해 고정했다. 원본은 이 섹션 append 외에는 변경하지 않았으며 상태를 변경하는 git 명령은 실행하지 않았다.
- `W=/home/ziozzang/.cache/bongsu-work/u4`, `R=/home/ziozzang/bongsu-scanner`, 기본 cwd `$W/run`, `PATH=$W/bin:<Go 1.27.1 bin>:<기존 PATH>`, `BONGSU_HOME=$W/home`, `BONGSU_NO_UPDATE_CHECK=1`. 전달된 TMPDIR은 `work-U4`였지만 모든 시험 프로세스에는 `TMPDIR=$W/tmp`, `GOTMPDIR=$W/tmp`를 적용했다.
- `GOCACHE=$W/gocache`, `GOMODCACHE=$W/gomod`, `GOPATH=$W/gopath`, `XDG_CACHE_HOME=$W/xdg`, `BUILDX_CONFIG=$W/buildx`, `GOMAXPROCS=4`, `GOTOOLCHAIN=local`, `GOFLAGS='-p=2 -buildvcs=false'`. 설치된 Go 1.27.1을 직접 선택했다. 모든 `go test`는 GOFLAGS의 `-p=2`를 상속했다. Git 메타데이터를 복사하지 않았으므로 build 정보의 commit/date `unknown`은 의도한 시험 조건이다.
- `make build`는 Makefile 기본값인 **0.1.0**, `make dist VERSION=0.6.0-rc2`의 Linux archive는 **0.6.0-rc2**를 보고했다. 동일 소스의 archive 실행 파일로 후반 시험을 이어갔다. native SHA-256 `6dd910ff48890e04164158e991c1396741161751efe23e8cd6a1c7761b94252c`, rc2 SHA-256 `46824d9b114966ebdb69402bae62e873cc1638135c1b7f581fb928207c086bab`.
- 일반 사용자 UID/GID 1000, Debian 13/linux amd64, Docker 29.5.2. `/usr/bin/time`의 peak RSS(KiB)와 Python monotonic wall time을 기록했다. 일부 독립 작업은 겹쳤다. 소스 빌드/DB 갱신과 겹친 host 시간은 단독 성능 회귀 판정으로 사용하지 않았다.
- 매칭·CI의 기본 DB는 `$W/airgap`에 오프라인 import한 기본 카탈로그다. Ubuntu/VEX 정책 시험은 `$W/home`의 확장 카탈로그를 사용했다. DB writer와 같은 DB reader가 겹치지 않도록 분리했다. `db.prev`는 용량 관리를 위해 필요 없는 세대부터 제거했고, convert 검증 후 변환본도 제거했다.
- 옵션 없는 재갱신과 VEX 갱신에는 `GODEBUG=http2debug=1`(재갱신), `http2debug=2`(VEX)를 추가하여 HTTP 요청·응답을 관측했다. 재갱신은 HTTP/2 프레임과 별도 조건부 HEAD 조회를 함께 대조했다. `$W/bin`의 임시 exec wrapper는 원본 실행 파일에 이 환경값만 추가하고 실제 프로세스 종료값을 보존했다. 제품 코드를 계측·변경하지 않았고, 이후 직접 실행 파일로 복구했다. 아래 취소 로그 판정은 계측 로그와 CLI의 최종 오류를 구분한다.
- Docker daemon의 이미지/레이어 저장은 daemon의 기존 저장소를 사용했다. 기존 `alpine:3.20`은 pull하지 않았고, 이번에 pull한 `ubuntu:24.04`, `golang:1.27.1-alpine` 및 생성한 `bscan:u4-acceptance`는 정리했다. 타 사용자의 컨테이너·이미지·공용 build cache는 prune하지 않았다.

재현용 최소 fixture와 환경은 다음과 같다. source snapshot 복사 후 모든 make/go 명령은 `$W/src`, 나머지는 `$W/run`에서 실행한다. 실제 명령/추가 환경/종료값/시간은 아래 전체 실행표에 있다.

```sh
W=/home/ziozzang/.cache/bongsu-work/u4
R=/home/ziozzang/bongsu-scanner
export W R BONGSU_HOME="$W/home" BONGSU_NO_UPDATE_CHECK=1
export TMPDIR="$W/tmp" GOTMPDIR="$W/tmp" GOCACHE="$W/gocache"
export GOMODCACHE="$W/gomod" GOPATH="$W/gopath" XDG_CACHE_HOME="$W/xdg"
export BUILDX_CONFIG="$W/buildx" GOMAXPROCS=4 GOFLAGS='-p=2 -buildvcs=false'
# PATH에는 설치된 Go 1.27.1의 bin과 $W/bin을 앞에 둔다.
mkdir -p "$W/run/rootfs" "$W/run/unreadable/denied"
printf '%s\n' '{"name":"fixture","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}' > "$W/run/rootfs/package-lock.json"
printf test > "$W/run/unreadable/denied/secret"
chmod 000 "$W/run/unreadable/denied"
```

`rootfs.tar`/`rootfs.tgz`는 이 디렉터리의 tar/gzip이다. orphan fixture는 생성된 CycloneDX lodash component에 `{"name":"bscan:owner","value":"rpm:missing-owner@1"}` property만 추가했다. module fixture는 실제 UBI9 SBOM의 RPM components에 `bscan:modularity=u4:fixture:1:context`를 붙였다. 이 둘은 skip 계약 시험용 합성 입력이며 실제 이미지의 package/version을 발견했다고 주장하지 않는다.

### 단계별 수락 결과

종료값은 **실제 프로세스 값**이다. 의도한 오류 1/2/3/7/130도 기대값과 일치하면 PASS로 표시했다. 아래 요약의 시간/RSS는 해당 대표 실행이며, 각 독립 명령의 값은 전체 실행표에 별도로 있다.

| 단계 | 판정 | 종료 / wall / peak RSS | 확인 내용 |
| --- | --- | --- | --- |
| 1. 소스 빌드 | PASS | 0 / 21.772초 / 781,372 KiB | make build; 0.1.0은 Makefile 기본값 |
| 1. 다섯 portable archives | PASS | 0 / 71.304초 / 807,920 KiB | rc2의 linux amd64/arm64, darwin amd64/arm64, windows amd64; archive 내부 executable·LICENSE·THIRD_PARTY_NOTICES 및 SHA256SUMS 전부 확인 |
| 1. version/about/help/completion | PASS | 0 / 0.018초 / 12,540 KiB | root+모든 문서 명령 경로의 help가 stdout, stderr 0 bytes; bash/zsh/fish 생성, bash 구문·source 확인 |
| 2. init/config | PASS | 0 / 0.006초 / 12,668 KiB | 빈 config show는 파일을 만들지 않음; config init 덮어쓰기 거절; template의 두 피드 제한은 주석 |
| 2. 기본 DB | PASS | 0 / 188.322초 / 1,026,928 KiB | 765,054 records; defaults 출처, 모든 source의 data through 출력, freshness 경고 0 |
| 2. Ubuntu 추가 | PASS | 0 / 358.993초 / 1,504,048 KiB | sources 4개·기존 ecosystem·Alpine release 유지, Ubuntu 저장 |
| 2. 저장 선택 재사용 | PASS | 0 / 285.338초 / 1,532,112 KiB | plain update가 installed catalog 사용; 조건부 요청 및 동일 선택 확인 |
| 2. redhat-vex 추가 | PASS | 0 / 739.981초 / 2,263,104 KiB | OSV Red Hat feed 생략 안내, selection의 Red Hat은 유지, status에 redhat-vex |
| 2. lookup/show/verify | PASS | 0 / 2.622초 / 18,380 KiB | lodash lookup과 GHSA 상세 조회; 서명·manifest 검증 |
| 2. export/import | PASS | 0 / 17.483초 / 21,592 KiB | 별도 BONGSU_HOME, BONGSU_OFFLINE=1 및 네트워크 없는 namespace에서 pinned import/verify/match |
| 2. convert | FAIL (성능), 기능 PASS | 0 / 135.308초 / 10,947,588 KiB | 765,054 records의 변환/후속 verify는 성공; 10.44 GiB peak RSS: U4-D5 |
| 3. 일반 사용자 host | PASS (partial) | 0 / 34.194초 / 239,292 KiB | 54,082 packages; denied=167, partial=true. 첫 실행의 visited=6,053,982. 권한 상승 없이 요청대로 실행 |
| 3. 디렉터리/tar/tgz | PASS | 0 / 0.009초 / 13,644 KiB | SPDX 2.3/CycloneDX 1.6, archive SHA manifest·서명; tar와 tgz 각각 실행 |
| 3. Docker/registry/OCI | PASS | 0 / 1.797초 / 31,544 KiB | docker Ubuntu 24.04와 registry/oci Alpine 3.20 실제 스캔 |
| 3. 실행 중 container | PASS (환경 우회) | 0 / 0.134초 / 28,860 KiB | 기본 docker run은 docker0 부재로 125; 제거 후 --network none 재시작, Running=true 확인 후 스캔 |
| 3. batch/4 reports | PASS | 2 / 1.341초 / 34,952 KiB | 여러 target 및 html/markdown/csv/sarif + 자동 findings JSON; HIGH 게이트 2 |
| 3. 요청한 --report json | FAIL (요청 범위 제한) | 1 / 0.008초 / 12,284 KiB | unsupported report format "json", exit 1. 문서의 네 형식 목록에는 json이 없으므로 문서 위반은 아님. 별도 report --format json은 성공 |
| 3. 실제 custom findings exit | PASS | 7 / 0.636초 / 21,116 KiB | match/scan/batch 세 프로세스 모두 7; 산출물 보존 |
| 3. strict partial | PASS | 3 / 0.018초 / 13,180 KiB | readable root + mode000 child: exit3, SBOM 없음; findings code7을 설정해도 3 |
| 3. SIGINT | PASS | 130 / 7.055초 / 19,580 KiB | 시작 2초 뒤 프로세스 그룹에 SIGINT; CLI 최종 interrupted 1회, manifest 불변, verify 성공 |
| 3. quiet/JSON/memory | PASS | 0 / 0.603초 / 20,280 KiB | Ubuntu coverage warning은 -q에서도 유지; JSON progress의 ts/level/stage/msg 검증; 64MiB soft limit scan/match 완료 |
| 3. severity/filter/details/CPE | PASS | 0 / 1.476초 / 24,412 KiB | cvss/distro/max, exclude-unimportant, only-fixed, details, --cpe 실행 및 결과 대조; NVD 추가 다운로드는 요청 범위 밖 |
| 4. findings JSON | FAIL (문서), 구조 PASS | 0 / 6.384초 / 472,524 KiB | schema/snake_case/string PURL/findings []/counters/skip vocabulary 검사; U4-D1/D2 |
| 4. report round trips | PASS | 0 / 0.009초 / 14,076 KiB | html/markdown/csv/sarif/json; CSV/SARIF 5 findings 일치, HTML 외부 script/link 없음 |
| 4. legacy JSON | PASS | 1 / 0.008초 / 12,412 KiB | 문서의 legacy findings JSON from a pre-release build; re-run bscan match 안내 그대로 |
| 5. CI shell blocks | PASS | 3 / 0.640초 / 21,188 KiB | 모든 sh 및 GitHub/GitLab YAML 내 실행 블록 로컬 실행; GitHub code3→warning/0, GitLab 변환 후3; 실제 hosted actions 제외 |
| 6. UBI OSV/VEX | PASS | 0 / 13.489초 / 54,848 KiB | 같은 UBI9 image: OSV 181 → VEX 823 findings; 아래 status/rating 분포 |
| 6. CentOS Stream | PASS | 0 / 6.353초 / 49,992 KiB | centos-stream-unsupported=145, owner-unmatched=7; OS finding 0을 안전 판정으로 해석하지 않음 |
| 7. 서명/trust/scramble | PASS | 0 / 0.004초 / 3,312 KiB | verify/check/hash/sign, trust name, 암호화/복원 바이트 동일; 유효 v1은 기본 허용, minimum2에서1, v2는0 |
| 7. offline 차단 | PASS | 1 / 0.010초 / 12,412 KiB | registry/oci, scan/batch --match, db update, update/update --check, LLM 모두 offline 오류1; local Docker는0 |
| 8. lint | PASS | 0 / 57.307초 / 1,576,844 KiB | staticcheck/gosec |
| 8. test-short | PASS | 0 / 108.864초 / 852,156 KiB | format/vet/short race tests; -p2 |
| 8. ci | PASS | 0 / 59.644초 / 468,720 KiB | short race tests 및 Linux 두 architecture 빌드 |
| 8. generate | PASS | 0 / 6.114초 / 740,448 KiB | tracked source hash 대조와 commands.md cmp에서 변경 없음 |
| 8. Docker build/smoke | PASS | 0 / 0.404초 / 29,388 KiB | --network=host build, --network none/non-root/read-only/bind reports; 기본 UID:GID 65532:65532 |
| 9. umask | PASS | 0 / 0.009초 / 14,204 KiB | SBOM/서명/findings/5종 보고서: 022→0644, 077→0600; config/private key는 양쪽0600, HOME0700 |
| 9. 문서·표시 정확성 | FAIL | 0 / 2.682초 / 18,428 KiB | findings 어휘·status, Selection 잘림, rubysec help 누락, 크기 단위: 아래 결함표 |

### 카탈로그와 성능 측정

| 선택 | wall 초 | peak RSS KiB | DB 디렉터리 bytes | SQLite bytes | records |
| --- | ---: | ---: | ---: | ---: | ---: |
| default | 188.322 | 1,026,928 | 4,177,499,270 | 3,180,724,224 | 765,054 |
| ubuntu | 358.993 | 1,504,048 | 8,195,817,275 | 6,013,304,832 | 832,344 |
| reuse | 285.338 | 1,532,112 | 8,196,652,859 | 6,014,140,416 | 832,344 |
| vex | 739.981 | 2,263,104 | 10,614,565,603 | 8,104,984,576 | 816,211 |

크기는 DB 디렉터리 내 일반 파일의 논리 크기 합계이며 db.prev·lock·export는 제외했다.
default 크기는 검증한 import 복사본의 실측이다. signed 파일은 원본과 동일하며, unsigned verification receipt 크기는 원본과 미세하게 다를 수 있다.

기본 OSV 다운로드 합계는 673,371,470 bytes로 README의 약 670 MB와 일치했다. Ubuntu 추가 시 다운로드는 687.1이라고 표시됐지만 이는 MiB 값이다(U4-D6). per-source data through가 unknown인 native source도 있었으며, 문서가 허용하는 상태다.

host는 0 / 50.299초 / 236,668 KiB, 같은 SBOM 매칭은 0 / 5.733초 / 381,888 KiB였다. Round 5의 약14초/240MB 및 soak의 23.066초/222,656KiB, match 4.627–6.430초/310,660–357,292KiB와 비교하면 host 시간만 커졌고 메모리는 비슷했다. 이번 host는 다른 작업과 겹쳤으며 GOMAXPROCS=4였으므로 단독 성능 회귀로 확정하지 않는다. partial=true와 167 denied를 결과에서 확인했다.

기본 런타임 재시험(GOMAXPROCS 제한 해제)은 0 / 34.194초 / 239,292 KiB였다. 메모리는 이전 기준에 가깝고 wall은 여전히 컸다. 재시험도 DB 구축과 겹쳤으므로 머신 부하를 배제한 성능 회귀 증명은 아니다.

조건부 HEAD 검증은 동일 ETag/Last-Modified로 **26/27 HTTP304**, RubySec 1개 HTTP200이었다. 첫 보조 HEAD 스크립트의 URL 공백 2건을 percent-encode해 재검증했다(시험 도구 오류). 실제 plain update의 HTTP/2 trace에는 조건부 헤더 및 END_STREAM HEADERS가 보이며, 일반 로그는 상태 코드를 출력하지 않는다. 따라서 26/27이라는 숫자는 보조 HEAD의 실측이며, plain update의 각 HTTP status를 직접 모두 로깅했다고 주장하지 않는다. VEX 업데이트의 debug2 status 집계는 다음과 같다.

`{'304': 25, '200': 1, '302': 1}`

VEX 전체 갱신은 739.981초(12.33분)로 요청의 4–8분 예상보다 길었고 peak RSS는 2.16 GiB였다. Ubuntu를 포함한 전체 갱신·GOMAXPROCS=4·HTTP trace 조건의 수치이므로 README의 VEX 단독 변환 약2분/1GB 미만과 같은 범위로 비교하지 않았다. VEX 변환은 42,232 records, 6,279,678 affected entries, skipped_malformed=0, skipped_oversized=0이었다.

### Findings·정책·CI 상세

- JSON 구조 assertion **468개**, 실패 **0개**. 별도의 문서 어휘 대조는 `owner-unmatched`와 Red Hat status에서 FAIL(U4-D1/D2). 출력에서 확인한 이유: `centos-stream-unsupported, distro-not-affected, distro-owned, ecosystem-not-in-database, missing-version, module-mismatch, no-usable-range, owner-unmatched, unimportant, unknown-ecosystem, withdrawn`. 빈 Alpine 결과는 `findings: []`이며 null이 아니다. 합성 module fixture는 `module-mismatch: 770`, UBI OSV는 `distro-owned: 18`을 확인했다.
- UBI OSV **181**, VEX **823** findings. VEX distro_status 분포: `{'없음': 340, 'workaround-only': 362, 'affected': 22, 'under-investigation': 17, 'fix-deferred': 79, 'will-not-fix': 3}`. distro_severity 분포: `{'high': 95, 'medium': 394, 'low': 332, 'negligible': 2}`. not-affected는 retained finding에 없으며 vendor status와 fixed_in/confidence를 대조했다. 서로 다른 upstream 데이터 공급 범위가 있으므로 finding 수 차이 전체를 오탐/누락 판정으로 해석하지 않았다.
- Ubuntu `cvss`: 59 findings, by_severity `{'HIGH': 34, 'LOW': 8, 'MEDIUM': 17}`.
- Ubuntu `distro`: 59 findings, by_severity `{'LOW': 6, 'MEDIUM': 51, 'NEGLIGIBLE': 2}`.
- Ubuntu `max`: 59 findings, by_severity `{'HIGH': 34, 'LOW': 5, 'MEDIUM': 20}`.
- Ubuntu exclude-unimportant: 57 findings, skipped `{'unimportant': 2, 'unknown-ecosystem': 6, 'withdrawn': 134}`. host에서는 51,603→50,218 findings; only-fixed fixture의 모든 retained hit에 fixed_in이 있었고 --details에서만 본문이 나타났다. CPE 플래그는 실행 완료를 확인했지만 NVD 카탈로그를 수집하지 않아 CPE 양성 정확도는 이 시험에서 입증하지 않았다.
- CI 문서의 2개 sh 블록과 GitHub의 build/PATH-file/date/import/scan/exit 처리, GitLab의 build/PATH/import/scan/Python conversion/exit 블록을 로컬에서 실행했다. 소스 디렉터리 음성 입력에서는 0, lodash 양성 입력에서는 findings3을 실측했다. GitHub 처리 블록은 warning을 쓰고0, GitLab 처리 블록은 변환 JSON을 보존하고3이었다. 변환 결과의 schema version15.2.0과 dependency_scanning envelope를 검사했으며 hosted cache/upload/보안 UI는 실행하지 않았다. 원격 GitLab JSON Schema 전체 검증을 이번 결과로 주장하지 않는다.
- 실제 종료값 0/1/2/3/7/130을 모두 확인했다. SBOM이 없는 partial3, legacy JSON1, 잘못된 global flag 위치1, v1 minimum 거절1, findings 산출물 보존7을 구분했다.

### 결함과 재현

| ID / 심각도 | 재현 및 영향 | file:line 근본 원인 |
| --- | --- | --- |
| U4-D1 / P2 | `bscan -q scan --match --output centos registry://quay.io/centos/centos:stream9` → owner-unmatched:7. 또는 위 orphan fixture에 `bscan match --format json orphan.cdx.json` → owner-unmatched:1, lodash findings5. docs/findings-json.md의 명시적 skip vocabulary에 없는 값이며 owner가 있어도 owner coverage가 없으면 언어 매칭이 유지된다. 새 사용자가 schema consumer/coverage 해석을 문서대로 구현할 수 없다. | `internal/match/match.go:138`–144가 fallback을 구현; `docs/findings-json.md:150`–167에서 owner-unmatched 누락, `:155` 및 `README.md:368`–373은 owner가 있다는 이유만으로 distro-owned로 설명 |
| U4-D2 / P2 | VEX catalog에서 `bscan scan --match --output ubi-vex registry://registry.access.redhat.com/ubi9/ubi:9.4`의 distro_status에 workaround-only/affected/fix-deferred/under-investigation/will-not-fix 상태가 나타난다. findings reference는 undetermined만 설명하여 severity-policy 문서와 불일치한다. | `internal/match/cache.go:275`–279에서 redhat_status를 읽고 `internal/match/match.go:289`–291에서 출력; 문서 `docs/findings-json.md:54` 갱신 누락. 실제 전체 vocabulary는 `docs/severity-policy.md:47`–51 |
| U4-D3 / P3 | `bscan db status` 기본 Selection이 `alpine=v3.18,v3.19,v3.20,v3.21,v3.2...`로 끝난다. 추가 선택도 잘린다. 저장된 meta.json은 정상이나 문서가 안내한 Selection 줄만으로 모든 값을 감사할 수 없다. | `cmd/bscan/db.go:257`, `:336`이 선택 전체 문자열에 `httpx.Sanitize` 적용; `internal/httpx/httpx.go:45`, `:310`–314는 200 rune로 잘라냄 |
| U4-D4 / P3 | `bscan help db update` / docs command reference의 --source 열거에서 기본 source인 rubysec가 빠져 있다. 기본 update/status에는 rubysec가 실제 존재하고 README는 --source에 이를 넣으라고 안내한다. | `cmd/bscan/db.go:290` source help 문자열 누락 → 생성된 `docs/commands.md:485` 부근에 전파; 실제 기본 공급원 `internal/vulndb/source.go:67` 및 등록 `:112` |
| U4-D5 / P2 | 기본 갱신 직후 `bscan db convert --no-keep-raw "$W/converted"`: exit0,135.308초, **10,947,588KiB(10.44GiB)**. 변환 후 verify는 성공하지만 기본 catalog 하나에 약10.4GiB RSS가 필요한 확장성 문제다. 메모리 상한 계약 위반이나 실제 OOM으로 주장하지 않으며, 작은 메모리 환경에서의 실패는 미실측이다. 추가 대용량 반복 시험은 하지 않았다. | `internal/vulndb/convert.go:64`–70에서 모든 Record를 map에 유지한 뒤 `:113`에서 다시 SQLite를 구축. 조회/갱신의 streaming 경로와 달리 catalog 전체가 살아 있음 |
| U4-D6 / P3 | 기본 DB의 논리 bytes 합계4,177,499,270인데 `db status`는 Disk size:3.9 GB라고 표시한다. 이는3.9GiB이며 약4.18GB다. Ubuntu feed도 MiB 계산값을 MB로 표시한다. 바이트 값/문서의 decimal MB와 CLI를 직접 비교하면 단위가 어긋난다. | `internal/vulndb/source.go:524`–531에서 2^30/2^20/2^10으로 나누면서 GB/MB/KB로 표시 |

P1은 재현하지 못했다. `--report html,markdown,csv,sarif,json`의 거절은 요청 범위의 FAIL로 남기되, README/command reference는 네 형식만 약속하므로 문서 위반 결함으로 중복 집계하지 않았다(`cmd/bscan/scanmatch.go:73`–77). 별도 `report --format json`으로 다섯 번째 presentation을 생성할 수 있다. 기본 Docker 브리지 부재, 최초 네트워크 우회 재시도의 이름 충돌, 첫 JSON report 거절에 따른 report 입력 부재는 각각 환경/시험 선행조건 실패로 분리했다. 유효 v1 fixture는 새 local Ed25519 key로 `cmd/bscan/verify_minversion_test.go:19`의 v1 payload/domain 규칙에 따라 서명했다.

### U4 수정 (재시험 직후)

- **U4-D1/D2:** `owner-unmatched`와 Red Hat `distro_status` 값(affected, fix-deferred, will-not-fix, out-of-support-scope, under-investigation, workaround-only)을 `docs/findings-json.md`와 README에 기록했다.
- **U4-D3:** `db status`/`db update`의 Selection 줄은 항목별로 sanitize하여 잘리지 않는다 (`cmd/bscan/db.go` sanitizeSelection, 회귀 테스트 추가).
- **U4-D4:** `--source` 도움말에 rubysec(기본)와 `default` 토큰을 명시했다.
- **U4-D6:** 크기 표시는 이진 단위 표기(GiB/MiB/KiB)로 바꿨다.
- `scan/batch --report json`은 이제 받아들이며(findings JSON은 항상 기록되므로 no-op), 오류 문구도 이를 안내한다.
- **U4-D5:** `db convert`의 전체 레코드 상주 문제는 별도 작업(스트리밍 변환)으로 처리한다.
- host 스캔 성능: 유휴 상태에서 4회 측정 14.4–15.1초, RSS 230–253 MB로 Round 5 기준선(약 14초/240 MB)과 같다. U4의 34–50초는 동시 DB 구축·GOMAXPROCS=4 조건이었다.

### 전체 명령 실행표

`$W`와 `$R`은 위 절대 경로로 치환한다. 기본 cwd는 `$W/run`; cwd/env 열의 `airgap/offline`은 `BONGSU_HOME=$W/airgap BONGSU_OFFLINE=1`이다. GitHub/GitLab 다중행 블록은 docs/ci-integration.md의 해당 YAML run/script 내용을 그대로 실행했으며 아래에 원문을 반복하지 않았다. `retry-` 실행은 json을 제외한 문서상의 report 목록으로 재실행한 기록이다. 성능/문서 FAIL은 종료값 PASS와 별개로 앞 표에서 판정했다.

| ID | 실제 명령 또는 문서 실행 블록 | cwd / 추가 env | exit | wall 초 | 판정 |
| --- | --- | --- | ---: | ---: | --- |
| build | `make build` | $W/src | 0 | 21.772 | PASS |
| version | `bscan version` | $W/run | 0 | 0.008 | PASS |
| version-flag | `bscan --version` | $W/run | 0 | 0.006 | PASS |
| about | `bscan about` | $W/run | 0 | 0.006 | PASS |
| help-root | `bscan --help` | $W/run | 0 | 0.006 | PASS |
| help-init | `bscan help init` | $W/run | 0 | 0.006 | PASS |
| help-config | `bscan help config` | $W/run | 0 | 0.007 | PASS |
| help-config-show | `bscan help config show` | $W/run | 0 | 0.006 | PASS |
| help-config-init | `bscan help config init` | $W/run | 0 | 0.006 | PASS |
| help-key | `bscan help key` | $W/run | 0 | 0.006 | PASS |
| help-key-show | `bscan help key show` | $W/run | 0 | 0.006 | PASS |
| help-key-generate | `bscan help key generate` | $W/run | 0 | 0.007 | PASS |
| help-key-trust | `bscan help key trust` | $W/run | 0 | 0.007 | PASS |
| help-scan | `bscan help scan` | $W/run | 0 | 0.007 | PASS |
| help-batch | `bscan help batch` | $W/run | 0 | 0.008 | PASS |
| help-hash | `bscan help hash` | $W/run | 0 | 0.006 | PASS |
| help-sign | `bscan help sign` | $W/run | 0 | 0.008 | PASS |
| help-check | `bscan help check` | $W/run | 0 | 0.008 | PASS |
| help-verify | `bscan help verify` | $W/run | 0 | 0.007 | PASS |
| help-scramble | `bscan help scramble` | $W/run | 0 | 0.006 | PASS |
| help-scramble-encrypt | `bscan help scramble encrypt` | $W/run | 0 | 0.007 | PASS |
| help-scramble-decrypt | `bscan help scramble decrypt` | $W/run | 0 | 0.007 | PASS |
| help-encrypt | `bscan help encrypt` | $W/run | 0 | 0.006 | PASS |
| help-decrypt | `bscan help decrypt` | $W/run | 0 | 0.007 | PASS |
| help-db | `bscan help db` | $W/run | 0 | 0.007 | PASS |
| help-db-update | `bscan help db update` | $W/run | 0 | 0.008 | PASS |
| help-db-status | `bscan help db status` | $W/run | 0 | 0.006 | PASS |
| help-db-lookup | `bscan help db lookup` | $W/run | 0 | 0.007 | PASS |
| help-db-show | `bscan help db show` | $W/run | 0 | 0.006 | PASS |
| help-db-verify | `bscan help db verify` | $W/run | 0 | 0.007 | PASS |
| help-db-export | `bscan help db export` | $W/run | 0 | 0.007 | PASS |
| help-db-import | `bscan help db import` | $W/run | 0 | 0.007 | PASS |
| help-db-convert | `bscan help db convert` | $W/run | 0 | 0.007 | PASS |
| help-match | `bscan help match` | $W/run | 0 | 0.007 | PASS |
| help-report | `bscan help report` | $W/run | 0 | 0.007 | PASS |
| help-update | `bscan help update` | $W/run | 0 | 0.007 | PASS |
| help-self-update | `bscan help self-update` | $W/run | 0 | 0.007 | PASS |
| help-version | `bscan help version` | $W/run | 0 | 0.007 | PASS |
| help-about | `bscan help about` | $W/run | 0 | 0.007 | PASS |
| help-help | `bscan help help` | $W/run | 0 | 0.006 | PASS |
| help-completion | `bscan help completion` | $W/run | 0 | 0.008 | PASS |
| help-completion-bash | `bscan help completion bash` | $W/run | 0 | 0.007 | PASS |
| help-completion-zsh | `bscan help completion zsh` | $W/run | 0 | 0.007 | PASS |
| help-completion-fish | `bscan help completion fish` | $W/run | 0 | 0.007 | PASS |
| completion-bash | `bscan completion bash > bash.completion` | $W/run | 0 | 0.008 | PASS |
| completion-zsh | `bscan completion zsh > zsh.completion` | $W/run | 0 | 0.007 | PASS |
| completion-fish | `bscan completion fish > fish.completion` | $W/run | 0 | 0.009 | PASS |
| completion-bash-syntax | `bash -n bash.completion` | $W/run | 0 | 0.004 | PASS |
| config-show-empty | `bscan config show` | $W/run ; BONGSU_HOME=$W/config-home | 0 | 0.007 | PASS |
| config-init | `bscan config init` | $W/run ; BONGSU_HOME=$W/config-home | 0 | 0.006 | PASS |
| config-init-refuse | `bscan config init` | $W/run ; BONGSU_HOME=$W/config-home | 1 | 0.006 | PASS |
| init | `bscan init --signer u4-acceptance` | $W/run | 0 | 0.007 | PASS |
| config-show | `bscan config show` | $W/run | 0 | 0.007 | PASS |
| dist | `make dist VERSION=0.6.0-rc2` | $W/src | 0 | 71.304 | PASS |
| scan-host | `bscan scan --timeout 10m --output host-out host` | $W/run | 0 | 50.299 | PASS |
| scan-directory | `bscan scan --sign --output dir-out rootfs` | $W/run | 0 | 0.013 | PASS |
| make-tar | `tar -cf rootfs.tar rootfs` | $W/run | 0 | 0.003 | PASS |
| make-tgz | `tar -czf rootfs.tgz rootfs` | $W/run | 0 | 0.005 | PASS |
| scan-tar | `bscan scan --sign --output tar-out rootfs.tar` | $W/run | 0 | 0.009 | PASS |
| scan-tgz | `bscan scan --sign --output tgz-out rootfs.tgz` | $W/run | 0 | 0.009 | PASS |
| pull-ubuntu | `docker pull ubuntu:24.04` | $W/run | 0 | 2.248 | PASS |
| scan-docker | `bscan scan --output docker-out docker://ubuntu:24.04` | $W/run | 0 | 0.779 | PASS |
| scan-registry | `bscan scan --output registry-out registry://docker.io/library/alpine:3.20` | $W/run | 0 | 1.797 | PASS |
| scan-oci | `bscan scan --output oci-out oci://docker.io/library/alpine:3.20` | $W/run | 0 | 1.789 | PASS |
| container-start | `docker run -d --name u4 alpine:3.20 sleep 600` | $W/run | 125 | 0.518 | FAIL (환경/재시도 조건) |
| container-start-none | `docker run -d --network none --name u4 alpine:3.20 sleep 600` | $W/run | 125 | 0.030 | FAIL (환경/재시도 조건) |
| scan-container | `bscan scan --output container-out container://u4` | $W/run | 0 | 0.150 | PASS |
| container-remove | `docker rm -f u4` | $W/run | 0 | 0.023 | PASS |
| scan-batch | `bscan batch --jobs 2 --sign --output batch-out rootfs rootfs.tar docker://alpine:3.20` | $W/run | 0 | 0.129 | PASS |
| scan-partial | `bscan scan --fail-on-partial --output partial-out unreadable` | $W/run | 3 | 0.018 | PASS |
| scan-memory | `bscan --memory-limit 64MiB scan --output memory-out rootfs` | $W/run | 0 | 0.014 | PASS |
| scan-error | `bscan scan no-such-path` | $W/run | 1 | 0.011 | PASS |
| offline-0 | `unshare -rn bscan scan --output off-reg registry://docker.io/library/alpine:3.20` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.012 | PASS |
| offline-1 | `unshare -rn bscan scan --output off-oci oci://docker.io/library/alpine:3.20` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.012 | PASS |
| offline-2 | `unshare -rn bscan batch --output off-batch rootfs registry://docker.io/library/alpine:3.20` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.012 | PASS |
| offline-3 | `unshare -rn bscan db update` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.014 | PASS |
| offline-4 | `unshare -rn bscan update --check` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.010 | PASS |
| offline-5 | `unshare -rn bscan update` | $W/run ; BONGSU_OFFLINE=1 | 1 | 0.008 | PASS |
| offline-docker | `unshare -rn bscan scan --output offline-docker docker://alpine:3.20` | $W/run ; BONGSU_OFFLINE=1 | 0 | 0.125 | PASS |
| lint | `make lint` | $W/src | 0 | 57.307 | PASS |
| container-retry | `docker run -d --network none --name u4 alpine:3.20 sleep 600` | $W/run | 0 | 0.561 | PASS |
| container-running | `docker inspect --format "{{.State.Running}}" u4` | $W/run | 0 | 0.015 | PASS |
| scan-container-running | `bscan scan --output running-out container://u4` | $W/run | 0 | 0.134 | PASS |
| container-clean | `docker rm -f u4` | $W/run | 0 | 0.109 | PASS |
| key-show | `bscan key show` | $W/run | 0 | 0.008 | PASS |
| key-trust | `bscan key trust u4 "$W/home/signing.pub"` | $W/run | 0 | 0.008 | PASS |
| verify | `bscan verify --pubkey u4 dir-out/rootfs.cdx.json.sig dir-out/rootfs.spdx.json.sig` | $W/run | 0 | 0.008 | PASS |
| check-sig | `bscan check --pubkey u4 tar-out/rootfs.tar.sha256.sig` | $W/run | 0 | 0.008 | PASS |
| check-manifest | `bscan check tar-out/rootfs.tar.sha256` | $W/run | 0 | 0.007 | PASS |
| hash | `bscan hash -o rootfs.sha256 rootfs.tar` | $W/run | 0 | 0.008 | PASS |
| sign | `bscan sign -o rootfs.sha256.sig rootfs.sha256` | $W/run | 0 | 0.009 | PASS |
| check-hash | `bscan check --pubkey u4 rootfs.sha256.sig` | $W/run | 0 | 0.009 | PASS |
| scramble-encrypt | `bscan scramble encrypt --chunk-size 4MiB -o payload.bgs rootfs.tar` | $W/run | 0 | 0.010 | PASS |
| scramble-decrypt | `bscan scramble decrypt --pubkey u4 -o restored.tar payload.bgs` | $W/run | 0 | 0.009 | PASS |
| scramble-compare | `cmp rootfs.tar restored.tar` | $W/run | 0 | 0.004 | PASS |
| signature-v1-default | `bscan verify --pubkey u4 rootfs-v1.sig` | $W/run | 0 | 0.008 | PASS |
| signature-min-v1 | `bscan verify --pubkey u4 rootfs-v1.sig` | $W/run | 1 | 0.007 | PASS |
| signature-min-v2 | `bscan verify --pubkey u4 rootfs.sha256.sig` | $W/run | 0 | 0.008 | PASS |
| permissions-022 | `umask 022; bscan scan --sign --output perm-022 rootfs` | $W/run | 0 | 0.013 | PASS |
| permissions-077 | `umask 077; bscan scan --sign --output perm-077 rootfs` | $W/run | 0 | 0.012 | PASS |
| checksums | `sha256sum -c SHA256SUMS` | $W/src/dist | 0 | 0.037 | PASS |
| version-dist | `tar -xzf "$W/src/dist/bscan_0.6.0-rc2_linux_amd64.tar.gz" -C "$W/bin"; "$W/bin/bscan" version` | $W/run | 0 | 0.107 | PASS |
| docker-base-pull | `docker pull golang:1.27.1-alpine` | $W/run | 0 | 2.238 | PASS |
| docker-build | `docker build --network=host --platform linux/amd64 --build-arg VERSION=0.6.0-rc2 -t bscan:u4-acceptance .` | $W/src | 0 | 22.792 | PASS |
| docker-smoke | `sh deploy/container-smoke.sh bscan:u4-acceptance 0.6.0-rc2` | $W/src | 0 | 0.404 | PASS |
| docker-run-nonroot | `docker run --rm --read-only --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 --mount "type=bind,src=$W/run/rootfs,dst=/input,readonly" --mount "type=bind,src=$W/run/docker-reports,dst=/reports" bscan:u4-acceptance scan --no-sign --workers 2 --output /reports /input` | $W/run | 0 | 0.198 | PASS |
| docker-config | `docker image inspect --format "{{.Config.User}} {{.Config.WorkingDir}}" bscan:u4-acceptance` | $W/run | 0 | 0.017 | PASS |
| db-default | `bscan db update` | $W/run | 0 | 188.322 | PASS |
| db-status-default | `bscan db status` | $W/run | 0 | 2.682 | PASS |
| db-lookup | `bscan db lookup npm lodash` | $W/run | 0 | 0.801 | PASS |
| db-show | `bscan db show GHSA-29mw-wpgm-hmr9` | $W/run | 0 | 0.654 | PASS |
| db-verify | `bscan db verify` | $W/run | 0 | 2.622 | PASS |
| scan-ubi-osv | `bscan scan --match --report html,markdown,csv,sarif,json --output ubi-osv registry://registry.access.redhat.com/ubi9/ubi:9.4` | $W/run | 1 | 0.007 | FAIL (json report 미지원) |
| scan-centos | `bscan -q scan --match --output centos registry://quay.io/centos/centos:stream9` | $W/run | 0 | 7.620 | PASS |
| db-export | `bscan -q db export catalog.tar.gz` | $W/run | 0 | 34.739 | PASS |
| test-short | `make test-short` | $W/src | 0 | 108.864 | PASS |
| db-import | `unshare -rn bscan db import --pubkey "$W/home/signing.pub" catalog.tar.gz` | $W/run ; BONGSU_HOME=$W/airgap, BONGSU_OFFLINE=1 | 0 | 17.483 | PASS |
| db-verify-import | `unshare -rn bscan db verify --pubkey "$W/home/signing.pub"` | $W/run ; BONGSU_HOME=$W/airgap, BONGSU_OFFLINE=1 | 0 | 0.595 | PASS |
| scan-match-formats | `bscan scan --match --report html,markdown,csv,sarif,json --fail-on HIGH --output matched rootfs` | $W/run ; airgap/offline | 1 | 0.008 | FAIL (json report 미지원) |
| batch-match | `bscan batch --match --report html,markdown,csv,sarif,json --fail-on HIGH --output batch-matched rootfs rootfs.tgz docker://alpine:3.20` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (json report 미지원) |
| exit7-match | `bscan --findings-exit-code 7 match --fail-on HIGH --format json -o exit7.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 7 | 2.446 | PASS |
| exit7-scan | `bscan --findings-exit-code 7 scan --match --fail-on HIGH --output exit7-scan rootfs` | $W/run ; airgap/offline | 7 | 0.619 | PASS |
| exit7-batch | `bscan --findings-exit-code 7 batch --match --fail-on HIGH --output exit7-batch rootfs` | $W/run ; airgap/offline | 7 | 0.621 | PASS |
| exit7-partial | `bscan --findings-exit-code 7 scan --fail-on-partial --output exit7-partial unreadable` | $W/run ; airgap/offline | 3 | 0.009 | PASS |
| severity-cvss | `bscan match --severity-source cvss --format json -o severity-cvss.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.611 | PASS |
| severity-distro | `bscan match --severity-source distro --format json -o severity-distro.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.652 | PASS |
| severity-max | `bscan match --severity-source max --format json -o severity-max.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.645 | PASS |
| only-fixed | `bscan match --only-fixed --fail-on HIGH --format json -o fixed.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 2 | 0.648 | PASS |
| details | `bscan match --details --format json -o details.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.640 | PASS |
| exclude-unimportant | `bscan match --exclude-unimportant --format json -o excluded.findings.json host-out/host.cdx.json` | $W/run ; airgap/offline | 0 | 6.146 | PASS |
| cpe | `bscan match --cpe --format json -o cpe.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.619 | PASS |
| quiet-coverage | `bscan -q match --format json -o coverage.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.655 | PASS |
| json-logging | `bscan --log-format json scan --match --output log-json rootfs` | $W/run ; airgap/offline | 0 | 0.621 | PASS |
| match-memory | `bscan --memory-limit 64MiB match --format json -o memory.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.622 | PASS |
| empty-findings | `bscan match --format json -o empty.findings.json registry-out/alpine_3.20.cdx.json` | $W/run ; airgap/offline | 0 | 0.700 | PASS |
| owner-unmatched | `bscan match --format json -o orphan.findings.json orphan.cdx.json` | $W/run ; airgap/offline | 0 | 0.618 | PASS |
| report-html | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format html -o roundtrip.html` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (선행 입력 없음) |
| report-markdown | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format markdown -o roundtrip.markdown` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (선행 입력 없음) |
| report-csv | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format csv -o roundtrip.csv` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (선행 입력 없음) |
| report-sarif | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format sarif -o roundtrip.sarif` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (선행 입력 없음) |
| report-json | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format json -o roundtrip.json` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (선행 입력 없음) |
| ubi-osv-retry | `bscan scan --match --db "$W/airgap/db" --report html,markdown,csv,sarif --output ubi-osv registry://registry.access.redhat.com/ubi9/ubi:9.4` | $W/run | 0 | 18.523 | PASS |
| match-format-table | `bscan match --format table -o match-format.table dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.622 | PASS |
| match-format-json | `bscan match --format json -o match-format.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.625 | PASS |
| match-format-cyclonedx | `bscan match --format cyclonedx -o match-format.cyclonedx dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.656 | PASS |
| match-format-html | `bscan match --format html -o match-format.html dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.618 | PASS |
| match-format-markdown | `bscan match --format markdown -o match-format.markdown dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.633 | PASS |
| match-format-csv | `bscan match --format csv -o match-format.csv dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.622 | PASS |
| match-format-sarif | `bscan match --format sarif -o match-format.sarif dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.641 | PASS |
| legacy-reject | `bscan report --from legacy.json --format html` | $W/run ; airgap/offline | 1 | 0.008 | PASS |
| placement-error | `bscan scan --findings-exit-code 3 rootfs` | $W/run ; airgap/offline | 1 | 0.007 | PASS |
| report-permissions-022 | `umask 022; bscan scan --match --report html,markdown,csv,sarif,json --output report-perm-022 rootfs` | $W/run ; airgap/offline | 1 | 0.007 | FAIL (json report 미지원) |
| report-permissions-077 | `umask 077; bscan scan --match --report html,markdown,csv,sarif,json --output report-perm-077 rootfs` | $W/run ; airgap/offline | 1 | 0.008 | FAIL (json report 미지원) |
| ci | `make ci` | $W/src | 0 | 59.644 | PASS |
| generate | `go generate ./cmd/bscan` | $W/src | 0 | 6.114 | PASS |
| generate-no-diff | `cmp docs/commands.md "$R/docs/commands.md"` | $W/src | 0 | 0.004 | PASS |
| ci-shell-0 | `bscan -q db export ci-catalog.tar.gz ;` | $W/src ; airgap/offline | 0 | 38.979 | PASS |
| ci-shell-1 | `bscan --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out . ;` | $W/src ; airgap/offline | 0 | 0.716 | PASS |
| ci-github-2 | `go build -o "$BSCAN_BIN/bscan" ./cmd/bscan ; echo "$BSCAN_BIN" >> "$GITHUB_PATH" ;` | $W/src ; airgap/offline | 0 | 0.721 | PASS |
| ci-github-3 | `echo "date=$(date -u +%F)" >> "$GITHUB_OUTPUT"` | $W/src ; airgap/offline | 0 | 0.005 | PASS |
| ci-github-5 | `bscan db import catalog.tar.gz` | $W/src ; airgap/offline | 0 | 19.085 | PASS |
| ci-github-6 | `status=0 ; bscan --memory-limit 512MiB --log-format json --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out . \|\| status=$? ; echo "status=$status" >> "$GITHUB_OUTPUT" ; case "$status" in ;   0) ;; ;   3) echo "::warning::bscan findings meet HIGH; see SARIF and findings artifacts" ;; ;   *) exit "$status" ;; ; esac ;` | $W/src ; airgap/offline | 0 | 0.666 | PASS |
| ci-gitlab-build | `go build -o "$BSCAN_BIN/bscan" ./cmd/bscan` | $W/src ; airgap/offline | 0 | 0.085 | PASS |
| ci-gitlab-path | `export PATH="$BSCAN_BIN:$PATH"; command -v bscan` | $W/src ; airgap/offline | 0 | 0.002 | PASS |
| ci-gitlab-import | `bscan db import catalog.tar.gz` | $W/src ; airgap/offline | 0 | 18.225 | PASS |
| ci-gitlab-scan-convert | `docs/ci-integration.md GitLab script[3] (Python conversion 포함)` | $W/src ; airgap/offline | 0 | 0.730 | PASS |
| ci-github-positive | `status=0 ; bscan --memory-limit 512MiB --log-format json --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out . \|\| status=$? ; echo "status=$status" >> "$GITHUB_OUTPUT" ; case "$status" in ;   0) ;; ;   3) echo "::warning::bscan findings meet HIGH; see SARIF and findings artifacts" ;; ;   *) exit "$status" ;; ; esac ;` | $W/run/rootfs ; airgap/offline | 0 | 0.632 | PASS |
| ci-gitlab-positive | `docs/ci-integration.md GitLab script[3] (Python conversion 포함)` | $W/run/rootfs ; airgap/offline | 3 | 0.640 | PASS |
| retry-scan-match-formats | `bscan scan --match --report html,markdown,csv,sarif --fail-on HIGH --output matched rootfs` | $W/run ; airgap/offline | 2 | 0.603 | PASS |
| retry-batch-match | `bscan batch --match --report html,markdown,csv,sarif --fail-on HIGH --output batch-matched rootfs rootfs.tgz docker://alpine:3.20` | $W/run ; airgap/offline | 2 | 1.341 | PASS |
| retry-exit7-match | `bscan --findings-exit-code 7 match --fail-on HIGH --format json -o exit7.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 7 | 0.600 | PASS |
| retry-exit7-scan | `bscan --findings-exit-code 7 scan --match --fail-on HIGH --output exit7-scan rootfs` | $W/run ; airgap/offline | 7 | 0.636 | PASS |
| retry-exit7-batch | `bscan --findings-exit-code 7 batch --match --fail-on HIGH --output exit7-batch rootfs` | $W/run ; airgap/offline | 7 | 0.617 | PASS |
| retry-exit7-partial | `bscan --findings-exit-code 7 scan --fail-on-partial --output exit7-partial unreadable` | $W/run ; airgap/offline | 3 | 0.009 | PASS |
| retry-severity-cvss | `bscan match --severity-source cvss --format json -o severity-cvss.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.611 | PASS |
| retry-severity-distro | `bscan match --severity-source distro --format json -o severity-distro.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.609 | PASS |
| retry-severity-max | `bscan match --severity-source max --format json -o severity-max.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.600 | PASS |
| retry-only-fixed | `bscan match --only-fixed --fail-on HIGH --format json -o fixed.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 2 | 0.605 | PASS |
| retry-details | `bscan match --details --format json -o details.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.614 | PASS |
| retry-exclude-unimportant | `bscan match --exclude-unimportant --format json -o excluded.findings.json host-out/host.cdx.json` | $W/run ; airgap/offline | 0 | 5.885 | PASS |
| retry-cpe | `bscan match --cpe --format json -o cpe.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.614 | PASS |
| retry-quiet-coverage | `bscan -q match --format json -o coverage.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run ; airgap/offline | 0 | 0.618 | PASS |
| retry-json-logging | `bscan --log-format json scan --match --output log-json rootfs` | $W/run ; airgap/offline | 0 | 0.616 | PASS |
| retry-match-memory | `bscan --memory-limit 64MiB match --format json -o memory.findings.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.603 | PASS |
| retry-empty-findings | `bscan match --format json -o empty.findings.json registry-out/alpine_3.20.cdx.json` | $W/run ; airgap/offline | 0 | 0.648 | PASS |
| retry-owner-unmatched | `bscan match --format json -o orphan.findings.json orphan.cdx.json` | $W/run ; airgap/offline | 0 | 0.606 | PASS |
| retry-report-html | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format html -o roundtrip.html` | $W/run ; airgap/offline | 0 | 0.009 | PASS |
| retry-report-markdown | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format markdown -o roundtrip.markdown` | $W/run ; airgap/offline | 0 | 0.009 | PASS |
| retry-report-csv | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format csv -o roundtrip.csv` | $W/run ; airgap/offline | 0 | 0.008 | PASS |
| retry-report-sarif | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format sarif -o roundtrip.sarif` | $W/run ; airgap/offline | 0 | 0.009 | PASS |
| retry-report-json | `bscan report --from matched/rootfs.findings.json --sbom matched/rootfs.cdx.json --format json -o roundtrip.json` | $W/run ; airgap/offline | 0 | 0.009 | PASS |
| retry-match-format-table | `bscan match --format table -o match-format.table dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.599 | PASS |
| retry-match-format-json | `bscan match --format json -o match-format.json dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.603 | PASS |
| retry-match-format-cyclonedx | `bscan match --format cyclonedx -o match-format.cyclonedx dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.621 | PASS |
| retry-match-format-html | `bscan match --format html -o match-format.html dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.614 | PASS |
| retry-match-format-markdown | `bscan match --format markdown -o match-format.markdown dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.607 | PASS |
| retry-match-format-csv | `bscan match --format csv -o match-format.csv dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.611 | PASS |
| retry-match-format-sarif | `bscan match --format sarif -o match-format.sarif dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 0 | 0.613 | PASS |
| retry-legacy-reject | `bscan report --from legacy.json --format html` | $W/run ; airgap/offline | 1 | 0.008 | PASS |
| retry-placement-error | `bscan scan --findings-exit-code 3 rootfs` | $W/run ; airgap/offline | 1 | 0.007 | PASS |
| retry-report-permissions-022 | `umask 022; bscan scan --match --report html,markdown,csv,sarif --output report-perm-022 rootfs` | $W/run ; airgap/offline | 0 | 0.612 | PASS |
| retry-report-permissions-077 | `umask 077; bscan scan --match --report html,markdown,csv,sarif --output report-perm-077 rootfs` | $W/run ; airgap/offline | 0 | 0.608 | PASS |
| db-convert | `bscan db convert --no-keep-raw "$W/converted"` | $W/run | 0 | 135.308 | PASS |
| db-verify-convert | `bscan db verify --db "$W/converted"` | $W/run | 0 | 2.272 | PASS |
| module-mismatch | `bscan match --format json -o module.findings.json modular.cdx.json` | $W/run ; airgap/offline | 0 | 1.352 | PASS |
| host-match-baseline | `bscan match --format json -o host.findings.json host-out/host.cdx.json` | $W/run ; airgap/offline | 0 | 5.733 | PASS |
| offline-extra-0 | `unshare -rn bscan scan --match --output offline-scan registry://docker.io/library/alpine:3.20` | $W/run ; airgap/offline | 1 | 0.009 | PASS |
| offline-extra-1 | `unshare -rn bscan batch --match --output offline-batch rootfs oci://docker.io/library/alpine:3.20` | $W/run ; airgap/offline | 1 | 0.009 | PASS |
| offline-extra-2 | `unshare -rn bscan match --llm --llm-base-url https://example.invalid/v1 --llm-model example dir-out/rootfs.cdx.json` | $W/run ; airgap/offline | 1 | 0.008 | PASS |
| negative-workers | `bscan scan --workers -1 rootfs` | $W/run ; airgap/offline | 1 | 0.007 | PASS |
| negative-jobs | `bscan batch --jobs -1 rootfs` | $W/run ; airgap/offline | 1 | 0.007 | PASS |
| report-json-input-rejected | `bscan report --from roundtrip.json` | $W/run ; airgap/offline | 1 | 0.008 | PASS |
| report-validations | `python3 "$W/report_validate.py"` | $W/run ; airgap/offline | 0 | 0.045 | PASS |
| rc2-buildinfo | `bscan version; bscan --version; bscan about` | $W/run | 0 | 0.018 | PASS |
| config-show-no-files | `BONGSU_HOME="$W/show-only" bscan config show; test ! -e "$W/show-only"` | $W/run | 0 | 0.008 | PASS |
| completion-load | `source bash.completion; declare -F _bscan >/dev/null` | $W/run | 0 | 0.038 | PASS |
| db-add-ubuntu | `bscan db update --add-ecosystem Ubuntu` | $W/run | 0 | 358.993 | PASS |
| db-status-ubuntu | `bscan db status` | $W/run | 0 | 4.771 | PASS |
| conditional-headers | `python3 "$W/conditional.py"` | $W/run | 0 | 11.742 | PASS |
| conditional-encoded | `python3 "$W/conditional.py"` | $W/run | 0 | 14.159 | PASS |
| init-permissions-022 | `umask 022; bscan init --signer u4` | $W/run ; BONGSU_HOME=$W/identity-022 | 0 | 0.009 | PASS |
| json-report-permissions-022 | `umask 022; bscan report --from matched/rootfs.findings.json --format json -o report-perm-022/rootfs.report.json` | $W/run | 0 | 0.009 | PASS |
| init-permissions-077 | `umask 077; bscan init --signer u4` | $W/run ; BONGSU_HOME=$W/identity-077 | 0 | 0.009 | PASS |
| json-report-permissions-077 | `umask 077; bscan report --from matched/rootfs.findings.json --format json -o report-perm-077/rootfs.report.json` | $W/run | 0 | 0.009 | PASS |
| db-reuse | `bscan db update` | $W/run | 0 | 285.338 | PASS |
| db-status-reuse | `bscan db status` | $W/run | 0 | 4.754 | PASS |
| docker-cleanup | `docker rmi bscan:u4-acceptance ubuntu:24.04 golang:1.27.1-alpine` | $W/run | 0 | 0.045 | PASS |
| scan-host-default-runtime | `bscan scan --timeout 10m --output host-default host` | $W/run ; GOMAXPROCS= | 0 | 34.194 | PASS |
| environment | `id; cat /etc/os-release; go version; docker version --format "{{.Client.Version}} / {{.Server.Version}}"` | $W/run | 0 | 0.030 | PASS |
| db-add-vex | `bscan db update --add-source redhat-vex` | $W/run | 0 | 739.981 | PASS |
| db-status-vex | `bscan db status` | $W/run | 0 | 7.305 | PASS |
| scan-ubi-vex | `bscan scan --match --report html,markdown,csv,sarif,json --output ubi-vex registry://registry.access.redhat.com/ubi9/ubi:9.4` | $W/run | 1 | 0.008 | FAIL (json report 미지원) |
| scan-centos-vex | `bscan -q scan --match --output centos-vex registry://quay.io/centos/centos:stream9` | $W/run | 0 | 6.353 | PASS |
| db-interrupt | `exec bscan db update` | $W/run | 130 | 7.055 | PASS |
| db-verify-interrupt | `bscan db verify` | $W/run | 0 | 6.139 | PASS |
| ubi-vex-retry | `bscan scan --match --report html,markdown,csv,sarif --output ubi-vex registry://registry.access.redhat.com/ubi9/ubi:9.4` | $W/run | 0 | 13.489 | PASS |
| ubuntu-policy-cvss | `bscan match --severity-source cvss --format json -o ubuntu-cvss.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run | 0 | 1.481 | PASS |
| ubuntu-policy-distro | `bscan match --severity-source distro --format json -o ubuntu-distro.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run | 0 | 1.476 | PASS |
| ubuntu-policy-max | `bscan match --severity-source max --format json -o ubuntu-max.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run | 0 | 1.478 | PASS |
| ubuntu-exclude | `bscan match --exclude-unimportant --format json -o ubuntu-excluded.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run | 0 | 1.481 | PASS |
| ubuntu-details | `bscan match --details --format json -o ubuntu-details.findings.json docker-out/ubuntu_24.04.cdx.json` | $W/run | 0 | 1.483 | PASS |
| ubi-vex-details | `bscan match --details --format json -o vex-details.findings.json ubi-vex/ubi_9.4.cdx.json` | $W/run | 0 | 3.412 | PASS |
| vex-verify | `bscan db verify` | $W/run | 0 | 6.146 | PASS |
| artifact-validation | `python3 "$W/validate.py"` | $W/run | 0 | 6.384 | PASS |
| ci-github-built-binary | `status=0 ; bscan --memory-limit 512MiB --log-format json --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out . \|\| status=$? ; echo "status=$status" >> "$GITHUB_OUTPUT" ; case "$status" in ;   0) ;; ;   3) echo "::warning::bscan findings meet HIGH; see SARIF and findings artifacts" ;; ;   *) exit "$status" ;; ; esac ;` | $W/run/rootfs ; BONGSU_HOME=$W/home BONGSU_OFFLINE=1 PATH=$W/ci-bin:... | 0 | 6.768 | PASS |
| init-plain | `bscan init` | $W/run ; BONGSU_HOME=$W/plain-init | 0 | 0.009 | PASS |
| final-artifact-validation | `python3 "$W/validate.py"` | $W/run | 0 | 6.213 | PASS |
| policy-validation | `python3 "$W/policy_validate.py"` | $W/run | 0 | 0.040 | PASS |
| final-check | `python3 "$W/final_check.py"` | $W/run | 0 | 0.062 | PASS |

### 정리와 판정의 한계

원본 변경 여부는 snapshot hash와 git diff로 확인했다. 이번 회차에서는 플랫폼별 archive의 cross-build/내용/checksum을 검사했으며 macOS/Windows native 실행, self-update 설치, publisher release 배포, systemd/cron 설치, 원격 CI 업로드, LLM 서버 호출, NVD/GHSA/Chainguard 추가 대용량 수집은 수행하지 않았다. 이 범위를 실행했다고 주장하지 않는다.

마지막 추가 검사에서 SPDX-2.3/CycloneDX 1.6, 실행 중 container=true, SIGINT 최종 오류 1회, manifest 불변, DB staging/TMPDIR 잔류 없음, HOME0700 및 원본 tracked 파일 hash 일치를 확인했다.

최종 정리: `docker rmi bscan:u4-acceptance ubuntu:24.04 golang:1.27.1-alpine` 종료 **0**, **0.045초**. 세 tag와 시험 container `u4`의 부재를 재확인했다. 권한을 복구한 뒤 `shutil.rmtree("/home/ziozzang/.cache/bongsu-work/u4")`로 카탈로그·export·키·모든 임시 소스/캐시/로그/보고서 원시 산출물을 삭제했다. 삭제 종료 **0**, **2.870초**, 경로 부재 확인. 기존 alpine:3.20과 공용 Docker build cache는 유지했다.
최종 `git diff --check -- docs/reviews/2026-09-17-acceptance.md`: 종료 **0**, **0.004초**. 원본 내용은 보존되었고 변경 파일은 이 보고서 하나다. 최종 판정은 **reject**이며 P1 0건, P2 3건, P3 3건이다.
