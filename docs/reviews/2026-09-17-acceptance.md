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
