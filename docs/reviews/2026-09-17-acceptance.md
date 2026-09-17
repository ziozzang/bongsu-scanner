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
