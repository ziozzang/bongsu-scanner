# bongsu (봉수)

Zero-trust asset inventory and vulnerability scanner — a fully static Rust node scanner (`bongsu-node`) and a small collection server (`bongsu-hub`).

정적 Rust 실행 파일 하나로 호스트·컨테이너 이미지의 구성요소(SBOM, SPDX)를 읽고, 서명된 공개 취약점 자료(secdb)와 대조하는 봉수 노드 스캐너와 결과를 모으는 서버입니다.

## 받기 / Download

배포판은 [Releases](https://github.com/ziozzang/bongsu-scanner/releases) 에 있습니다(현재 사전 배포판 `node-v0.1.0-rcN`).

- `bongsu-node-*-linux.zip` — 노드 스캐너 (x86_64, aarch64, 정적 musl)
- `bongsu-hub-*-linux.zip` — 수집 서버
- `SHA256SUMS` — 체크섬

취약점 자료(secdb)는 [ziozzang/bongsu-secdb](https://github.com/ziozzang/bongsu-secdb/releases) 에서 서명과 함께 배포됩니다.

## 빠른 시작 / Quick start

```sh
unzip bongsu-node-*-x86_64-linux.zip
./bongsu-node --version
./bongsu-node scan -o host.spdx.json             # 이 호스트 스캔
./bongsu-node query host.spdx.json "SELECT name, version FROM packages LIMIT 10"
```

서버 가입: 서버 관리자가 `bongsu-hub join-code issue` 로 8자리 일회용 코드를 발급하고, 노드에서 `bongsu-node join --hub https://HOST:8443 --code CODE` (지문 확인 후 `--pin`) 로 가입합니다. 자세한 사용법은 각 ZIP 안의 README·UPLOAD·QUERY 문서를 보세요.

## 이 저장소 / This repository

이 저장소는 배포판을 올리는 곳입니다. 예전 Go 구현(`bscan` v0.1–v0.5)은 2026-11-05 정리했습니다(이력은 git 기록에 남아 있습니다).

Copyright Jioh L. Jung <jung@jioh.net> — AGPL-3.0-only
