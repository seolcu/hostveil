**[English](README.md)** | 한국어

# hostveil

> Docker Compose를 중심으로 한 Linux 셀프호스팅 환경용 경량 통합 보안 대시보드

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Jellyfin, Nextcloud, Vaultwarden, Gitea, Immich 등을 운영하는 셀프호스터는 보안 상태를 확인하기 위해 Lynis, Trivy, Dockle, Docker Bench, Fail2ban, CrowdSec 같은 도구를 각각 따로 설치하고 해석해야 합니다. hostveil은 이런 신호를 하나의 터미널 중심 워크플로로 통합하는 것을 목표로 합니다. 심각도 순으로 정렬된 점수화된 발견 사항, 셀프호스팅 맥락에 맞춘 설명, 그리고 구체적인 해결 가이드를 한 번에 제공합니다.

[Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (실행 가능한 가이드를 포함한 점수화 감사)와 [btop](https://github.com/aristocratos/btop) (경량 TUI 디자인)에서 영감을 받았습니다.

## 주요 기능

- **보안 개요 대시보드** — 카테고리별 세부 점수 및 심각도 카운트를 포함한 전체 점수
- **셀프호스팅 맥락 기반 기본 점검** — 각 서비스의 데이터 위치, Compose 구조, 운영 위험을 반영한 점검
- **선택적 외부 스캐너 어댑터** — 런타임 의존성으로 강제하지 않으면서 기존 도구 결과를 통합
- **실행 가능한 가이드** — 모든 발견 사항에 포함: 무엇인지, 왜 위험한지, 어떻게 수정하는지
- **Compose 중심 수정 흐름** — `quick-fix`와 `fix`는 미리보기와 백업이 가능한 Compose 변경에 집중

## Rust V1 방향

- **Linux 우선 런타임** — 실제 제품의 공식 타깃은 Linux 셀프호스팅 서버이며, Windows 기여자는 WSL을 사용하는 것을 전제로 합니다
- **통합 우선 전략** — hostveil은 기존 도구를 모두 다시 만드는 대신, 기본 점검과 선택적 외부 스캐너 결과를 함께 보여줍니다
- **TUI 우선 + JSON export 보조** — 주 경험은 대화형 TUI이고, 자동화와 회귀 테스트를 위해 최소한의 JSON 출력 경로를 둡니다
- **호스트 보안도 제품 범위에 포함** — SSH 같은 Host Hardening 신호를 별도 도구가 아니라 같은 제품 안에서 다룹니다
- **자동 수정 범위는 v1에서 좁게 유지** — 자동 쓰기는 Compose 중심 변경에 한정하고, 위험한 변경은 검토 흐름으로 남깁니다

## 목표 점검 축

| 축 | 점검 내용 |
|---|---|
| 민감 정보 노출 | `.env` 파일, 평문/기본 자격증명, 볼륨 내 시크릿 |
| 과도한 권한 | `privileged: true`, root 실행, 광범위한 볼륨 마운트, `network_mode: host` |
| 불필요한 외부 노출 | 공개 포트, 관리자 페이지, 리버스 프록시 우회 서비스 |
| 업데이트/공급망 위험 | `latest` 태그 남용, 버전 고정 부재, 오래된 이미지, 이미지 신뢰 신호 |
| 호스트 하드닝 | SSH 설정, Docker 호스트 노출, 서버 측 방어 수단 |

## 설치

Rust 릴리스는 GitHub Releases를 통해 Linux 바이너리로 제공합니다. `proto/` 안의 Python 프로토타입은 Compose 파싱, 점수화, 수정 흐름을 설명하는 고정된 참고 구현으로 유지되고, 실제 제품 개발은 `src/`에서 진행합니다.

hostveil 릴리스 태그는 `vX.Y.Z`, 크레이트와 바이너리 버전은 `X.Y.Z` 형식을 사용합니다. 호환성을 의도적으로 안정화했다고 선언하기 전까지는 prerelease 접미사 대신 `0.Y.Z` 라인을 유지합니다.

실제 제품의 공식 런타임 지원 대상은 Linux입니다. Windows에서 개발할 경우 native PowerShell 대신 WSL 사용을 권장합니다.

현재 Rust 부트스트랩 개발 환경은 저장소 루트에서 다음처럼 시작할 수 있습니다.

```sh
rustup default stable
cargo build
cargo run -- --help
cargo run
cargo run -- --json

# 스냅샷/타깃 테스트용 고급 override
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
```

현재 릴리스 전달 경로:

- `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`용 GitHub Releases tarball
- 릴리스 아티팩트 검증용 `SHA256SUMS`
- 호스트 아키텍처에 맞는 Linux 바이너리를 선택하는 작은 설치 스크립트
- Docker, Trivy 같은 외부 도구는 번들하지 않고 `PATH`에서 선택적으로 탐지
- 첫 설치는 installer script로, 이후 업그레이드/자동 업데이트 토글/삭제는 설치된 `hostveil` 명령으로 수행

최신 릴리스 설치:

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

최초 설치 이후 라이프사이클 명령:

```sh
hostveil upgrade
hostveil auto-upgrade disable
hostveil auto-upgrade enable
hostveil uninstall
```

현재 참고용 프로토타입 실행 방법:

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"
```

## 사용법

고정된 참고용 프로토타입 CLI는 Compose 파일 또는 디렉터리를 대상으로 실행할 수 있습니다.

```sh
python -m hostveil scan path/to/docker-compose.yml
python -m hostveil quick-fix path/to/docker-compose.yml --preview-changes --yes
python -m hostveil fix path/to/docker-compose.yml --preview-changes --yes
```

## 현황

hostveil은 현재 초기 개발 단계입니다. 구현은 두 단계로 계획되어 있습니다.

1. **Python CLI 프로토타입** — Compose 파서, 핵심 규칙, 점수화, 수정 흐름을 검증한 참고 구현
2. **Rust TUI** — 실제 제품 구현 단계

프로토타입에서 검증된 기준:

- 기본 override 병합을 포함한 Docker Compose 파싱
- 네 가지 감사 축: 민감 정보, 권한, 노출, 업데이트 위험
- 심각도 카운트와 축별 점수를 포함한 점수화 모델
- ANSI 스타일을 쓰는 터미널 스캔 리포트(환경 변수 `NO_COLOR`로 비활성화 가능)
- 백업, 변경 미리보기(`--preview-changes`), 확인 절차를 포함한 `quick-fix` 흐름
- 안전 수정과 검토가 필요한 가이드 수정까지 함께 적용하는 `fix` 흐름

계획된 Rust v1 범위:

- 서비스, 호스트, 이미지, 프로젝트 범위를 함께 다루는 finding 모델
- Host Hardening을 포함한 다섯 가지 축
- SSH와 Docker host posture를 다루는 Linux 기본 점검
- Trivy부터 시작하는 선택적 외부 스캐너 통합
- TUI 우선 워크플로와 최소한의 headless JSON export
- Linux 전용 런타임과 WSL 기반 기여 경로

현재 Rust 부트스트랩 상태:

- 저장소 루트에 Cargo workspace 초기화 완료
- `src/` 아래 활성 Rust crate 골격 생성 완료
- `rust-toolchain.toml`로 stable toolchain 고정
- `ratatui` + `crossterm` 기반 TUI 부트스트랩과 `rust-i18n` 연결 완료
- 일반화된 Rust scan result 모델과 최소 JSON export 경로 동작
- override 병합과 정규화를 포함한 Compose parser 포팅 및 parity 테스트 추가
- 기본 Compose 규칙 엔진과 점수화 모델을 Rust로 일부 포팅하고 fixture 테스트로 검증
- `--host-root`를 통한 SSH posture 및 Docker host exposure 기본 점검 시작
- 인자 없는 live scan이 host 스캔 + Docker 기반 Compose 자동 발견 + 현재 디렉터리 fallback으로 동작

## 릴리스 규칙

hostveil은 접미사 없는 SemVer를 사용합니다. 크레이트/바이너리 버전은 `X.Y.Z`, Git 태그는 `vX.Y.Z`입니다.

- `1.0.0`을 선언하기 전까지는 `0.Y.Z` 라인을 유지합니다.
- 하위 호환 버그 수정, 설치/업데이트 흐름 수정, 안정성 개선은 patch를 올립니다.
- 새 기능, 새 명령, 사용자에게 보이는 범위 확장은 minor를 올립니다.
- 버전은 모든 PR마다 올리지 않고, 배포 준비가 끝난 시점의 전용 release 변경에서만 올립니다.
- GitHub Release는 `main`에서 만든 annotated tag `vX.Y.Z`를 푸시할 때만 생성합니다.
- 태그, `src/Cargo.toml`, `Cargo.lock`의 버전은 항상 일치해야 합니다.

## 기여

[CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 라이선스

hostveil은 [GNU 일반 공중 사용 허가서 v3.0](LICENSE)에 따라 배포되는 자유 소프트웨어입니다.
