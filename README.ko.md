English | **[한국어](README.ko.md)**

# hostveil

> Docker Compose 기반 셀프호스팅 환경을 위한 경량 통합 보안 대시보드

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Jellyfin, Nextcloud, Vaultwarden, Gitea, Immich 등을 운영하는 셀프호스터는 보안 상태를 확인하기 위해 Lynis, Trivy, Dockle, Docker Bench 같은 도구를 각각 따로 설치하고 해석해야 합니다. hostveil은 이를 하나의 터미널 대시보드로 통합합니다. 심각도 순으로 정렬된 점수화된 발견 사항과 명확한 해결 방법을 한 번에 제공합니다.

[Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (실행 가능한 가이드를 포함한 점수화 감사)와 [btop](https://github.com/aristocratos/btop) (경량 TUI 디자인)에서 영감을 받았습니다.

## 주요 기능

- **보안 개요 대시보드** — 카테고리별 세부 점수 및 심각도 카운트를 포함한 전체 점수
- **서비스 인식 규칙 점검** — 각 서비스의 데이터 위치와 설정 구조에 맞춘 점검
- **실행 가능한 가이드** — 모든 발견 사항에 포함: 무엇인지, 왜 위험한지, 어떻게 수정하는지
- **quick-fix** — 낮은 위험 항목만 한 명령으로 자동 수정
- **fix** — 안전 수정과 검토가 필요한 가이드 기반 수정까지 한 번에 적용하며, 미리보기·백업·확인을 지원

## 점검 항목

| 축 | 점검 내용 |
|---|---|
| 민감 정보 노출 | `.env` 파일, 평문/기본 자격증명, 볼륨 내 시크릿 |
| 과도한 권한 | `privileged: true`, root 실행, 광범위한 볼륨 마운트, `network_mode: host` |
| 불필요한 외부 노출 | 공개 포트, 관리자 페이지, 리버스 프록시 우회 서비스 |
| 업데이트/유지보수 위험 | `latest` 태그 남용, 버전 고정 부재, 오래된 이미지 |

## 설치

최종 배포용 바이너리는 아직 제공되지 않습니다. 현재 동작하는 구현은 `proto/` 안의 Python 프로토타입입니다.

**Linux / macOS**

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"
```

**Windows (PowerShell)** — 저장소 루트에서:

```powershell
python -m venv proto\.venv
.\proto\.venv\Scripts\Activate.ps1
pip install -e "proto[dev]"
```

스크립트 실행이 막혀 있으면 관리자 PowerShell에서 한 번 `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`를 실행하거나, **명령 프롬프트(cmd)** 를 사용하세요:

```bat
python -m venv proto\.venv
proto\.venv\Scripts\activate.bat
pip install -e "proto[dev]"
```

`python`이 인식되지 않으면 Windows용 Python 런처로 `py -m venv proto\.venv`를 사용할 수 있습니다.

## 사용법

Compose 파일 또는 디렉터리를 대상으로 프로토타입 CLI를 실행할 수 있습니다.

```sh
python -m hostveil scan path/to/docker-compose.yml
python -m hostveil quick-fix path/to/docker-compose.yml --preview-changes --yes
python -m hostveil fix path/to/docker-compose.yml --preview-changes --yes
```

## 현황

hostveil은 현재 초기 개발 단계입니다. 구현은 두 단계로 계획되어 있습니다.

1. **Python CLI 프로토타입** — 규칙 엔진, 점수화 모델, Quick Fix 로직을 빠르게 검증
2. **Rust TUI** — 검증된 프로토타입을 기반으로 한 경량 프로덕션 수준 터미널 대시보드

현재 프로토타입 범위:

- 기본 override 병합을 포함한 Docker Compose 파싱
- 네 가지 감사 축: 민감 정보, 권한, 노출, 업데이트 위험
- 심각도 카운트와 축별 점수를 포함한 점수화 모델
- ANSI 스타일을 쓰는 터미널 스캔 리포트(환경 변수 `NO_COLOR`로 비활성화 가능)
- 백업, 변경 미리보기(`--preview-changes`), 확인 절차를 포함한 `quick-fix` 흐름
- 안전 수정과 검토가 필요한 가이드 수정까지 함께 적용하는 `fix` 흐름

## 기여

[CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 라이선스

hostveil은 [GNU 일반 공중 사용 허가서 v3.0](LICENSE)에 따라 배포되는 자유 소프트웨어입니다.
