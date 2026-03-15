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
- **Quick Fix** — 낮은 위험 항목은 한 명령으로 자동 수정; 높은 위험 항목은 수정 초안 제공

## 점검 항목

| 축 | 점검 내용 |
|---|---|
| 민감 정보 노출 | `.env` 파일, 평문/기본 자격증명, 볼륨 내 시크릿 |
| 과도한 권한 | `privileged: true`, root 실행, 광범위한 볼륨 마운트, `network_mode: host` |
| 불필요한 외부 노출 | 공개 포트, 관리자 페이지, 리버스 프록시 우회 서비스 |
| 업데이트/유지보수 위험 | `latest` 태그 남용, 버전 고정 부재, 오래된 이미지 |

## 설치

> 아직 제공되지 않습니다. 현재 초기 개발 단계입니다.
>
> 예정: `curl -fsSL https://get.hostveil.dev | sh` 및 `cargo install hostveil`

## 사용법

> 준비 중입니다.

## 현황

hostveil은 현재 초기 개발 단계입니다. 구현은 두 단계로 계획되어 있습니다.

1. **Python CLI 프로토타입** — 규칙 엔진, 점수화 모델, Quick Fix 로직을 빠르게 검증
2. **Rust TUI** — 검증된 프로토타입을 기반으로 한 경량 프로덕션 수준 터미널 대시보드

## 기여

[CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 라이선스

hostveil은 [GNU 일반 공중 사용 허가서 v3.0](LICENSE)에 따라 배포되는 자유 소프트웨어입니다.
