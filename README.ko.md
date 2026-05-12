**[English](README.md)** | 한국어

# hostveil

> Docker Compose를 중심으로 한 Linux 셀프호스팅 환경용 경량 통합 보안 대시보드

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Jellyfin, Nextcloud, Vaultwarden, Gitea, Immich 등을 운영하는 셀프호스터는 보안 상태를 확인하기 위해 Lynis, Trivy, Dockle, Gitleaks, Fail2ban 같은 도구를 각각 따로 설치하고 해석해야 합니다. hostveil은 이런 신호를 하나의 터미널 중심 워크플로로 통합하는 것을 목표로 합니다. 심각도 순으로 정렬된 점수화된 발견 사항, 셀프호스팅 맥락에 맞춘 설명, 그리고 구체적인 해결 가이드를 한 번에 제공합니다.

## 주요 기능

- **보안 개요 대시보드** — 전체 보안 상태, 축별 점수, 그룹화된 조치 대기열, 어댑터 활동을 한 화면에 표시
- **셀프호스팅 맥락 기반 기본 점검** — 각 서비스의 데이터 위치, Compose 구조, 운영 위험을 반영한 점검
- **선택적 외부 스캐너 어댑터** — Trivy, Dockle, Lynis, Gitleaks 같은 기존 도구 결과를 런타임 필수 의존성으로 강제하지 않고 통합
- **보이는 백그라운드 진행 상태** — 실행 시 자동 업데이트 점검과 TUI 내부 어댑터 로딩 상태를 숨기지 않고 표시
- **설정 모달** — TUI에서 키보드나 마우스로 테마, 레이아웃, 언어 설정을 변경 가능
- **테마 프리셋** — 터미널 기본 ANSI와 Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, Solarized Light 프리셋을 TUI에서 전환 가능
- **실행 가능한 가이드** — 모든 발견 사항에 포함: 무엇인지, 왜 위험한지, 어떻게 수정하는지
- **가이드형 수정 흐름** — 미리보기와 백업이 가능한 Compose 변경과, 지원되는 어댑터가 제안한 검토형 호스트 수정 작업을 함께 다룹니다

## 설치

hostveil은 GitHub Releases를 통해 Linux tarball과 패키지 자산으로 배포됩니다.

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

설치 스크립트가 올바른 아키텍처(`x86_64` 또는 `aarch64`)를 선택하고 `~/.local/bin` 또는 `/usr/local/bin`에 설치합니다. 설치 후에는 `hostveil` 명령을 직접 사용합니다.

터미널이 가능하면 설치 직후 `hostveil setup`으로 넘어가 Lynis, Trivy, Dockle, Gitleaks, Fail2Ban 같은 추천 도구를 바로 설치하고 기본 설정까지 진행할 수 있습니다.

Debian 계열 사용자와 Fedora 또는 Rocky/RHEL 9 계열 사용자는 패키지 자산으로도 설치할 수 있습니다:

```sh
sudo apt install ./hostveil_<version>_amd64.deb
sudo dnf install ./hostveil-<version>-1.x86_64.rpm
```

RPM 패키지는 Rocky Linux 9 호환 기준선에서 빌드됩니다. 패키지 설치는 hostveil의 실행 시 자동 업데이트 흐름 대신 시스템 패키지 관리자를 사용해 업그레이드와 제거를 처리합니다.

나중에 다시 setup을 실행하려면:

```sh
hostveil setup
```

기존 설치를 최신 버전으로 업그레이드:

```sh
hostveil upgrade
```

패키지 설치에서는 `hostveil upgrade` 대신 새 릴리스 패키지를 내려받아 `apt` 또는 `dnf`로 다시 설치하세요.

자동 업데이트를 끄거나 다시 켜기:

```sh
hostveil auto-upgrade disable
hostveil auto-upgrade enable
```

패키지 설치는 실행 시 자동 업데이트를 지원하지 않습니다.

완전히 제거:

```sh
hostveil uninstall
```

패키지 설치는 `sudo apt remove hostveil` 또는 `sudo dnf remove hostveil`처럼 시스템 패키지 관리자로 제거하세요.

> **참고:** 라이프사이클 명령(`upgrade`, `uninstall`, `auto-upgrade`)은 설치 방식에 따라 동작이 다릅니다. `install.sh` 설치는 번들 래퍼를 사용하고, 패키지 설치는 패키지 관리자 안내를 반환합니다.

## 빠른 시작

대화형 TUI로 실행:

```sh
hostveil
```

터미널 없는 JSON 스캔 실행:

```sh
hostveil --json
hostveil --compose path/to/docker-compose.yml --json
hostveil --host-root / --json
hostveil --json --adapters none
hostveil --json --findings-only
```

공유용 또는 자동화용 터미널 없는 리포트 생성:

```sh
hostveil --markdown
hostveil --html
hostveil --sarif
```

Markdown과 HTML은 사람이 읽는 공유용에, JSON과 SARIF는 자동화와 후속 도구 연동에 적합합니다.

`--json`과 함께 `--findings-only`를 사용하면 가벼운 후속 처리를 위해 findings 배열만 출력합니다.

선택형 스캐너 어댑터의 기본값은 `all`입니다. 기본 점검만 빠르게 실행하려면 `--adapters none`을 쓰고, 일부만 실행하려면 `--adapters trivy,dockle,gitleaks`처럼 지정합니다.

터미널 호환성을 위해 기본 로케일은 항상 영어입니다. 한국어로 명시적으로 바꾸려면 `hostveil --locale ko ...` 또는 `HOSTVEIL_LOCALE=ko hostveil ...`를 사용하세요. TUI에서는 설정(`s`)을 열어 언어를 전환하고 저장할 수 있습니다.

## 사용법

### TUI 조작

- `1` / `2` / `3` — 개요, Findings, History 화면 전환
- `Enter` — 개요에서 Findings 화면 열기
- `s` — 설정 열기(테마/레이아웃/언어)
- `t` — 스캔 이력 추세 화면 열기
- `/` — Findings 검색 열기
- `?` — 도움말 오버레이 표시
- `Tab` — 개요 패널 간 포커스 이동
- `L` — 레이아웃 프리셋 전환
- 마우스 — 탭, findings 행, 설정 행 클릭 가능
- `q` 또는 `Esc` — 종료 또는 뒤로가기

### 개요 화면

- **Security Scores** — 전체 점수와 축별 점수(민감 정보, 권한, 노출, 업데이트, 호스트 하드닝)
- **Scan Results** — 서비스별 findings 요약, 심각도 개수, 어댑터 상태
- **Action Queue** — 서비스 또는 호스트 단위로 묶은 다음 조치 요약, 자동 수정 가능 항목과 수동 수정 항목 구분
- **History** — 최근 스캔의 점수와 발견 항목 개수 추세(개요에서 `t` 키)
- 어댑터가 아직 실행 중이면 점수 패널에서 진행 상태와 네이티브 기준 점수를 분리해 보여줍니다

### Findings 화면

- 소스, 수정 유형, 서비스별 필터로 findings를 심각도 순으로 탐색
- 각 항목에는 근거, 위험 설명, 구체적인 수정 가이드가 포함됩니다
- 수정 가능한 항목에서 `f`를 눌러 수정 흐름을 엽니다

### 수정 흐름

파일을 쓰기 전에 Compose 수정 계획을 미리 볼 수 있습니다:

```sh
hostveil --auto-fix path/to/docker-compose.yml --preview-changes
hostveil --fix path/to/docker-compose.yml --preview-changes
```

- `--auto-fix`는 추가 입력 없이 hostveil이 끝까지 처리할 수 있는 변경을 적용합니다
- `--fix`는 자동 변경과 함께, 선택이나 입력이 필요한 검토형 변경까지 처리합니다
- `Auto`는 diff를 검토한 뒤 `f`로 바로 끝까지 진행할 수 있는 수정입니다
- `Review`는 `f`로 진행할 수는 있지만 최종 patch를 만들기 전에 사용자의 선택이나 입력이 필요한 수정입니다
- `Manual`은 물리 조치나 외부 인프라 변경처럼 hostveil이 현실적으로 대신 처리할 수 없는 경우만 남깁니다
- 둘 다 쓰기 전에 백업을 생성합니다

## 선택형 도구

hostveil은 선택형 의존성 없이도 실행되지만, 관련 도구가 설치되어 있으면 커버리지가 향상됩니다:

| 도구 | 역할 | 설치 방법 |
|------|------|-----------|
| Lynis | 호스트 보안 감사 | `hostveil setup` 또는 시스템 패키지 관리자 |
| Trivy | 이미지 취약점 스캔 | `hostveil setup` 또는 시스템 패키지 관리자 |
| Dockle | 이미지 베스트 프랙티스 스캔 | 지원되는 Linux 대상에서는 `hostveil setup`, 그 외에는 수동 설치 |
| Gitleaks | 프로젝트 비밀 정보 유출 점검 | 지원되는 Linux `x86_64` / `aarch64` 대상에서는 `hostveil setup`, 그 외에는 수동 설치 |
| Fail2Ban | 침입 방지 | `hostveil setup` 또는 시스템 패키지 관리자 |

`--adapters none`으로 모든 외부 스캐너를 건너뛰거나, `--adapters trivy,dockle,gitleaks`처럼 일부만 실행할 수 있습니다.

## 목표 점검 축

| 축 | 점검 내용 |
|----|-----------|
| 민감 정보 노출 | `.env` 파일, 평문/기본 자격증명, 볼륨 내 시크릿 |
| 과도한 권한 | `privileged: true`, root 실행, 광범위한 볼륨 마운트, `network_mode: host` |
| 불필요한 외부 노출 | 공개 포트, 관리자 페이지, 리버스 프록시 우회 서비스 |
| 업데이트/공급망 위험 | `latest` 태그 남용, 버전 고정 부재, 오래된 이미지 |
| 호스트 하드닝 | SSH 설정, Docker 호스트 노출, 방화벽, 방어 수단 |

## 기여하기

개발 환경 설정, Lab 워크플로, Git 워크플로, 테스트, 릴리스 정보는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참조하세요.

## 라이선스

hostveil은 [GNU General Public License v3.0](LICENSE)에 따라 자유 소프트웨어로 배포됩니다.
