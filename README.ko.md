[English](README.md) | **[한국어]**

# hostveil

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Status: Active](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/seolcu/hostveil)

> **hostveil** — Linux 셀프호스팅 환경을 위한 보안 대시보드입니다. 별도 설정이 필요 없으며, 터미널 네이티브로 동작하고, 외부 스캐너를 자동으로 탐지합니다.

Chrome Lighthouse와 `btop`에서 영감을 받은 hostveil은 Docker Compose 스택과 호스트 환경의 보안 설정 오류를 스캔하여 하나의 대화형 TUI로 보여줍니다. `hostveil`만 실행하면 됩니다.

---

## 철학

**`hostveil` — 플래그가 필요하지 않습니다.** 모든 것을 자동으로 탐지합니다:

- 현재 디렉터리에서 상위로 이동하며 Compose 파일을 찾습니다.
- `PATH`에서 Trivy, Dockle, Lynis, Gitleaks를 감지하여 자동 실행합니다.
- 발견 항목을 5개 감사 축에 따라 점수화하여 Bubbletea TUI로 제공합니다.

`--compose`, `--output`, `--fix`, `--adapters` 플래그가 없습니다. `--serve`, `--port`, `--host`, `--user-mode`, `--version`만 있습니다. 최대 범위의 검사를 위해 root로 실행하고, `--user-mode`로 제한할 수 있습니다.

---

## 빠른 시작

```sh
# 대화형 TUI 실행 (모든 것을 자동 탐지)
hostveil

# 웹 UI (ttyd, http://127.0.0.1:8080)
hostveil --serve

# 제한된 권한
hostveil --user-mode
```

`hostveil`만 실행하면 Compose 파일을 찾고, 규칙을 실행하며, 어댑터 도구를 감지하고, 개요/발견 항목/이력 화면을 갖춘 TUI를 엽니다.

---

## 기능

### Compose 스캐너 — 7개 규칙 범주

| 규칙 | 점검 내용 |
|------|----------|
| **노출 (Exposure)** | 공개 포트 바인딩(`0.0.0.0`), 리버스 프록시가 필요한 서비스 |
| **권한 (Permissions)** | `privileged: true`, root 사용자, `SYS_ADMIN`, 민감한 호스트 마운트 |
| **런타임 (Runtime)** | `no-new-privileges` 비활성화, 쓰기 가능한 루트 파일시스템 |
| **민감 정보 (Sensitive Data)** | 환경 변수의 인라인 시크릿, 기본/취약 자격증명 |
| **업데이트 (Updates)** | 버전 고정 누락, `:latest` 태그 |
| **네트워크 (Network)** | 기본 브리지 네트워크, `network_mode: host` |
| **서비스 인식 (Service-Aware)** | 23개 서비스 — Vaultwarden, Jellyfin, Gitea, Nextcloud, Immich, Traefik, Portainer, Home Assistant, Pi-hole, Grafana, NPM, Caddy, Authentik, Paperless, Postgres, MySQL, Redis, GitLab, Uptime Kuma, Duplicati, Restic, Borg, Kopia |

### 호스트 감사 — 9개 점검 모듈

| 모듈 | 점검 내용 |
|------|----------|
| **SSH** | PermitRootLogin, 암호 인증, 프로토콜 버전 |
| **Docker** | 데몬 소켓 노출, 사용자 네임스페이스 리매핑 |
| **방화벽** | 활성 방화벽(iptables/nftables/ufw), 기본 정책 |
| **커널** | sysctl 하드닝, ASLR, YAMA ptrace |
| **파일시스템** | 전역 쓰기 가능 디렉터리, noexec 마운트 |
| **FIM** | 파일 무결성 모니터링(AIDE, Tripwire) |
| **MAC** | 강제 접근 통제(AppArmor, SELinux) |
| **방어** | Fail2ban, auditd, rkhunter |
| **업데이트** | unattended-upgrades, 재부팅 필요 상태 |

### 외부 어댑터 — 설치 = 자동 실행

| 어댑터 | 목적 |
|--------|------|
| **Trivy** | 컨테이너 이미지 취약점 스캔 |
| **Dockle** | Docker 이미지 모범 사례 린터 |
| **Lynis** | 호스트 수준 보안 감사 |
| **Gitleaks** | Git 시크릿/자격증명 유출 탐지 |

설정이 필요하지 않습니다. 시작 시 사용 가능한 도구를 감지하여 결과를 발견 항목 목록에 통합합니다.

### 수정 엔진 (Fix Engine)

Compose 파일 및 호스트 설정에 대한 단계별 수정 가이드를 제공합니다:

- 변경 사항을 **미리 보기**하고 적용합니다(수정 가능한 항목에서 `f` 키).
- **Auto** — 확인 즉시 적용 (태그 고정, 역량 제거).
- **Review** — 사용자 입력 후 적용 (포트를 `127.0.0.1`에 바인딩).
- **Manual** — 자동화 불가 시 수행 방법 안내.
- **백업** — 편집 전 원본 파일을 자동 백업.
- **호스트 + 어댑터 수정** — SSH, 방화벽, Trivy 업데이트, Gitleaks 정리 명령 제공.

### 내보내기 (Export)

이력 화면에서 사용 가능:

| 형식 | 사용 사례 |
|------|----------|
| **JSON** | 기계 판독, 파이프라인 통합 |
| **SARIF** | 정적 분석 교환 형식(SIEM, CodeQL) |
| **Markdown** | 사람이 읽을 수 있는 리포트, PR 코멘트 |
| **HTML** | 이해관계자용 풍부한 형식 리포트 |

### 웹 UI (ttyd)

```sh
hostveil --serve --port 8080 --host 127.0.0.1
```

ttyd WebSocket을 통해 실제 Bubbletea TUI를 브라우저로 스트리밍합니다. 포트 충돌 시 자동으로 점유 중인 프로세스를 종료합니다.

### TUI 테마

9개 테마: Default ANSI, Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, Solarized Light.

---

## 설치

### GitHub Releases (권장)

```sh
curl -fsSL https://github.com/seolcu/hostveil/releases/latest/download/hostveil_linux_amd64 -o /usr/local/bin/hostveil
chmod +x /usr/local/bin/hostveil
```

아키텍처: `amd64`, `arm64`. Linux 및 macOS 지원.

### Go Install

```sh
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Go 1.24+ 필요.

### Docker

```sh
docker pull ghcr.io/seolcu/hostveil:latest
```

---

## 소스에서 빌드

Go 1.24+, CGO 불필요.

```sh
git clone https://github.com/seolcu/hostveil.git
cd hostveil
go build -o hostveil ./cmd/hostveil/

# 크로스 컴파일 (네이티브, 추가 도구체인 불필요)
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
GOOS=darwin GOARCH=amd64 go build -o hostveil-darwin-amd64 ./cmd/hostveil/
```

Makefile 사용: `make build`, `make cross`, `make test`.

---

## 사용법

### TUI 화면

| 키 | 화면 | 내용 |
|-----|------|------|
| `1` | **개요 (Overview)** | 점수 카드, 축별 분석, 조치 대기열, 어댑터 상태, 호스트 정보 |
| `2` | **발견 항목 (Findings)** | 심각도순 목록, 상세 패널, 수정 가이드, 필터, 검색 |
| `3` | **이력 (History)** | 점수 추세, 심각도 요약, 내보내기 버튼 |

### 키보드 단축키

| 키 | 동작 |
|-----|------|
| `f` | 선택한 발견 항목 수정 미리보기 |
| `/` | 발견 항목 검색 |
| `s` | 설정 (테마, 레이아웃, 테두리) |
| `?` | 도움말 오버레이 |
| `Tab` | 패널 포커스 이동 |
| `q` / `Esc` | 종료 또는 뒤로가기 |
| `L` | 레이아웃 프리셋 전환 |

### 발견 항목 화면

- 심각도 순 정렬 (Critical → High → Medium → Low).
- 소스(compose/host/adapter), 수정 유형(auto/review/manual), 서비스별 필터.
- 세 가지 정렬 모드: 심각도, 서비스, 축.
- 수정 가능한 항목에서 `f`를 눌러 수정 미리보기 워크플로 시작.

### 수정 엔진 워크플로

1. 수정 가능한 발견 항목(`Auto` 또는 `Review` 유형)을 선택합니다.
2. `f`를 누르면 미리보기 패널에 diff와 작업 요약이 표시됩니다.
3. 확인하면 엔진이 원본 파일을 백업하고 수정을 적용합니다.

### 내보내기

이력 화면에서 JSON, SARIF, Markdown, HTML로 내보낼 수 있습니다.

---

## 목표 감사 축

모든 발견 항목은 5개 감사 축 중 하나에 매핑됩니다. TUI는 전체 점수와 함께 각 축의 점수를 표시합니다.

| 축 (Axis) | 점검 내용 | 예시 |
|-----------|----------|------|
| **민감 정보 노출** (Sensitive Data) | 시크릿, 자격증명, 기밀 정보 노출 | `.env` 파일, 평문 비밀번호, 인라인 토큰, 볼륨 내 시크릿 |
| **과도한 권한** (Excessive Permissions) | 과도한 권한의 컨테이너, 광범위한 접근 | `privileged: true`, root 사용자, `SYS_ADMIN`, `/etc/shadow` 또는 `/var/run/docker.sock` 마운트 |
| **불필요한 노출** (Unnecessary Exposure) | 네트워크 노출로 인한 공격 표면 | 공개 포트 바인딩(`0.0.0.0`), 리버스 프록시 부재, `network_mode: host` |
| **업데이트 및 공급망 위험** (Update & Supply Chain) | 이미지 및 의존성 리스크 | `:latest` 태그, 버전 미고정, 오래된 이미지, CVE 스캔 부재 |
| **호스트 하드닝** (Host Hardening) | Linux 호스트 보안 상태 | SSH 설정, 방화벽, Docker 데몬, 커널 파라미터, AppArmor/SELinux, Fail2ban |

---

## Docker Lab

개발 및 테스트를 위한 완전한 랩 환경입니다. 모든 도구가 사전 설치된 스캐너 컨테이너와 의도적으로 취약하게 구성된 5개의 Compose 스택을 실행합니다.

### 사전 요구사항

Docker (Compose V2), Git.

### 시작하기

```sh
cd hostveil
./scripts/lab.sh up
```

랩 컨테이너(Go 1.24, ttyd, Trivy, Dockle, Lynis, Gitleaks)를 빌드하고 Vaultwarden, Jellyfin, Gitea, Nextcloud, nginx를 시작합니다. 각 서비스는 의도적인 보안 취약점을 갖추고 있습니다.

### Lab 명령어

```sh
./scripts/lab.sh up              # 랩 시작 (스캐너 + 모든 대상)
./scripts/lab.sh down            # 모든 랩 서비스 중지
./scripts/lab.sh shell           # 랩 컨테이너 접속 (bash)
./scripts/lab.sh run             # 랩 내부에서 hostveil 실행 (자동 탐지)
./scripts/lab.sh serve           # http://localhost:9090/ 에서 --serve 실행
./scripts/lab.sh serve-detached  # 분리 모드로 --serve 실행
```

대상 서비스는 개별적으로도 시작할 수 있습니다:

```sh
docker compose -f docker/lab/vaultwarden/compose.yml up -d
```

### Lab 아키텍처

```
┌──────────────────────┐
│   Lab 컨테이너         │
│  (Go 1.24 + 도구)      │
│  hostveil --serve     │
│  http://localhost:9090 │
└──────────┬───────────┘
           │
┌──────────┴───────────┐
│ hostveil-lab 브리지   │
├──────────────────────┤
│ vaultwarden:8081     │
│ jellyfin:8096        │
│ gitea:3000/2222      │
│ nextcloud:8082       │
│ nginx:8083           │
└──────────────────────┘
```

모든 대상은 hostveil이 탐지할 의도적인 문제(기본 자격증명, 공개 포트, 특권 모드, 민감한 마운트, `:latest` 태그)를 포함합니다.

---

## 테스트 실행

```sh
# 레이스 탐지와 함께 모든 테스트 실행
go test -race -count=1 ./...

# 특정 패키지
go test -race -count=1 ./internal/scanner/...
go test -race -count=1 ./internal/adapter/...
go test -race -count=1 ./internal/fix/...
go test -race -count=1 ./internal/export/...
```

규칙 엔진, 호스트 점검, 어댑터, 수정 엔진, 내보내기, TUI를 포함한 73개 이상의 테스트를 제공합니다.

---

## 기술 스택

- **언어**: Go 1.24+, CGO 불필요
- **TUI**: Bubbletea, Bubbles, Lipgloss, Glamour, Huh
- **YAML**: goccy/go-yaml
- **웹**: [ttyd](https://github.com/tsl0922/ttyd) — TUI를 WebSocket으로 브라우저 스트리밍
- **빌드**: `go build`, `GOOS`/`GOARCH` 크로스 컴파일
- **라이선스**: GPL-3.0

---

## 기여

기여 가이드는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참조해주세요.

## 라이선스

hostveil은 [GNU General Public License v3.0](LICENSE)에 따라 배포되는 자유 소프트웨어입니다.

저작권 &copy; 2025-2026 설규원. 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.
