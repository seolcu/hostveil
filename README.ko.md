# hostveil

[English](README.md) · **한국어**

> 2026-1 Ajou SoftCon 개발부문 최우수상 수상

**hostveil은 셀프호스팅 중인 리눅스 서버의 보안 실수를 찾아, 쉬운 말로 설명하고, 안전하게 고쳐 줍니다.**
바이너리 하나, 설정 파일 없음, 클라우드 계정 없음.

[![CI](https://github.com/seolcu/hostveil/actions/workflows/ci.yml/badge.svg)](https://github.com/seolcu/hostveil/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/seolcu/hostveil)](https://github.com/seolcu/hostveil/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/seolcu/hostveil)](go.mod)
[![License: GPL-3.0](https://img.shields.io/github/license/seolcu/hostveil)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/seolcu/hostveil)](https://goreportcard.com/report/github.com/seolcu/hostveil)

[웹사이트](https://hostveil.seolcu.com/ko/) · [문서](https://hostveil.seolcu.com/ko/docs/) · [최신 릴리스](https://github.com/seolcu/hostveil/releases/latest)

<p align="center">
  <img src="site/assets/web.png" width="900"
       alt="hostveil 웹 대시보드: 0–100 보안 점수, 영역별 계기판, 심각도로 묶인 발견 항목과 클릭 한 번의 안전한 수정">
</p>

---

셀프호스팅이 빠르게 늘고 있지만, Jellyfin이나 Nextcloud, 게임 서버, 로컬
LLM을 돌리는 사람 대부분은 보안 전문가가 아닙니다 — 그리고 잘못된 설정
하나가 심각한 침해로 이어질 수 있습니다. hostveil은 바로 그런 사람들을 위한
**가이드형 보안 강화 도구**입니다. 리눅스 서버를 가리키기만 하면, 영향이 가장
큰 영역들을 점검해 하나의 0–100 점수로 합치고, 각 발견 항목을 전문 용어 없이
설명하며, 고치는 과정을 안내합니다 — 바뀔 내용을 정확히 보여 주고, 원본을 먼저
백업하고, 어떤 수정이든 명령 하나로 되돌릴 수 있게 하면서.

## 점검 범위

모든 발견 항목은 그것을 찾아낸 영역의 이름을 답니다. 두 번째 열의 접두사가
`hostveil fix`와 `hostveil explain`에 입력하는 값입니다.

| 영역 | 발견 항목 | 무엇을 보는가 | 필요한 것 |
| --- | --- | --- | --- |
| **Docker / Compose** | `compose.*` | 특권 모드, Docker 소켓 마운트, 노출된 데이터 저장소와 관리자 패널, 호스트 네트워킹, 안전하지 않은 바인드 마운트, 공유된 PID·IPC 네임스페이스, 쓰기 가능한 루트 파일시스템, 누락된 no-new-privileges, 하드코딩된 비밀값 등 — Compose 파일에 대한 네이티브 감사에 더해, 그냥 `docker run`으로 띄운 컨테이너까지 | Docker |
| **SSH** | `ssh.*` | root 로그인, 비밀번호 인증, 빈 비밀번호, 느슨한 무차별 대입 제한, 로그인 유예 시간, 게이트웨이 포트, 호스트 기반·키보드 대화형 인증, X11 포워딩 — `sshd_config`에서 직접 파싱하며 `Include`를 따라 `sshd_config.d/`까지 읽습니다 | — |
| **방화벽** | `firewall.*` | ufw, firewalld, nftables, iptables 중 무엇이 실제로 동작 중인지 — 그리고 컨테이너가 게시한 포트가 그것을 조용히 우회하고 있지는 않은지 | — |
| **자동 업데이트** | `updates.*` | unattended-upgrades(apt) 또는 dnf-automatic(dnf)이 켜져 있는지 | — |
| **노출된 서비스** | `ports.*` | 루프백이 아닌 주소에서 대기 중인 호스트 프로세스 — Compose 감사로는 볼 수 없는, 네이티브로 설치된 데이터베이스·관리자 패널·앱을 `ss`에서 읽습니다 | `ss` |
| **계정** | `accounts.*` | root의 UID(0)를 가진 root 아닌 계정과 비밀번호가 빈 로그인 계정을 `/etc/passwd`·`/etc/shadow`에서 파싱 | root (`/etc/shadow` 때문에) |
| **파일 권한** | `fileperms.*` | `/etc/shadow`, `/etc/passwd`, `/etc/group`, `sshd_config`, SSH 호스트 개인 키의 과도한 권한 | — |
| **AI 에이전트 런타임** | `agent.*` | 셀프호스팅 에이전트 런타임 — OpenClaw와 Hermes Agent: 호스트 밖에서 닿는 게이트웨이, 그런 게이트웨이에서 꺼진 인증, 제한 없는 셸과 상승된 도구, 비활성화된 샌드박스, 설정 파일과 그 옆 API 키의 느슨한 권한 | — |
| **커널 강화** | `sysctl.*` | `/proc/sys`에서 직접 읽는 여덟 개의 커널 파라미터 — 로컬 발판이 root가 되는 것을, 위조된 패킷이 경로가 되는 것을 막는 조용한 손잡이들. `sysctl` 바이너리는 필요 없습니다 | — |
| **Docker 데몬** | `dockerd.*` | 컨테이너 아래의 데몬: TLS 클라이언트 검증 없이 TCP로 제공되는 API(포트에 닿을 수 있는 누구에게나 인증 없는 root), 누구나 쓸 수 있는 소켓, 그 소켓의 그룹을 쥔 사람, 그리고 기본값들 — no-new-privileges, userns-remap, live-restore | Docker |
| **서비스 강화** | `systemd.*` | 직접 설치한 유닛을 systemd 자신의 *실효* 설정으로 읽습니다: 서비스가 setuid로 권한을 얻을 수 있는지, `/usr`와 `/etc`에 쓸 수 있는지, 모든 사용자의 홈 디렉터리를 읽을 수 있는지, `/tmp`를 호스트와 공유하는지. 배포판이 넣은 유닛은 배포판에 맡깁니다 | systemd |
| **이미지 CVE** *(선택)* | `cve.*` | Compose 서비스가 실행하는 이미지의 알려진 취약점 | Trivy |

Docker나 Trivy가 없나요? 해당 영역은 깔끔하게 건너뛰고, 점수는 다시
정규화됩니다 — 오해를 부르는 만점을 받게 되는 일은 없습니다.

## 설치

```bash
curl -fsSL https://hostveil.seolcu.com/install.sh | bash
```

또는 [최신 릴리스](https://github.com/seolcu/hostveil/releases/latest)에서
네이티브 패키지를 설치하세요 — 특히 보안 도구라면, 스크립트를 셸로 파이프하고
싶지 않은 것이 합리적입니다:

```bash
sudo apt install ./hostveil_<version>_linux_amd64.deb   # 또는 dnf install ./hostveil-<version>.x86_64.rpm
```

패키지는 같은 바이너리를 같은 경로(`/usr/bin/hostveil`)에 설치하므로, 설치
스크립트와 서로 바꿔 쓸 수 있습니다. Docker와 `iproute2`는 *권장*일 뿐 필수가
아닙니다: 없으면 hostveil이 실패하는 대신 해당 영역이 N/A로 보고됩니다.

Go 1.26 이상이 있고 직접 빌드하고 싶다면:

```bash
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Trivy는 선택입니다 — 언제든 설치하면 이미지 CVE 스캔이 켜집니다.

**업그레이드**는 같은 명령을 다시 실행하면 됩니다: 바이너리만 교체되고 저장된
스캔과 롤백 체크포인트는 그대로 남습니다. **제거**는:

```bash
curl -fsSL https://hostveil.seolcu.com/install.sh | bash -s -- --uninstall
```

이 명령은 바이너리를 지우고 상태 디렉터리의 위치를 알려 줄 뿐, 지우지는
않습니다 — 그 체크포인트들은 hostveil이 호스트에서 편집한 모든 파일의
백업이고, 제거한다는 것이 되돌릴 능력을 포기하겠다는 결정은 아니니까요.

릴리스 아카이브는 GitHub Actions가 빌드하며 서명된 빌드 프로버넌스 증명을
함께 담습니다. 실행 전에 이 저장소의 릴리스 워크플로에서 나온 것이 맞는지
확인할 수 있습니다:

```bash
gh attestation verify hostveil-linux-amd64.tar.gz --repo seolcu/hostveil
```

각 아카이브에는 바이너리에 무엇이 들어갔는지 나열한 SBOM(`.sbom.json`)도
포함됩니다.

## 사용법

```bash
hostveil                 # 대화형 TUI (터미널에서의 기본값)
hostveil scan            # 점수가 매겨진 보고서 출력 (-v 상세, --json JSON)
hostveil fix <id>        # 발견 항목 하나를 미리 보고 수정 적용
hostveil fix --all       # 안전한(자동 수정) 항목을 한 번에 모두 적용
hostveil fix --all --review  # 검토(Review) 항목까지, 무엇인지 읽고 나서
hostveil rollback <id>   # 이미 적용한 수정을 되돌리기
hostveil history         # 적용된 수정과 롤백 ID 목록
hostveil explain <id>    # 발견 항목 설명 (--ai로 로컬 LLM의 2차 소견 추가)
hostveil serve           # 127.0.0.1:8787 웹 대시보드 (출력된 URL을 여세요)
```

일부 점검(SSH, 방화벽)은 root 소유 파일을 읽고, 수정 적용에도 root가
필요합니다. 그래서 `hostveil`은 **필요할 때 `sudo`로 스스로 권한을
올립니다** — `sudo hostveil`과 똑같은 비밀번호 프롬프트가 뜨고, 인증하면 같은
터미널에서 이어집니다. `version`과 `help`는 절대 묻지 않습니다.

권한 없이 실행하려면(스크립트·CI) `HOSTVEIL_NO_SUDO=1`을 설정하세요. root
소유 영역은 분명한 메시지와 함께 건너뜁니다.

### CI나 cron 게이트로 쓰기

`hostveil scan`은 찾은 내용을 종료 상태로 알려 주므로, 예약 점검에 출력
파싱이 필요 없습니다:

| 코드 | 의미 |
| --- | --- |
| `0` | 스캔이 실행됐고 high 항목이 없음. |
| `1` | 고치지 않은 high 발견 항목이 하나 이상 있음. |
| `3` | 탐지 영역 하나가 아예 실패해, 스캔이 호스트를 덜 훑었음. |

```bash
HOSTVEIL_NO_SUDO=1 hostveil scan --json > report.json || echo "조치 필요"
```

`--sarif`는 대신 SARIF 2.1.0을 내보냅니다 — GitHub 코드 스캐닝과 대부분의 CI가
받아들이는 형식으로, 발견 항목 ID당 규칙 하나와 항목별 안정적인 지문을 담아
소비자가 스캔 사이를 추적할 수 있게 합니다. 점수와 영역별 커버리지는 실행의
properties에 실립니다. 볼 수 없었던 스캔에서 나온 결과 0건짜리 SARIF 파일은
그러지 않으면 깨끗한 호스트로 읽히기 때문입니다. `--output FILE`은 고른
형식을 파일로 쓰며, 종료 상태는 형식이나 목적지에 따라 달라지지 않습니다 —
계약은 종료 코드입니다.

`--only`와 `--skip`은 실행 범위를 일부 영역으로 좁힙니다(`--only ssh,firewall`).
실행되지 않은 영역은 100이 아니라 N/A로 보고되고, 부분 스캔은 다음 변화량의
기준선으로 저장되지 않습니다.

코드 **3**은 보기보다 중요합니다. 실패한 영역은 발견 항목을 하나도 내지
않으므로, 이 코드가 없다면 닿지 않는 Docker 소켓이 가장 무거운 두 축을
침묵시키고 파이프라인은 깨끗한 실행을 봅니다 — 출력을 읽지 않는 유일한
소비자에게 눈감은 스캔과 건강한 호스트는 구별되지 않습니다. 의존성이 없어
건너뛴 영역이나 부분 커버리지로 저하된 영역은 상태를 바꾸지 않고, 대신 출력에
보고됩니다.

다른 명령은 성공 시 0, 실패 시 1, 사용법 오류 시 2로 종료합니다.

### 뭔가 이상해 보일 때

`HOSTVEIL_DEBUG=1`을 설정하면 hostveil이 호스트에 대해 실행하는 모든 명령을
추적해 표준 오류로 보냅니다 — 무엇이 실행됐고, 얼마나 걸렸고, 실패했는지:

```bash
HOSTVEIL_DEBUG=1 hostveil scan
```

영역이 건너뛰어지거나 점검이 엉뚱한 것을 보고한다는 버그 리포트에 첨부하기
좋은 것이 바로 이것입니다. 명령의 *출력*은 의도적으로 절대 기록하지
않습니다: `docker inspect`는 모든 컨테이너의 확정된 환경 변수를 보고하므로,
그것까지 담은 추적은 일상적으로 자격 증명 유출이 됩니다.

저하(Degraded), 거절된 롤백, 빈 히스토리, 종료 코드 3이 무슨 뜻인지는
[문제 해결](https://hostveil.seolcu.com/ko/docs/troubleshooting)을 보세요.

## 수정은 어떻게 이뤄지나

모든 발견 항목은 도구가 함부로 건드리지 않도록 분류됩니다:

- **자동 수정** — 명백히 옳은 변경 하나. 그래도 먼저 보여 줍니다.
- **검토** — 유효한 대안이 여럿; 하나를 고르세요.
- **수동** — 안전한 자동화가 없음; 대신 무엇을 해야 하는지 설명합니다.

수정 적용은 언제나 **정확한 diff나 명령을 보여 주고**, **원본 파일을
체크포인트로 백업한 뒤** 적용합니다. `hostveil rollback`이 그 백업을
복원하며 — 모든 UI(CLI, TUI, 웹)가 같은 엔진을 지나므로 — 어디서 적용한
수정이든 되돌릴 수 있습니다.

### 정말 효과가 있나요?

hostveil의 수정 뒤에 hostveil 자신의 점수가 오르는 것은 아무것도 증명하지
않습니다 — 무엇이 발견 항목이고 그 뒤 숫자가 얼마여야 하는지를 같은 코드가
정하니까요. 그래서 이 저장소에는 hostveil을 한 번도 들어본 적 없는 도구들로
시드 호스트를 측정하는 하네스가 들어 있습니다: Lynis, Docker의 CIS 벤치마크,
호스트 밖에서의 TCP 스캔, 그리고 커널 자신의 수신 소켓 목록.

시드 호스트에서 `fix --all`은 27개의 수정을 적용했고, 게시된 포트 네 개가
`0.0.0.0`을 떠나 루프백으로 갔으며, CIS Docker 점검 세 개가 통과로 바뀌었고,
모든 수정을 되돌리자 변경된 다섯 파일이 바이트 단위로 복원됐습니다. Lynis는
거의 움직이지 않았고, 서비스를 재시작하기 전까지는 hostveil 밖의 무엇도
움직이지 않았습니다 — 모든 자동 수정은 파일 편집이므로, 그 파일을 읽는
쪽이 다시 읽기 전까지는 어떤 것도 실제로 적용되지 않습니다.

숫자와 방법, 움직이지 않은 계기들, 그리고 엉뚱한 이유로 통과된 하나는
[측정 결과](https://hostveil.seolcu.com/ko/docs/measurements) 페이지에
있습니다. 직접 돌려보려면 `scripts/measure/run.sh -c`를 — 본인 컴퓨터가 아니라
컨테이너나 버려도 되는 VM에서.

## 인터페이스

<p align="center">
  <img src="site/assets/tui.png" width="820"
       alt="hostveil 터미널 UI: 같은 점수와 영역별 계기판 아래, 키보드로 다루는 발견 항목 목록">
</p>

- **TUI** — 키보드 중심. 터미널에서 `hostveil`을 실행했을 때의 기본값입니다.
- **웹** — `hostveil serve`. localhost에 묶인 대시보드입니다. 일회용 접근
  토큰이 담긴 URL을 출력하니 그 URL을 그대로 여세요. 루프백은 대시보드를
  네트워크에서 떼어 놓을 뿐, 같은 머신의 다른 계정으로부터 지켜 주지는
  않습니다 — 게다가 root로 실행됩니다. 원격 접근이 필요하면 `--addr`를 바꾸는
  대신(그렇게 해도 노출되지 않습니다) SSH로 포트를 포워딩하세요.
- **CLI** — 스크립트로 다루는 `scan` / `fix` / `rollback`, `--json` 출력.

셋 모두 하나의 공유 엔진 위에 얹힌 얇은 층이라, 동일하게 동작합니다.

TUI와 대시보드는 다섯 가지 색상 테마를 공유합니다 — `onedark`(기본값),
`gruvbox`, `nord`, `catppuccin`, `tokyonight`. TUI에서 `t`를 눌러 고르면
기억되고, 대시보드에서는 상태 표시줄의 선택기를 쓰거나, `--theme nord` 또는
`HOSTVEIL_THEME=nord`로 명시할 수 있습니다.

여섯 가지 화면 배치도 함께 씁니다 — `console`(기본값)은 왼쪽에 영역 레일을
두어 모든 점수와 커버리지 공백을 담고, `split`, `triage`, `railverdict`,
`lanes`, `inline`이 나머지입니다. TUI에서는 `l`, 대시보드에서는 상태
표시줄의 선택기로 고릅니다. 넓은 창과 80칸 터미널에 동시에 맞는 배치는
없기에, 기본값이 흔한 경우를 답하고 선택기가 나머지를 답합니다.

TUI와 `scan`은 상태 기호를 패치된
[Nerd Font](https://www.nerdfonts.com/)에서 가져올 수도 있습니다 —
`--glyphs nerd`, 또는 한 번만 `HOSTVEIL_GLYPHS=nerd`. 자동 감지가 아니라
명시적 선택인 이유는, 터미널에 어떤 폰트를 쓰는지 물어볼 수 없고 없는 글리프도
있는 글리프와 똑같이 한 칸에 그려지기 때문입니다. 기본 세트는 평범한
유니코드(`plain`)라 어디서나 렌더링됩니다.

Nerd Font는 어떤 빌드든 됩니다 — Mono든 아니든. 기호는 Font Awesome 블록에서
가져오는데, 패치된 모든 폰트에 있고 모두에서 한 칸 너비입니다. 비-Mono
빌드에서 두 칸이 되는 것은 Powerline과 아이콘 영역이고, hostveil은 그것을 쓰지
않습니다.

## AI (선택, 조언 전용)

`hostveil explain <id> --ai`는 로컬 LLM(기본은 Ollama)의 쉬운 말 설명을
덧붙입니다. 무엇도 호스트를 떠나지 않습니다. AI는 철저히 조언 전용이며 —
변경을 적용하는 일이 없습니다 — 모든 설명과 점수, 수정은 AI가 전혀 없어도
동작합니다.

## 다른 도구와의 비교

서버 강화 도구 대부분은 감사자입니다: 보고서를 건네주고 고치는 일은 당신에게
남깁니다. hostveil은 보안 전문가가 아닌 사람들을 위해 그 고리를 닫으려고
만들어졌습니다.

- **[Lynis](https://github.com/CISOfy/lynis)**는 철저하고 전문가 지향적인
  호스트 감사 도구입니다. 긴 제안 목록을 출력하지만 적용하지는 않고, 그
  출력을 읽으려면 어떤 것이 중요한지 이미 알고 있어야 합니다.
- **[docker-bench-security](https://github.com/docker/docker-bench-security)**는
  Docker 호스트를 CIS 벤치마크에 견줍니다. 컨테이너에 한정되고, 고치는 대신
  보고합니다.
- **[Trivy](https://github.com/aquasecurity/trivy)**는 이미지와 파일시스템에서
  알려진 CVE와 설정 오류를 스캔합니다. 그 한 가지 일에 탁월하고 — hostveil도
  CVE 영역에서 실제로 Trivy를 *실행*합니다 — 다만 SSH 설정이나 방화벽, 계정은
  보지 않습니다.

hostveil의 관점은 호스트와 컨테이너, 이미지 CVE를 하나의 0–100 점수로 합치고,
각 발견 항목을 쉬운 말로 설명한 다음, 미리보기와 백업과 명령 한 번의 롤백과
함께 **수정을 적용하는** 것입니다. 바이너리 하나, 해석할 보고서 없음.

## 소스에서 빌드하기

```bash
go build ./cmd/hostveil
go test ./...
```

전체 설정(플랫폼별 데모 VM, 저장소 구조, 기여 체크리스트)은
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)를 보세요.

## 라이선스

[GPL-3.0](LICENSE)

> Team 내컴퓨터누가해킹했어 ([@gkdms04](https://github.com/gkdms04), [@seolcu](https://github.com/seolcu))
