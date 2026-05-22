# hostveil 기여 가이드

hostveil에 관심을 가져주셔서 감사합니다. 이 문서는 프로젝트 기여 시 필요한 정보를 제공합니다.

## 프로젝트 소개

hostveil은 Linux self-hosting 환경의 보안 설정을 점검하는 TUI 대시보드입니다.
Go 1.24+와 Bubbletea로 작성되었으며, Docker Compose 스택과 호스트 환경을 자동으로 스캔합니다.

자세한 구현 상태와 아키텍처는 [AGENTS.md](AGENTS.md)를 참고해주세요.

## 개발 환경 설정

- **Go 1.24 이상**이 필요합니다. `go version`으로 확인해주세요.
- Docker Compose V2가 설치되어 있어야 합니다 (lab 환경 실행 시).

```sh
# 저장소 클론
git clone https://github.com/seolcu/hostveil.git
cd hostveil

# 빌드
go build -o hostveil ./cmd/hostveil/

# 도커 Lab 환경 실행 (선택 사항)
./scripts/lab.sh up
```

## 코드 스타일

- `gofmt`으로 코드 포맷을 맞춰주세요.
- `go vet ./...` 실행 시 경고가 없어야 합니다.
- `golangci-lint` 설정이 있는 경우 통과를 권장합니다.
- 불필요한 주석보다는 명확한 변수명과 일관된 네이밍을 선호합니다.

## 테스트 실행

```sh
# 전체 테스트 (race detection 포함)
go test -race -count=1 ./...

# 특정 패키지 테스트
go test -race -count=1 ./internal/scanner/...
go test -race -count=1 ./internal/adapter/...
go test -race -count=1 ./internal/fix/...
go test -race -count=1 ./internal/export/...
```

새로운 기능 추가 시 관련 테스트를 함께 작성해주세요.

## 브랜치 전략 (GitHub Flow)

1. `main` 브랜치에서 기능 브랜치를 생성해주세요.
2. 브랜치 이름은 `feat/`, `fix/`, `docs/`, `refactor/`, `chore/` 접두사를 사용합니다.
3. 작업 완료 후 `main` 브랜치로 Pull Request를 생성해주세요.
4. 최소 1명의 리뷰어 승인을 받은 후 병합합니다.
5. `main` 브랜치로의 직접 푸시는 차단되어 있습니다.

## 커밋 메시지 규칙

[Conventional Commits](https://www.conventionalcommits.org/) 형식을 따릅니다.

```
<type>(<optional scope>): <간결한 설명>

[선택 사항: 본문]
```

타입: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
요약 줄은 72자 이내, 명령형으로 작성합니다.

## Pull Request 프로세스

- PR 제목도 Conventional Commits 형식을 권장합니다.
- 변경 사항이 있는 경우 관련 테스트가 통과하는지 확인해주세요.
- UI 변경이 있는 경우 스크린샷 또는 설명을 함께 첨부해주세요.
- 불필요한 의존성 변경은 PR 범위에서 제외해주세요.

## 행동 강령

서로를 존중하고 건설적으로 소통해주세요. 차별, 비방, 괴롭힘은 허용되지 않습니다.
