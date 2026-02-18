# ethsy-connect (CLI Client)

외부 디바이스에서 ethsy.me 호스트에 접속하기 위한 CLI 도구. `brew install`로 설치하고 `ethsy` 명령어로 사용.

---

## 설치

```bash
brew tap devsigner9920/tap
brew install ethsy-connect
```

설치 후 `ethsy` 명령어 사용 가능.

---

## 핵심 개념

- **유저별 홈 디렉터리**: 최초 인증 시 유저네임을 받아 서버에 `~/{username}` 디렉터리 생성. 유저네임은 유니크해야 하며 중복 시 다른 이름 요구
- **SSH 키는 디바이스별**: 각 디바이스에서 최초 인증 시 개별 SSH 키페어 생성 및 등록
- **tmux 세션은 유저(이메일)별**: 동일 이메일이면 어떤 디바이스에서든 같은 세션 목록을 공유
- **동시 접속 가능**: 여러 디바이스에서 같은 tmux 세션에 attach하면 화면이 실시간 공유됨

---

## 로컬 저장 경로

```
~/.ethsy/connect/
  ├── config.json    # 토큰, 유저 정보
  └── key/           # SSH 키 (자동 생성, 이 디바이스 고유)
      ├── id_ed25519
      └── id_ed25519.pub
```

**config.json:**
```json
{
  "token": "eyJhb...",
  "email": "user@gmail.com",
  "username": "{username}",
  "server": "connect.ethsy.me"
}
```

---

## 명령어

### `ethsy` (메인 명령어)

상태에 따라 분기:

#### 1) 미인증 상태 (config.json 없거나 토큰 만료)

```
$ ethsy

ethsy.me에 접속하려면 인증이 필요합니다.
브라우저에서 로그인 페이지를 여는 중...

브라우저가 열리지 않으면 아래 URL을 직접 열어주세요:
https://connect.ethsy.me/auth?session=abc123

인증 대기 중...
```

OAuth 완료 후:

```
인증 완료! ({email})
```

#### 2) 최초 등록 (신규 유저)

OAuth 직후, 서버에 유저가 없는 경우:

```
사용할 이름을 입력하세요 (홈 디렉터리로 사용됩니다): {username}
```

중복 시:
```
이미 사용 중인 이름입니다. 다른 이름을 입력하세요: {username}
```

성공 시:
```
등록 완료! 홈 디렉터리: ~/{username}
```

이 시점에 SSH 키 자동 생성 + 서버에 username과 public_key를 함께 등록 (`POST /api/register`).

#### 3) 기존 유저 + 새 디바이스

OAuth 완료 후 서버에 이미 유저가 있는 경우:

```
인증 완료! ({email})
이 디바이스의 SSH 키를 등록하는 중...
등록 완료!
```

유저네임 입력 없이 키만 등록 (`POST /api/register-key`).

#### 4) 인증 완료 상태 (일반 사용)

```
$ ethsy

{email}의 세션:

  #   Description          Status     Created
  1   dev server           active     2h ago
  2   debugging api        detached   30m ago

접속할 세션 번호를 선택하세요 (1-2):
```

번호 선택 시 SSH로 해당 tmux 세션에 attach.

**세션이 1개뿐일 때:**

목록 표시 없이 바로 해당 세션에 접속.

**세션이 0개일 때:**

```
세션이 없습니다. 새 세션을 생성합니다...
```

자동으로 새 세션 생성 후 접속.

### `ethsy new [description]`

새 tmux 세션 생성 후 바로 접속. 추가 인증 없이 저장된 토큰 + SSH 키 사용.

```bash
ethsy new                    # 세션 생성 (description 없음)
ethsy new "frontend 작업"     # 세션 생성 + description 지정
```

1. 저장된 토큰으로 서버 API 호출 (`POST /api/sessions`, body: `{ "description": "..." }`)
2. 서버에서 tmux 세션 생성 (working directory: `~/{username}`)
3. SSH 키로 바로 접속 + 새 세션 attach

### `ethsy list`

세션 목록만 표시 (접속하지 않음).

### `ethsy delete <session_number>`

세션 삭제.

```
$ ethsy delete 2
세션 #2 (debugging api)를 삭제합니다. 계속하시겠습니까? (y/n): y
세션 삭제 완료.
```

### `ethsy logout`

로컬 인증 정보 삭제 + 서버에서 해당 디바이스의 키 revoke.

```
$ ethsy logout
이 디바이스의 인증 정보를 삭제합니다.
SSH 키가 서버에서 제거되었습니다.
로그아웃 완료.
```

다른 디바이스의 키와 세션에는 영향 없음.

### `ethsy status`

현재 인증 상태 표시.

```
$ ethsy status
이메일: {email}
유저네임: {username}
홈 디렉터리: ~/{username}
디바이스 키: ~/.ethsy/connect/key/id_ed25519
토큰 만료: 2026-03-18
```

---

## 내부 플로우 상세

### OAuth 인증 플로우

1. 랜덤 `session_id` 생성 (UUID v4)
2. `open "https://connect.ethsy.me/auth?session={session_id}"` 로 브라우저 오픈
3. 1초 간격으로 `GET https://connect.ethsy.me/api/auth/poll?session={session_id}` 폴링
4. 폴링 타임아웃: 2분 (초과 시 안내 메시지 + 재시도 제안)
5. 토큰 수신 시 `~/.ethsy/connect/config.json`에 저장

### 유저 등록 플로우 (신규 유저)

1. 토큰으로 `GET /api/me` 호출 → 404면 신규 유저
2. 유저네임 입력 프롬프트 표시
3. SSH 키페어 자동 생성 (`~/.ethsy/connect/key/id_ed25519`)
4. `POST /api/register` with `{ "username": "...", "public_key": "ssh-ed25519 ..." }`
5. 서버 응답 409 (중복) → 다시 입력 요청
6. 서버 응답 200 → config.json에 username 저장, 등록 완료

### 키 등록 플로우 (기존 유저 + 새 디바이스)

1. 토큰으로 `GET /api/me` 호출 → 200이면 기존 유저
2. SSH 키페어 자동 생성
3. `POST /api/register-key` with `{ "public_key": "ssh-ed25519 ..." }`
4. config.json에 username(서버에서 받아옴) 저장, 등록 완료

### SSH 접속

모든 SSH 접속은 ethsy 전용 키를 사용:

```bash
ssh -t -i ~/.ethsy/connect/key/id_ed25519 -p 9920 ethsy@ethsy.me "tmux attach -t {tmux_name}"
```

CLI가 ssh 프로세스를 exec하여 터미널 제어권을 넘김. (`-t` 플래그로 PTY 할당)

---

## 기술 스택

- **언어**: Go
  - 크로스 컴파일 용이 (macOS arm64/amd64, Linux amd64)
  - 단일 바이너리 배포 (brew에 적합)
  - `os/exec`로 ssh 프로세스 실행
  - `net/http`로 서버 폴링
- **외부 의존성**: 없음 (시스템의 ssh, open 명령어 사용)

---

## Homebrew 배포

### Tap 구조

GitHub repo: `github.com/devsigner9920/homebrew-tap`

```
homebrew-tap/
  └── Formula/
      └── ethsy-connect.rb
```

### Formula 예시

```ruby
class EthsyConnect < Formula
  desc "CLI client for ethsy.me remote tmux sessions"
  homepage "https://github.com/devsigner9920/ethsy-ssh"
  url "https://github.com/devsigner9920/ethsy-ssh/releases/download/v0.1.0/ethsy-connect-darwin-arm64.tar.gz"
  sha256 "..."
  license "MIT"

  def install
    bin.install "ethsy"
  end
end
```

### 릴리즈 프로세스

1. `goreleaser`로 macOS (arm64, amd64) + Linux (amd64) 바이너리 빌드
2. GitHub Releases에 업로드
3. homebrew-tap Formula의 url, sha256 업데이트

---

## 에러 처리

| 상황 | 동작 |
|------|------|
| 서버 응답 없음 | "connect.ethsy.me에 연결할 수 없습니다" 출력 |
| OAuth 이메일이 화이트리스트에 없음 | "접근 권한이 없습니다. 관리자에게 문의하세요" 출력 |
| username 중복 (409) | "이미 사용 중인 이름입니다. 다른 이름을 입력하세요:" 재입력 |
| 토큰 만료 | 자동으로 재인증 플로우 시작 |
| SSH 접속 실패 | ssh 에러 메시지 그대로 출력 |
| tmux 세션 없음 (삭제됨) | "세션을 찾을 수 없습니다" 출력 후 목록 재표시 |
| 폴링 타임아웃 (2분) | "인증 시간이 초과되었습니다. 다시 시도하세요" 출력 |
