# ethsy-server (Local Host Server)

ethsy.me 호스트 머신에서 실행되는 서버. OAuth 인증, SSH 키 관리, tmux 세션 관리, 어드민 패널을 제공.

## 구성 요소

```
ethsy-server
  ├── Web Server (HTTPS)      # OAuth + Admin + API
  ├── SSH Key Manager          # authorized_keys 관리
  ├── Session Manager          # tmux 세션 생명주기 관리
  └── SQLite DB                # 유저, 세션, 키 메타데이터
```

---

## 핵심 개념

- **유저별 홈 디렉터리**: 최초 인증 시 유저네임을 받아 `~/{username}` 디렉터리를 생성. 유저네임은 시스템 내에서 유니크해야 하며, 중복 시 다른 이름을 요구
- **SSH 키는 디바이스별 관리**: 동일 유저가 여러 디바이스에서 인증하면 각각의 공개키가 별도로 authorized_keys에 등록됨
- **tmux 세션은 유저(이메일)별 관리**: 어떤 디바이스에서 접속하든 동일 이메일이면 같은 세션 목록을 봄. tmux 세션의 working directory는 해당 유저의 홈 디렉터리(`~/{username}`)
- **동시 접속**: 여러 디바이스가 같은 tmux 세션에 attach하면 화면이 실시간 공유됨

---

## 1. Web Server

### 도메인 및 포트

- `connect.ethsy.me` : OAuth 인증 + CLI용 API (외부 공개)
- `ethsy.me/admin` : 어드민 패널 (localhost only)
- HTTPS 443 포트, Let's Encrypt autocert로 TLS 인증서 자동 발급

### 엔드포인트

#### 인증 (외부 공개)

| Method | Path | 설명 |
|--------|------|------|
| GET | `/auth` | OAuth 플로우 시작. `session` 쿼리로 CLI의 폴링 세션 ID 수신 |
| GET | `/auth/callback` | Google OAuth 콜백. 이메일 확인 후 토큰을 세션에 매핑 |
| GET | `/api/auth/poll` | CLI 폴링용. `session` 쿼리로 인증 완료 여부 + 토큰 반환 |

**OAuth 플로우:**

1. CLI가 브라우저로 `https://connect.ethsy.me/auth?session={session_id}` 오픈
2. 서버가 session_id를 저장 후 Google OAuth로 리다이렉트
3. Google 인증 완료 → 서버 `/auth/callback`으로 돌아옴
4. 서버가 이메일 화이트리스트 확인
5. 승인 시: JWT 토큰 생성 → session_id에 매핑하여 저장
6. 브라우저에 "인증 완료! 터미널로 돌아가세요" 페이지 표시
7. CLI가 `/api/auth/poll?session={session_id}` 폴링하다 토큰 수신

**최초 등록 플로우 (OAuth 이후, CLI에서):**

1. CLI가 토큰 수신 후 서버에 유저 존재 여부 확인
2. 신규 유저인 경우:
   - CLI가 유저네임 입력 프롬프트 표시: `사용할 이름을 입력하세요 (홈 디렉터리로 사용됩니다): `
   - `POST /api/register` 로 username + public_key 전송
   - 서버가 username 중복 체크 → 중복 시 409 응답 → CLI가 "이미 사용 중인 이름입니다. 다른 이름을 입력하세요:" 표시
   - 통과 시: 서버가 `~/{username}` 디렉터리 생성 + DB에 유저/키 등록
3. 기존 유저 + 새 디바이스인 경우:
   - `POST /api/register-key` 로 public_key만 전송 (username 불필요)

#### API (CLI용, JWT 인증 필요)

| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/me` | 현재 유저 정보 반환. 신규 유저면 404, 기존 유저면 200 + `{ "username": "...", "email": "..." }` 반환 |
| POST | `/api/register` | 최초 등록. body: `{ "username": "...", "public_key": "ssh-ed25519 ..." }`. username 중복 시 409 응답 |
| POST | `/api/register-key` | 기존 유저가 새 디바이스에서 키 추가. body: `{ "public_key": "ssh-ed25519 ..." }` |
| POST | `/api/revoke-key` | 공개키 해제 (해당 디바이스의 키만 제거) |
| GET | `/api/sessions` | 해당 유저의 tmux 세션 목록 반환 |
| POST | `/api/sessions` | 새 세션 생성. body: `{ "description": "..." }` |
| DELETE | `/api/sessions/:id` | 세션 삭제 (tmux kill + DB 삭제) |

#### 어드민 패널 (localhost only)

| Method | Path | 설명 |
|--------|------|------|
| GET | `/admin` | 어드민 대시보드 |
| GET | `/admin/users` | 화이트리스트 관리 페이지 |
| POST | `/admin/users` | 이메일 추가 |
| DELETE | `/admin/users/:id` | 이메일 제거 (+ 해당 유저의 모든 키/세션 정리) |
| GET | `/admin/sessions` | 전체 세션 모니터링 |

**어드민 접근 제어:**

- localhost (127.0.0.1) 에서만 접근 가능
- 외부에서 `/admin` 접근 시 403 반환

---

## 2. SSH Key Manager

`~/.ssh/authorized_keys` 파일을 프로그래밍 방식으로 관리.

**키 등록 형식:**
```
# ethsy-managed:user_id:key_id
ssh-ed25519 AAAA... user@device
```

- 각 키에 주석으로 `ethsy-managed:{user_id}:{key_id}` 태그를 붙여서 식별
- 수동으로 추가한 키에는 영향 없음
- 동일 유저라도 디바이스별로 별도 키가 등록됨

**키 해제:**
- `revoke-key` 호출 시 해당 디바이스의 키(key_id)만 제거
- 유저 삭제 시 해당 유저의 모든 키 일괄 제거

**키 정책:**
- 유저당 최대 키 개수: 5 (디바이스별)
- 토큰 만료 시 키도 자동 제거 (서버가 주기적으로 정리)

---

## 3. Session Manager

tmux 세션의 생명주기를 관리. 세션은 유저(이메일) 단위로 귀속되며, 해당 유저의 모든 디바이스에서 공유된다.

**세션 네이밍 규칙:**
```
ethsy_{user_id}_{session_number}
```

예: `ethsy_1_1`, `ethsy_1_2`, `ethsy_2_1`

**세션 생성:**
```bash
tmux new-session -d -s ethsy_{user_id}_{n} -c ~/{username} -x 200 -y 50
```

세션의 초기 working directory는 해당 유저의 홈 디렉터리(`~/{username}`).

**세션 접속 (CLI → SSH):**
```bash
ssh -t -p 9920 ethsy@ethsy.me "tmux attach -t ethsy_{user_id}_{n}"
```

여러 디바이스에서 같은 세션에 attach하면 tmux가 화면을 실시간 공유한다. 한쪽에서 타이핑하면 다른 쪽에서도 보인다.

**세션 정리:**
- 유저가 명시적으로 삭제 (`DELETE /api/sessions/:id`)
- 어드민이 삭제 (`/admin/sessions`)
- 일정 기간 비활성 세션 자동 정리 (설정 가능, 기본: 7일)

**tmux 기본 설정:**
- 서버에 `~/.ethsy/server/tmux.conf` 를 두고 세션 생성 시 적용
- 색상, 키바인딩, 상태바 등 최적화된 기본값 제공

---

## 4. Database (SQLite)

파일 경로: `~/.ethsy/server/ethsy.db`

### 테이블

**users**
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| email | TEXT UNIQUE | Google OAuth 이메일 |
| username | TEXT UNIQUE | 유저네임 (홈 디렉터리명으로 사용, ~/{username}) |
| is_admin | BOOLEAN | 어드민 여부 |
| created_at | DATETIME | |

**ssh_keys**
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| user_id | INTEGER FK | users.id |
| public_key | TEXT | SSH 공개키 전문 |
| fingerprint | TEXT UNIQUE | 키 핑거프린트 (중복 방지) |
| device_name | TEXT | 디바이스 식별용 (optional) |
| created_at | DATETIME | |
| expires_at | DATETIME | 토큰 만료에 연동 |

동일 user_id에 여러 ssh_keys 레코드가 존재할 수 있다 (디바이스별 1개).

**sessions**
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| user_id | INTEGER FK | users.id |
| tmux_name | TEXT UNIQUE | tmux 세션 이름 (ethsy_{user_id}_{n}) |
| description | TEXT | 유저가 지정한 설명 |
| created_at | DATETIME | |
| last_attached | DATETIME | 마지막 접속 시각 |

sessions는 user_id에 귀속된다. 해당 user_id를 가진 모든 디바이스에서 조회/접속 가능.

**auth_sessions** (CLI 폴링용 임시)
| 컬럼 | 타입 | 설명 |
|------|------|------|
| session_id | TEXT PK | CLI가 생성한 랜덤 ID |
| token | TEXT | 인증 완료 시 발급된 JWT (미완료면 NULL) |
| created_at | DATETIME | |
| expires_at | DATETIME | 폴링 만료 (2분) |

---

## 5. 설정 파일

경로: `~/.ethsy/server/config.yaml`

```yaml
domain: ethsy.me
connect_domain: connect.ethsy.me
port: 443

oauth:
  provider: google
  client_id: "..."
  client_secret: "..."

jwt:
  secret: "..."  # 초기 설정 시 자동 생성
  expiry: 720h   # 30일

ssh:
  port: 9920
  authorized_keys: ~/.ssh/authorized_keys
  max_keys_per_user: 5

session:
  cleanup_after: 168h  # 7일 비활성 시 정리
  tmux_config: ~/.ethsy/server/tmux.conf

admin:
  emails:
    - ethsy@gmail.com
```

---

## 6. 설치 및 실행

```bash
# 설치
go install github.com/devsigner9920/ethsy-ssh/server@latest

# 초기 설정 (대화형: Google OAuth 클라이언트 ID, 어드민 이메일 등 입력)
ethsy-server init

# 실행
ethsy-server start

# macOS launchd 데몬 등록 (부팅 시 자동 시작)
ethsy-server install-service
```

**launchd 등록 시:**
- `~/Library/LaunchAgents/me.ethsy.server.plist` 생성
- 로그인 시 자동 시작
- 크래시 시 자동 재시작

---

## 7. 보안 고려사항

| 항목 | 대응 |
|------|------|
| HTTPS 필수 | Let's Encrypt autocert (443 포트) |
| 어드민 접근 | localhost only |
| JWT 탈취 | 만료 기간 설정 + revoke API |
| authorized_keys 변조 | ethsy-managed 태그로 관리 범위 한정 |
| tmux 세션 격리 | 유저별 세션 네이밍으로 다른 유저 세션 접근 불가 |
| OAuth state 검증 | CSRF 방지용 state 파라미터 필수 |
| 폴링 세션 | 2분 만료 + 1회 소비 후 삭제 |

---

## 8. DNS 추가 설정

| 타입 | 호스트 | 값 |
|------|--------|-----|
| A | (비워두기) | 49.164.90.157 |
| A | connect | 49.164.90.157 |

## 9. 공유기 추가 포트포워딩

| 외부 포트 | 내부 포트 | 용도 |
|-----------|-----------|------|
| 9920 | 22 | SSH (기존) |
| 443 | 443 | HTTPS (OAuth + API) |
| 80 | 80 | Let's Encrypt 인증서 발급 (HTTP challenge) |
