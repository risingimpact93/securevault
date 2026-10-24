# Keyhaven — 로컬 비밀번호 관리자

Keyhaven은 내 기기에만 저장되는 암호화 비밀번호 관리 앱입니다 (Tauri 2 데스크톱 + Axum 웹 + React + Rust).

## 기능
- 마스터 비밀번호로 금고 생성 / 잠금 해제 / 잠금, 마스터 비밀번호 변경
- 항목: 로그인, 보안 메모, 카드 — 추가·수정·삭제·검색·즐겨찾기
- 비밀번호 생성기 (길이 4~128, 대문자/소문자/숫자/기호 선택)
- 클립보드 복사 후 30초 뒤 자동 삭제 (그 사이 다른 걸 복사했으면 건드리지 않음)
- 마우스·키보드·터치가 없으면 자동 잠금. 선택: 1분, 2분, 5분, 10분, 30분, 1시간 (기본 1분). 값은 암호화된 금고 안에 저장되어 데스크톱과 웹이 같은 설정을 씁니다
- macOS 앱: 화면이 잠기거나 잠자기에 들어가면 즉시 잠그는 옵션
- 생체 인증: macOS는 Touch ID, 웹은 패스키(WebAuthn). 마스터 비밀번호는 항상 사용할 수 있습니다. 프로세스를 다시 시작한 직후와 N일마다(기본 14일, 1–365일) 마스터 비밀번호가 다시 필요합니다
- 별도 비밀번호로 암호화된 내보내기 / 가져오기 (병합 또는 교체)
- 기기 간 동기화: 금고 파일을 iCloud Drive 같은 폴더로 옮기고, 저장 전에 항목 단위로 병합합니다. 아래 "기기 간 동기화 (iCloud)"를 보세요
- 다크/라이트 테마

## 보안 구조
- 키 유도: Argon2id (64 MiB, 반복 3, 병렬 1, 무작위 16바이트 salt)
- 암호화: XChaCha20-Poly1305 (무작위 24바이트 nonce), 파일 헤더를 AAD로 묶어 변조 시 열리지 않음
- 기본 저장 위치: `~/Library/Application Support/com.keyhaven.app/vault.khv` (임시 파일 후 교체 방식으로 안전 저장). 설정에서 다른 절대 경로로 옮기거나 기존 파일을 열 수 있습니다. 그 경로에는 암호화된 파일만 두고, 잠금·세션·토큰·패스키·Touch ID 자료는 앱 데이터 폴더에 남습니다. 생체 인증 켜기/끄기는 금고 안에 있어 파일과 함께 동기화되지만, 키체인과 패스키 재료는 옮겨지지 않습니다
- 암호화 키는 메모리에서 zeroize/secrecy로 관리하고, 잠그면 지웁니다
- 자동 잠금·화면 잠금·생체 인증 사용 여부·비밀번호 재확인 주기는 암호문 안의 `settings`에 있습니다. 예전 금고 파일에 이 필드가 없으면 기본값(1분, 생체 인증 끔, 14일)으로 열립니다
- 웹 패스키의 공개 자격 증명과 PRF로 감싼 금고 키는 암호문 밖 `webauthn.json`에 있습니다. PRF를 지원하지 않는 인증기는 서버 메모리에 키가 남아 있을 때만 세션을 다시 엽니다
- macOS Touch ID는 데이터 보호 키체인에 금고 키를 넣고 `biometryCurrentSet`으로 지문이 바뀌면 그 항목을 무효로 합니다
- 마스터 비밀번호를 잊으면 복구할 수 없습니다 (서버 없음)

## 맥(Apple Silicon)에서 빌드하기
1. Xcode 명령줄 도구: `xcode-select --install`
2. Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` 후 터미널 재시작 (`rustc -V` 확인)
3. Node.js 20 이상: `brew install node` (또는 nodejs.org 설치 파일)
4. 압축을 풀고 폴더로 이동:
   ```
   unzip vaultapp-src.zip && cd vaultapp
   npm install
   ```
5. 바로 실행해 보기 (개발 모드): `npm run tauri dev`
6. 앱 만들기: `npm run tauri build`
   - 결과물: `src-tauri/target/release/bundle/macos/Keyhaven.app` 와 `bundle/dmg/Keyhaven_*.dmg`
   - `Keyhaven.app`을 `응용 프로그램` 폴더로 옮기면 됩니다.
7. 서명이 없는 앱이라 처음 열 때 "확인되지 않은 개발자" 경고가 나오면: Finder에서 앱을 우클릭 → 열기, 또는
   `xattr -dr com.apple.quarantine /Applications/Keyhaven.app`

## macOS 빌드 주의사항

Touch ID와 키체인은 서명된 앱에서만 안정적으로 동작합니다. `tauri.conf.json`의 `bundle.macOS`는 최소 macOS 10.15, 강화된 런타임(`hardenedRuntime: true`), 자격 파일, `Info.plist`를 가리킵니다. `signingIdentity`는 비어 있습니다. 배포할 때 Apple Developer ID(또는 팀에 고정된 서명 신원)를 넣으세요. 임시 서명(`codesign --sign -`)은 빌드마다 신원이 바뀌어 키체인 항목이 바로 무효가 됩니다.

- 자격(`src-tauri/entitlements.plist`): `keychain-access-groups` = `$(AppIdentifierPrefix)com.keyhaven.app`. 접근 그룹을 직접 지정할 때만 환경 변수 `KEYHAVEN_KEYCHAIN_ACCESS_GROUP`을 같은 값으로 설정합니다. 비워 두면 그룹을 묻지 않습니다.
- 코드 서명 신원: 강화된 런타임과 함께 안정적인 서명이 필요합니다. 키체인 ACL은 서명 신원이 바뀌면 읽기가 실패하고, 앱은 생체 인증을 끈 뒤 다음 마스터 비밀번호 잠금 해제 때 설정을 저장합니다.
- `Info.plist`의 `NSFaceIDUsageDescription`: Touch ID/Face ID 사용 이유를 적습니다. 없으면 시스템 프롬프트가 거절될 수 있습니다.
- 금고 키는 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`와 `biometryCurrentSet`으로 데이터 보호 키체인에 저장합니다. 등록된 생체 정보가 바뀌면 키체인 읽기가 실패하고 생체 인증은 무효가 됩니다.
- 화면 잠금·잠자기 즉시 잠금은 macOS에서만 동작합니다 (`com.apple.screenIsLocked`, IOKit 전원 알림). 다른 OS와 웹은 설정을 저장만 하고 감시하지 않습니다. 잠자기 알림은 `IOAllowPowerChange`로 응답합니다.

## 테스트
워크스페이스 전체 (금고 포맷, MCP, 웹 서버 보안):
```
cargo test --workspace
```
프론트엔드 빌드:
```
npm run build
```
데스크톱 패키지만 확인하려면 `cargo test -p keyhaven -p keyhaven-core` 입니다. 금고 암복호화·MCP 도구 테스트는 `keyhaven-core`에 있습니다.

## 브라우저 미리보기
웹 서버와 함께 쓰려면 아래 **웹 버전**을 보세요. `npm run dev`(http://localhost:1420)는 Tauri 개발용이며, `/api`와 `/mcp`를 `http://127.0.0.1:8787`로 프록시합니다. 실제 금고를 쓰려면 같은 머신에서 `keyhaven-web`도 켜 두세요.

## MCP 연결 (외부 에이전트에서 금고 사용)

Keyhaven 앱 안에 로컬 MCP 서버가 들어 있어서 Grok Bot이나 Claude Desktop 같은 에이전트가 금고를 검색할 수 있습니다.

### 동작 방식
- 주소: `http://127.0.0.1:47821/mcp` (Streamable HTTP, 이 맥 안에서만 접속 가능, 포트는 설정에서 변경)
- 기본은 꺼져 있습니다. 설정 → **MCP 연결**에서 "MCP 서버 사용"을 켜고 적용하세요.
- 금고가 **잠겨 있으면** 모든 도구 호출이 `Keyhaven vault is locked` 오류로 거부됩니다.
- 인증: 설정 → **접근 토큰**에서 이름을 넣고 토큰을 발급합니다. 토큰은 **발급 직후 한 번만** 보이니 바로 복사하세요. 앱에는 SHA-256 해시만 저장되고, 폐기하면 즉시 401로 거부됩니다.
- **접근 기록**: 시각, 토큰 이름, 도구, 항목 ID, 허용/거부, 사유 (최근 1000건). 비밀 값과 검색어는 기록하지 않습니다.

### 도구
| 도구 | 설명 | 승인 |
|---|---|---|
| `search_items(query?, type?)` | 제목/사용자/주소/태그 검색, 메타데이터만 | 불필요 |
| `list_items` | 전체 항목 메타데이터 | 불필요 |
| `get_item_metadata(id)` | 한 항목 메타데이터 | 불필요 |
| `get_secret(id, field)` | 비밀번호·카드번호·CVV·메모 본문 | **매번 앱에서 승인** (60초 안에 응답 없으면 거부) |

메타데이터 = id, 제목, 종류, 사용자 이름, 주소, 태그, 즐겨찾기, 만든/수정 시각. 비밀 값은 절대 포함되지 않습니다.

### Claude Desktop 연결 (stdio 브리지)
Claude Desktop은 stdio 방식을 쓰므로 함께 들어 있는 `bridge/keyhaven-mcp-bridge.mjs`(Node 18+, 의존성 없음)를 사용합니다.
`~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "keyhaven": {
      "command": "node",
      "args": ["/Users/<내계정>/keyhaven/vaultapp/bridge/keyhaven-mcp-bridge.mjs"],
      "env": {
        "KEYHAVEN_MCP_URL": "http://127.0.0.1:47821/mcp",
        "KEYHAVEN_MCP_TOKEN": "여기에_발급받은_토큰"
      }
    }
  }
}
```
`node` 경로를 못 찾으면 `which node` 결과(예: `/opt/homebrew/bin/node`)를 command에 넣으세요. 저장 후 Claude Desktop을 재시작합니다.

### Grok Bot 연결
- 사용자 지정 MCP 서버로 URL `http://127.0.0.1:47821/mcp`, 헤더 `Authorization: Bearer <토큰>`을 추가합니다.
- **주의:** Grok Bot의 클라우드 컴퓨터에서는 맥의 `127.0.0.1`에 닿을 수 없습니다. Grok Bot이 그 맥 위에서 실행되거나 그 맥에 연결된 상태(맥에서 명령을 실행할 수 있는 상태)여야 하며, 그 경우 맥에서 위 stdio 브리지를 실행하는 방식으로 연결합니다.
- 외부에 포트를 열거나 터널로 공개하는 것은 권장하지 않습니다.

### 한계
- 앱이 켜져 있고 잠금이 풀려 있을 때만 동작합니다.
- 비밀 값을 승인하면 그 값은 상대 에이전트(및 그 AI 서비스)로 전달됩니다. 꼭 필요할 때만 승인하세요.
- 토큰을 가진 같은 맥의 다른 프로그램도 메타데이터는 승인 없이 읽을 수 있습니다.
- 서버는 일반 JSON 응답만 하며 SSE 스트리밍/세션 재개는 지원하지 않습니다 (도구 호출에는 충분). 웹 버전의 `/mcp`도 같은 JSON 응답입니다. 웹 UI의 비밀 값 승인은 SSE(및 폴링)로 실시간 표시됩니다.

## 웹 버전

같은 React UI와 같은 `.khv` 금고 포맷을 Axum HTTP 서버로 제공합니다. 데스크톱 Tauri 앱과 Cargo 워크스페이스를 공유하며 (`crates/keyhaven-core`), 기본 바인딩은 `127.0.0.1`입니다.

### 실행
1. 프론트엔드 빌드: `npm install && npm run build` (`dist/`가 생깁니다)
2. 웹 서버:
   ```
   cargo run -p keyhaven-web -- --dev-insecure-cookie
   ```
   또는 `npm run web`
3. 브라우저에서 http://127.0.0.1:8787
   패스키를 쓰려면 **http://localhost:8787** 로 여세요. 서버는 계속 `127.0.0.1`에만 붙어 있고, WebAuthn RP ID는 `localhost`만 허용합니다. `127.0.0.1`은 RP ID가 될 수 없습니다.

주요 옵션:
- `--bind 127.0.0.1` (기본값) — 이 컴퓨터에서만 접속
- `--port 8787` — HTTP 포트
- `--data-dir DIR` — 기본 `vault.khv`, 로컬 설정(`keyhaven-config.json`), MCP 설정이 저장되는 디렉터리. 금고 파일 경로는 설정에서 바꿀 수 있고, 잠금 상태와 토큰은 이 디렉터리에 남습니다
- `--dist-dir DIR` — `npm run build` 결과 (`dist/`)
- `--dev-insecure-cookie` — 세션 쿠키에서 `Secure`만 빼서 **http://127.0.0.1** 테스트용. 그 외 플래그는 그대로입니다 (`HttpOnly; SameSite=Strict`)
- `--idle-timeout-secs 60` — 금고를 열기 전 서버 유휴 잠금의 예비 값입니다. 연 뒤에는 금고 안의 자동 잠금(기본 1분)이 이 값을 바꿉니다. 탭이 백그라운드여도 서버가 같은 시간으로 세션을 끊습니다. 승인 목록 조회나 SSE는 시간을 연장하지 않고, 마우스·키보드·터치로 `/api/activity`가 호출될 때만 연장됩니다

잠금 해제 후 세션 쿠키는 `HttpOnly; SameSite=Strict; Secure`입니다. HTTP 로컬 테스트에서만 `--dev-insecure-cookie`를 쓰세요. 상태 변경 요청은 세션마다 발급되는 `X-CSRF-Token` 헤더와 Origin/Host 검사로 막습니다. 로그인 실패는 IP별 지수 백오프입니다.

패스키는 설정에서 켜고 끌 수 있습니다. 브라우저가 WebAuthn PRF를 주면 그 출력으로 금고 키를 감싸 두어, 메모리를 지운 뒤에도 패스키로 열 수 있습니다. PRF가 없으면 패스키는 아직 메모리에 키가 있을 때(유휴 잠금 직후)만 세션을 다시 엽니다. 명시적으로 잠그면 키가 지워지므로 마스터 비밀번호가 필요합니다. 패스키를 지우거나 다시 등록하면 이전 자격 증명과 감싼 키는 무효가 됩니다. 마스터 비밀번호를 바꾸면 감싼 키를 버리고, 다음 패스키 인증 때 PRF가 있으면 새 키로 다시 감쌉니다.

MCP는 같은 서버의 `http://127.0.0.1:8787/mcp`입니다. 설정에서 MCP를 켠 뒤 접근 토큰을 발급하고 `Authorization: Bearer <토큰>`을 붙입니다. `get_secret`은 웹 UI에서 승인·거절하며, 60초 동안 응답이 없으면 거부됩니다.

### iPhone / iPad에서 HTTPS로 쓰기

Safari는 보안 쿠키와 클립보드 등에 HTTPS(또는 http localhost)를 요구하는 경우가 많습니다. **이 저장소는 터널을 열거나 외부에 노출하지 않습니다.** 아래는 직접 구성할 때의 선택지입니다. 어떤 경우든 Keyhaven 프로세스는 `127.0.0.1`에만 두고, 앞단에서 TLS를 종료하세요.

| 방법 | 누가 닿나 | 인증 | 암호화 | 위험 / 비고 |
|---|---|---|---|---|
| **Tailscale Serve** | 같은 Tailnet 기기 (내 아이폰 포함) | Tailscale 노드 신원 | HTTPS (Tailscale 인증서) | 가장 단순. 인터넷 전체에 열리지 않음. 아이폰에 Tailscale 앱 필요 |
| **Tailscale Funnel** | 인터넷의 아무나 (URL을 아는 사람) | Funnel 공개 HTTPS | HTTPS | **권장하지 않음.** 마스터 비밀번호 추측·토큰 유출 면적이 커짐. 꼭 쓸 경우 강력한 마스터 비밀번호 + MCP 끄기 |
| **Cloudflare Tunnel + Access** | Access 정책에 통과한 사람 | Cloudflare Access (이메일 OTP, IdP 등) | HTTPS | 제로트러스트 앞단. 본인만 허용하는 Access 앱을 반드시 켤 것. 터널만 열고 Access를 끄면 Funnel과 비슷하게 공개됨 |
| **VPS + Let's Encrypt** | 그 서버/리버스 프록시에 닿는 사람 | 보통 nginx/Caddy 기본 인증 또는 VPN | Let's Encrypt HTTPS | Keyhaven은 루프백에만 바인드하고 Caddy/nginx가 TLS 종료. 방화벽으로 22/443만, 가능하면 VPN 뒤에서만 |

권장 순서: 같은 사람 기기만이면 **Tailscale Serve**. 계정 단위 정책이 필요하면 **Cloudflare Tunnel + Access**. 공인 IP 서버를 이미 운영할 때만 VPS. Funnel이나 인증 없는 공개 터널은 비밀번호 관리자에 맞지 않습니다.

iPhone/iPad 팁:
- 홈 화면에 추가하면 전체 화면에 가깝게 열립니다 (viewport-fit, safe-area 적용).
- `--dev-insecure-cookie`는 폰의 `http://` 주소에는 쓰지 마세요. HTTPS 뒤에서 기본 `Secure` 쿠키를 사용합니다.
- 같은 금고 파일을 여러 기기에서 쓰려면 아래 기기 간 동기화를 따르세요. 동기화를 쓰지 않는다면 데스크톱과 웹이 같은 `vault.khv`를 동시에 열지 마세요.

## 기기 간 동기화 (iCloud)

여러 Mac(또는 같은 파일을 보는 웹 서버)이 하나의 암호화된 `vault.khv`를 나눠 쓸 수 있습니다. 브라우저 자동 입력은 없습니다.

### 준비
1. 한 기기에서 금고를 연 뒤 설정 → 기기 간 동기화에서 경로를 지정합니다. 예: `~/Library/Mobile Documents/com~apple~CloudDocs/Keyhaven/vault.khv`
2. **이 경로로 옮기기**는 현재 금고 파일을 그 위치로 옮깁니다. 선택한 경로에는 암호문 파일만 있습니다.
3. 다른 Mac의 Keyhaven에서 **이 경로 열기**로 같은 파일을 지정합니다. iCloud가 파일을 아직 받지 못했으면 "iCloud에서 내려받는 중"으로 표시하고, macOS에서는 `brctl download`로 받기를 요청합니다. 다른 운영체제에서는 기다리기만 합니다.
4. 웹 UI는 서버 파일 시스템을 고를 수 없으므로 절대 경로를 직접 입력합니다.
5. 잠금 상태, 세션, MCP 토큰, 패스키(`webauthn.json`), Touch ID 키체인 항목은 각 기기의 앱 데이터 폴더에 남습니다. 기기마다 기기 id가 `keyhaven-config.json`에 저장되며 이 파일은 금고 안에 넣지 않습니다.

### 병합
- 금고에는 수정 횟수(revision)와 마지막으로 저장한 기기 id가 있습니다. 각 항목에는 id, `updated_at`, 기기별 버전 벡터가 있습니다.
- 저장하기 전에 디스크의 파일이 마지막으로 읽은 것과 다르면(해시, nonce, revision) 그 파일을 풀어 항목마다 병합한 뒤 저장합니다. 잠금이 풀려 있는 동안 몇 초마다 파일 시각과 해시를 다시 보고, 바뀌었으면 같은 방식으로 합칩니다. 화면은 동기화 상태를 주기적으로 읽어 항목 목록을 새로고칩니다.
- 한 쪽 버전 벡터가 다른 쪽을 포함하면 그 쪽이 이깁니다(원인 있는 변경). 둘 다 살아 있고 서로 포함하지 않으면 `updated_at`이 늦은 쪽이 이기고, 시각이 같으면 기기 id가 큰 쪽이 이깁니다.
- 삭제와 편집이 겹치고 편집이 삭제보다 원인적으로 나중이 아니면 삭제가 이깁니다. 동시에 고친 내용은 충돌 목록에 남습니다. 그 버전을 복원하면 이 기기의 버전 번호를 올려 삭제를 이기고, 이후 어느 쪽으로 합쳐도 살아 있습니다. 삭제를 반영한 뒤의 수정은 항목을 다시 살립니다.
- 같은 폴더의 `vault 2.khv`, `vault (conflict).khv`처럼 갈라진 충돌 파일은 합친 뒤 동기화 폴더 밖으로 옮깁니다. 백업은 앱 데이터 폴더의 `sync-backups`(웹은 서버의 로컬 데이터 폴더)에 두고, 최근 10개만 유지하며 7일이 지난 파일은 지웁니다. 비밀번호가 달라 아직 합치지 못한 파일은 옮기거나 지우지 않습니다.

### 충돌
- 동시에 고친 항목은 이긴 쪽을 남기고, 진 쪽을 그 항목의 충돌 목록에 보관합니다. 삭제된 항목의 충돌도 같은 목록에서 보고 복원할 수 있습니다. 데이터를 조용히 버리지 않습니다.
- 설정에서 충돌을 보고 **현재 항목 유지** 또는 **보관 버전으로 되돌리기**를 고릅니다. 유지한 충돌은 다음 병합에서 다시 나타나지 않습니다.
- 다른 파일의 마스터 비밀번호나 salt가 달라 풀 수 없으면 자동으로 합치지 않습니다. 화면에 그 파일의 비밀번호를 물어 본 뒤에만 병합합니다.
- 예전 형식의 금고도 열립니다. 없는 id, 시각, 버전 벡터는 불러올 때 채우며, 두 기기가 같은 예전 항목을 보면 같은 id를 만듭니다.

### 한계
- 자동 병합은 같은 마스터 비밀번호로 풀리는 파일만 대상입니다.
- iCloud가 파일을 내려주기 전에는 실시간으로 반영되지 않습니다. 같은 컴퓨터의 잠금 파일로 동시에 쓰는 것을 막지는 않고, 기기 사이는 낙관적 병합입니다.
- 잠금, 세션, MCP 토큰, 패스키, Touch ID 재료는 동기화되지 않습니다. 생체 인증 사용 여부만 금고 설정과 함께 이동합니다.
- 이 버전이 아닌 앱은 삭제 표시와 충돌 목록을 무시할 수 있으므로, 같은 파일을 여는 기기는 이 버전을 쓰는 것이 안전합니다.
- 브라우저 자동 입력은 제공하지 않습니다.

## CI (GitHub Actions)

`.github/workflows/build.yml`은 푸시와 수동 실행(workflow_dispatch)에서 돌아요.

- **linux-web** (ubuntu): `npm ci && npm run build`, `cargo test --workspace`, `keyhaven-web` 릴리스 빌드 후 바이너리를 artifact로 올려요.
- **macos-app** (macos-14, arm64): Rust 테스트 후 tauri-action으로 `.app`/DMG를 빌드하고 DMG를 `keyhaven-macos-arm64-dmg` artifact로 올려요.

### 서명 켜는 법
저장소 Settings → Secrets and variables → Actions에 `APPLE_CERTIFICATE`(base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`(앱 전용 암호), `APPLE_TEAM_ID`를 넣으면 다음 실행부터 서명·공증 단계가 자동으로 켜져요.
서명이 없을 때는 `src-tauri/tauri.unsigned.conf.json`으로 entitlements(keychain-access-groups)와 hardened runtime을 끄고 빌드해요. 이 경우 Touch ID용 키체인 접근 그룹이 없어서 생체 인증 저장이 제한될 수 있고, 첫 실행 시 macOS 경고가 떠요(우클릭 → 열기).
