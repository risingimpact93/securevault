# SecureVault 자동 채우기(AutoFill) 설계 계획

- 상태: 설계 문서 (코드 변경 없음). 기준 코드: `cfdc987` (0.5.2)
- 작성: 2026-10-27 (KST)
- 표기: **[확실]** = 아래 링크의 공식 문서로 확인함. **[추정]** = 공식 문서로 확인하지 못했으며 근거를 함께 적음.

---

## 0. 요약 (Executive summary)

| 항목 | 무료 Apple ID(Personal Team)로 | $99 Apple Developer Program 필요 |
|---|---|---|
| Mac **Chrome 확장** + 네이티브 메시징 호스트 | **가능** (개발자 모드 "압축해제된 확장 프로그램 로드") | 불필요 (Chrome 웹 스토어 배포는 별도 계정 문제) |
| Mac **Safari 웹 확장** | **개발용으로만 가능**: "Allow unsigned extensions"를 Safari 실행마다 다시 켜야 함 | 상시 사용·배포하려면 서명 필요 [추정, 아래 3장] |
| iOS **AutoFill Credential Provider 확장** (QuickType 막대, 암호 목록) | **불가**: 엔타이틀먼트가 무료 계정에 없음 | **필요** |
| macOS 시스템 AutoFill Credential Provider | **불가** (같은 엔타이틀먼트) | **필요** |
| App Groups / Keychain sharing | 가능 (무료 계정 지원 목록에 있음) | – |
| iCloud(Documents/CloudKit) capability | 불가 | 필요. 단 SecureVault는 이 capability를 쓰지 않음(문서 선택기+보안 범위 북마크 방식) |
| 패스키 | 후순위 (Credential Provider 위에서만 의미 있음) | 필요 |

**권장 순서**

1. **1단계: 공통 코어.** `securevault-core`에 "자동 채우기 조회 API"와 PSL 기반 사이트 매칭(피싱 방어)을 먼저 만든다. 모든 경로가 공유하고 단위 테스트가 쉽다.
2. **2단계: Mac Chrome 확장 + 네이티브 메시징 호스트.** 무료 계정으로 바로 쓸 수 있고, 외부 노출 없이(stdio + 앱 내부 Unix 소켓) 구현할 수 있다.
3. **3단계: Mac Safari 웹 확장.** 2단계의 JS를 재사용한다. 무료 계정에서는 개발 모드로만 쓸 수 있다.
4. **4단계: iOS Credential Provider 확장.** $99 가입 후 진행한다. 메모리 제한(Argon2 64MiB) 때문에 Face ID로 잠금을 푸는 설계를 먼저 검증한다.
5. **5단계 (선택): 패스키, macOS 시스템 AutoFill provider.**

**핵심 위험**: 피싱(유사 도메인), 가짜 네이티브 호스트나 악성 확장, 클립보드, 메모리 잔존, 잠금 시간 처리, 로그 유출. 대응은 5장에 정리했다.

---

## 1. 현재 구조에서 출발점

코드에서 확인한 사실:

- **앱 구조**: Tauri 2 앱(`src-tauri`)과 공유 Rust 코어(`crates/securevault-core`), React UI. iOS는 같은 앱에 `crates/securevault-ios`(Swift `VaultAccessPlugin`)를 붙인다.
- **금고 파일**: `vault.khv`. 키는 마스터 비밀번호와 **Secret Key**를 Argon2id(**m = 64 MiB**, `vault.rs`의 `KDF_M = 65536`)로 유도하고, 암호화는 XChaCha20-Poly1305이다.
- **Secret Key 보관**: `secret_key_store.rs` 참고.
  - macOS: 로그인 키체인(generic password, iCloud 동기화 안 함, access group 없음. 무료/비서명 빌드에서도 동작하게 하려는 선택).
  - iOS: data-protection 키체인, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- **생체 인증**: `src-tauri/src/platform.rs`가 이미 `LAContext`와 `SecAccessControl`로 Face ID/Touch ID 잠금 해제를 구현하고 있다.
- **iOS 금고 위치**: iCloud Drive의 `vault.khv`는 **문서 선택기 + 보안 범위 북마크**로 접근한다(`VaultAccessPlugin.swift`의 `resolve`, `ensureDownloaded`). iCloud capability(엔타이틀먼트)는 쓰지 않는다.
- **네트워크 노출 선례**: MCP 서버는 이미 `mcp::bind_loopback`으로 **127.0.0.1에만** 바인딩한다. 자동 채우기에서는 이것조차 피한다(2.3절).
- **기존 보안 동작**: 클립보드 복사는 30초 뒤 지운다. 자동 잠금 시간은 금고 설정(`autoLockMinutes`)에 있다.

설계 원칙: **비밀번호 복호화와 매칭 판단은 항상 Rust 코어(앱 프로세스) 안에서 한다.** 확장(JS)은 "이 페이지에 무엇을 채울지" 요청하고, 결과만 받아 입력란에 넣는다. 확장 쪽 저장소(`chrome.storage` 등)에는 비밀 값을 저장하지 않는다.

### 1.1 코어에 추가할 API (1단계)

```text
securevault_core::autofill
  match_site(page_url, entry_url) -> MatchLevel { Exact, SameSite, None }
  candidates(vault, page_url, frame_info) -> Vec<CandidateMeta>   // 제목, 사용자 이름, 항목 id (비밀번호 없음)
  reveal(vault, item_id, page_url) -> Credential                   // 매칭을 다시 검사한 뒤에만 비밀번호 반환
```

- `reveal`은 **매칭을 다시 검사한다.** 확장이 보낸 item_id만 믿지 않는다.
- PSL은 빌드할 때 `public_suffix_list.dat`를 고정 버전으로 포함한다. 런타임에 내려받지 않는다(외부 요청 없음).

---

## 2. Mac 브라우저 확장 (Chrome, Safari)

### 2.1 로그인 필드 찾기와 값 채우기 (Chrome·Safari 공통 content script)

- `input[type=password]`를 기준으로 같은 `form`(또는 가장 가까운 공통 조상) 안에서 사용자 이름 후보를 찾는다.
  - 우선순위: `autocomplete="username"` → `type=email` → name/id에 user·login·email·id가 들어간 `type=text` → 비밀번호 칸 바로 앞의 텍스트 입력.
- 비밀번호 칸이 다음 화면에 나오는 2단계 로그인(사용자 이름 먼저)도 지원한다. `autocomplete="username"`만 있는 페이지는 사용자 이름만 채운다.
- 채우는 방법: 값 설정은 네이티브 setter(`HTMLInputElement.prototype.value`의 setter)로 하고, 그 뒤 `input`·`change` 이벤트를 보낸다. React 같은 프레임워크 대응이다.
- **사용자 동작이 있어야 채운다.** 툴바 버튼, 입력란 옆 아이콘 클릭, 단축키가 있어야 하고, 페이지가 열리자마자 자동으로 채우지 않는다. 숨겨진 필드 수집 공격에 대한 대비다.
- **숨김·투명 입력란(크기 0, `opacity:0`, 화면 밖)에는 채우지 않는다.**
- [추정] Shadow DOM과 iframe 대응은 2.4절의 정책 범위 안에서만 한다.

### 2.2 Chrome: 네이티브 메시징 [확실]

공식 문서: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging

- **동작 방식**: 확장이 `runtime.connectNative()`나 `sendNativeMessage()`를 호출하면 Chrome이 호스트 프로세스를 **별도로 실행**하고 **stdin/stdout**으로 통신한다.
- **메시지 형식**: 32비트 길이(네이티브 바이트 순서) + UTF-8 JSON. 호스트 → Chrome은 최대 1 MB, Chrome → 호스트는 최대 64 MiB.
- **매니페스트 필드**: `name`, `description`, `path`, `type`(`stdio`만 가능), `allowed_origins`.
  - `path`는 macOS에서 **절대 경로**여야 한다.
  - `allowed_origins`에는 **와일드카드를 쓸 수 없다**(확장 ID를 정확히 적어야 함).
- **매니페스트 위치 (macOS)**
  - 사용자별: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<name>.json`
  - 시스템 전체: `/Library/Google/Chrome/NativeMessagingHosts/<name>.json`
  - Chromium은 `~/Library/Application Support/Chromium/NativeMessagingHosts/`
- **호출 위치 제한**: content script에서는 직접 호출할 수 없고 서비스 워커나 확장 페이지에서만 가능하다. 문서는 서비스 워커가 `sender.origin`/`sender.url`을 **검증**하라고 권고한다.
- **호출자 확인**: 호스트의 첫 번째 인수로 호출자 origin(`chrome-extension://<ID>/`)이 전달된다.

**SecureVault 설계**

- 호스트 이름은 `com.securevault.nmh`, 바이너리는 앱 번들의 `SecureVault.app/Contents/MacOS/securevault-nmh`(작은 Rust 바이너리)로 한다.
- 매니페스트는 **사용자별 경로**에만 설치하고, 앱 설정의 "브라우저 연동 켜기"로 생성·삭제한다(관리자 권한 불필요).
- `allowed_origins`에는 개발 모드 확장 ID 하나만 넣는다. unpacked 확장의 ID가 매번 바뀌지 않도록 `manifest.json`에 `key`를 고정하는 방법은 [추정, 일반적인 개발 관행].
- **호스트 → 실행 중인 앱**: 앱 데이터 폴더 안의 **Unix 도메인 소켓**(권한 0600)을 쓴다.
  - 연결할 때 `getpeereid`로 같은 UID인지 확인하고, 앱이 생성한 무작위 토큰으로 상호 확인한다.
  - 토큰은 매니페스트 등록 때 호스트만 읽을 수 있는 파일에 둔다.
  - [추정] 호스트 바이너리의 코드 서명을 확인하는 방법은 무료 계정에서 Team ID가 없어 약하다. 그래서 UID·경로·토큰 확인을 기본으로 한다.
- 호스트는 상태를 두지 않는 중계자다. **비밀번호를 디스크에 쓰지 않고 로그도 남기지 않는다.**

### 2.3 localhost(HTTP/WebSocket) 방식을 피하는 이유

- 127.0.0.1에 포트를 열면 **같은 기기의 모든 프로세스와 모든 웹 페이지**가 접근을 시도할 수 있다. 웹 페이지에서는 DNS rebinding이나 `fetch`로 로컬 포트를 탐색할 수 있다. 접근을 막으려면 Origin 검사, 토큰, CSRF 대비가 모두 필요하고, 실수 한 번이 곧 비밀번호 유출이 된다.
- 프로젝트 원칙인 "외부 노출 금지"에도 맞지 않는다. MCP의 loopback 서버는 사용자가 명시적으로 켜고 매번 승인하는 별도 기능이고, 자동 채우기에 재사용하지 않는다.
- 반면 네이티브 메시징은 포트를 열지 않는다. **Chrome이 매니페스트의 `allowed_origins`로 확인한 확장만** 호스트를 실행할 수 있다 [확실, 위 문서].

### 2.4 Safari 웹 확장 [확실]

- **구조**: Safari 웹 확장은 ① macOS/iOS 앱, ② 브라우저에서 도는 JS, ③ 둘을 중계하는 **네이티브 앱 확장**의 세 부분으로 이뤄진다. 데이터 공유는 **App Groups**로 한다.
  - https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension.md
- **메시징**: `nativeMessaging` 권한을 선언하고 background/확장 페이지에서 `browser.runtime.sendNativeMessage`를 호출한다(content script에서는 불가). Safari는 application.id를 무시하고 **포함 앱(containing app)의 네이티브 확장으로만** 보낸다. 네이티브 쪽은 `beginRequest(with:)`에서 받는다.
- **SecureVault 설계**
  - Tauri 앱을 containing app으로 쓰는 Xcode 타깃이 필요하다. Tauri macOS 번들에 appex를 끼워 넣는 방법은 [추정: Tauri가 기본으로 지원하지 않아 빌드 후 단계에서 `Contents/PlugIns`에 넣고 다시 서명해야 할 가능성이 높음].
  - 네이티브 확장 → 앱 통신은 2.2절과 같은 Unix 소켓을 App Group 컨테이너에 둔다. [추정] 샌드박스된 appex는 App Group 컨테이너 밖의 소켓에 접근하기 어렵기 때문이다.
  - JS(content script, 매칭 UI)는 Chrome과 공유한다(WebExtension 표준).

### 2.5 잠금 상태에서의 동작

- 잠겨 있으면 호스트/네이티브 확장은 `{"state":"locked"}`만 돌려준다. **항목 메타데이터(제목, 사용자 이름)도 주지 않는다.**
- 확장 팝업에는 "SecureVault에서 잠금 해제" 버튼만 둔다. 누르면 앱을 앞으로 띄우고 앱이 Touch ID 또는 마스터 비밀번호를 받는다. **확장 안에서 마스터 비밀번호를 입력받지 않는다**(웹 페이지와 같은 프로세스에 비밀을 두지 않기 위함).
- 앱의 자동 잠금(`autoLockMinutes`)이 되면 소켓 세션도 즉시 무효화한다.

### 2.6 피싱 방어: 사이트 매칭 정책

- **PSL로 등록 가능 도메인(eTLD+1)을 계산한다.** 예: `a.example.co.uk` → `example.co.uk`. https://publicsuffix.org/ , 형식: https://github.com/publicsuffix/list/wiki/Format
- **제안 조건**:
  1. 페이지가 **https**일 것. http 페이지에는 제안하지 않는다(로컬 개발 주소 예외도 두지 않음).
  2. 항목 URL과 페이지의 **eTLD+1이 같을 것**.
  3. 정확한 origin(스킴+호스트+포트)이 같으면 우선 표시한다. eTLD+1만 같은 서브도메인이면 "다른 서브도메인" 표시를 붙여 **사용자가 클릭해야** 채운다.
  4. 항목별 "정확한 호스트만" 옵션을 둔다. `*.github.io`처럼 PSL private 섹션에 있는 도메인은 PSL 덕분에 자동으로 분리된다.
- **iframe**: 최상위 프레임과 같은 eTLD+1인 프레임에만 채운다. 교차 사이트 iframe에는 기본적으로 채우지 않는다(clickjacking·삽입 위젯 대비).
- **사용자 표시**: 유사 도메인(IDN 호모그래프) 대비로 퓨니코드(`xn--`) 도메인은 퓨니코드 그대로 보여 준다.
- **재검사**: 매칭 판단은 `reveal` 시점에 코어가 다시 한다(1.1절). 확장이 보낸 URL은 브라우저가 주는 탭 URL(`sender.tab.url`/`sender.url`)로 교차 확인한다.

---

## 3. iOS AutoFill Credential Provider 확장

### 3.1 QuickType 막대 (ASCredentialIdentityStore) [확실]

- 앱이 `ASCredentialIdentityStore.shared`에 `ASPasswordCredentialIdentity`(서비스 식별자=도메인/URL, 사용자 이름, recordIdentifier)를 저장하면 QuickType 막대에 바로 제안이 나온다.
- 비밀번호는 저장하지 않고 **메타데이터만** 저장한다.
- 증분 갱신(`saveCredentialIdentities`/`removeCredentialIdentities`)을 쓰고, 저장 전에 `getState`로 활성화 여부를 확인한다.
- 사용자가 확장을 끄면 시스템이 저장소를 비운다.
- 문서:
  - https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore/savecredentialidentities(_:completion:)-1bbx6
  - https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web (메타데이터에는 웹사이트와 사용자 이름이 들어가고 비밀번호는 들어가지 않으며, 앱 삭제 시 함께 지워짐)
- SecureVault 설계: 금고를 저장하거나 잠금 해제할 때 앱이 `recordIdentifier = 항목 id`로 동기화한다. 사용자 이름 노출이 싫은 사용자를 위해 "QuickType에 사용자 이름 표시" 설정(끄면 identity를 등록하지 않음)을 둔다.

### 3.2 확장 UI (ASCredentialProviderViewController) [확실]

- 확장 타깃이 `ASCredentialProviderViewController`를 상속하고, **확장과 containing app 둘 다에 AutoFill Credential Provider 엔타이틀먼트**를 넣는다.
  - https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider
- 오버라이드할 메서드:
  - `prepareCredentialList(for:)`: 목록 화면
  - `provideCredentialWithoutUserInteraction(for:)`: QuickType에서 바로 채우기. 잠겨 있으면 `ASExtensionError.userInteractionRequired`로 취소한다.
  - `prepareInterfaceToProvideCredential(for:)`: 잠금 해제 화면
  - `prepareInterfaceForExtensionConfiguration()`: 설정에서 켤 때 처음 동기화
  - 최신 SDK에는 `requestParameters`를 받는 변형과 패스키 메서드도 있다.
- 결과는 `extensionContext.completeRequest(withSelectedCredential:)`로 돌려준다.
- 확장 UI는 Tauri 웹뷰가 아니라 **SwiftUI/UIKit 네이티브**로 작게 만든다(메모리, 3.4절).

### 3.3 앱과 데이터 공유

- **App Group 컨테이너** [확실: 무료/유료 모두 capability 지원, https://developer.apple.com/help/account/reference/supported-capabilities-ios].
  - 확장은 별도 프로세스·별도 샌드박스라서 앱 컨테이너를 직접 읽을 수 없다.
  - 그래서 앱이 **`vault.khv`의 암호화된 사본(스냅샷)** 을 App Group 컨테이너에 쓴다. 금고 형식은 그대로이고 평문은 저장하지 않는다.
- **키체인 access group** [확실: Keychain sharing capability, https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps].
  - 확장이 같은 키체인 항목을 읽으려면 `kSecAttrAccessGroup = <TeamID>.com.securevault.shared`처럼 공유 그룹을 지정해야 한다.
  - 지금 iOS Secret Key는 기본 그룹에 있으므로 **공유 그룹으로 옮기는 마이그레이션**이 필요하다. 기존 항목을 읽어 새 그룹에 쓴 뒤 검증하고, 그다음에 기존 항목을 삭제한다.
- **iCloud 금고 파일을 확장에서 직접 여는 방식은 권장하지 않는다.** [추정] 보안 범위 북마크는 앱 프로세스가 만든 것이다. 확장에서 이를 해석하고 iCloud 다운로드(`ensureDownloaded`)까지 기다리면 실패하거나 시간 초과가 나기 쉽다. 시간과 메모리 제약이 있는 확장에서는 App Group 스냅샷을 읽고, 스냅샷이 오래됐으면 "앱을 열어 동기화" 안내를 띄운다.

### 3.4 확장 메모리 제한과 Argon2

- [추정] Credential Provider 확장의 메모리 한도는 **약 120 MB**로 알려져 있다. 공식 문서로는 확인하지 못했고, KeePassium 문서(https://support.keepassium.com/kb/autofill-memory/)와 Bitwarden 이슈(https://github.com/bitwarden/mobile/issues/2389)에서 Argon2 메모리 때문에 확장이 종료된 사례가 보고되어 있다.
- SecureVault의 KDF는 **64 MiB**라서 확장 안에서 마스터 비밀번호로 잠금을 풀면 한도에 가까워진다. 따라서:
  - **기본 경로는 Face ID**: 앱이 금고를 잠금 해제할 때 KDF 결과 키(vault key)를 **생체 ACL 키체인 항목**(공유 access group, `ThisDeviceOnly`, `.biometryCurrentSet`)에 저장한다. 확장은 Face ID로 이 키를 꺼내 스냅샷을 **KDF 없이** 복호화한다.
  - 마스터 비밀번호 경로는 대비책으로 둔다. 확장에서 KDF를 실행하기 전에 남은 메모리를 확인하고(`os_proc_available_memory`, [추정]), 부족하면 "앱에서 잠금 해제" 안내를 띄운다.
  - KDF 파라미터는 바꾸지 않는다(금고 형식·호환성 유지).
- 생체 ACL [확실]:
  - https://developer.apple.com/documentation/LocalAuthentication/accessing-keychain-items-with-face-id-or-touch-id
  - https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
  - `biometryCurrentSet`은 지문/얼굴 등록이 바뀌면 항목이 무효화된다. 그러면 마스터 비밀번호로 다시 등록한다.

### 3.5 Secret Key 저장과 접근

- Secret Key는 지금처럼 키체인에만 둔다(`ThisDeviceOnly`, 동기화 안 함). 공유 access group으로 옮겨 확장도 읽을 수 있게 한다.
- 위의 Face ID 경로를 쓰면 확장은 **Secret Key와 마스터 비밀번호 없이** vault key만으로 복호화한다. Secret Key가 확장에 노출되는 일은 마스터 비밀번호 대비책 경로에서만 생긴다.
- vault key 항목은 앱이 잠기거나 자동 잠금 정책상 무효화해야 할 때 지우지 않는다. 대신 확장에서 쓸 때마다 Face ID가 필요하다(ACL). 설정에서 "자동 채우기에 Face ID 사용"을 끄면 삭제한다.

### 3.6 패스키 (후순위)

- 같은 `ASCredentialProviderViewController`에 패스키 메서드(`prepareInterface(forPasskeyRegistration:)`, `ASPasskeyCredentialIdentity` 등)가 있다 [확실, 3.2절 문서의 메서드 목록].
- 금고 형식에 새 항목 유형(개인키, rpId, userHandle)이 필요하다. **형식 변경을 동반하므로 별도 설계와 승인이 필요하며 이번 계획 범위 밖이다.**

---

## 4. 서명·계정 제약

| 항목 | 무료 Apple ID (Personal Team) | $99 Program | 근거 |
|---|---|---|---|
| 기기 설치 기간 | 프로비저닝 7일, 만료 후 재빌드/재설치. 앱 ID 10개, 기기 3대, 기기당 앱 3개 | 1년 인증서 | [확실] https://developer.apple.com/help/account/basics/about-your-developer-account/ |
| AutoFill Credential Provider (iOS/macOS) | **불가** | 가능 | [확실] https://developer.apple.com/help/account/reference/supported-capabilities-ios (macOS 표도 같음: https://developer.apple.com/help/account/reference/supported-capabilities-macos) |
| App Groups | 가능 | 가능 | [확실] 위 표 |
| Keychain sharing | 가능 | 가능 | [확실] 위 표 |
| iCloud (Documents / CloudKit / KVS) capability | 불가 | 가능 | [확실] 위 표. SecureVault는 문서 선택기+북마크라 영향 없음 |
| Associated Domains (앱↔웹 자격 연결) | 불가 | 가능 | [확실] 위 표 |
| App Store/TestFlight 배포 | 불가 | 가능 | [확실] https://developer.apple.com/library/archive/qa/qa1915/_index.html |
| Safari 웹 확장 개발·실행 | 가능하지만 **"Allow unsigned extensions"가 Safari 종료 때마다 초기화**되어 매번 다시 켜야 함. "Sign to Run Locally"로 빌드 | 개발 인증서로 서명하면 이 설정 없이 표시 | [확실] https://developer.apple.com/videos/play/wwdc2020/10665/ (ad-hoc 서명 앱의 확장은 기본적으로 표시되지 않음), https://developer.apple.com/videos/play/wwdc2026/216/ |
| Safari 확장의 상시 사용(다른 Mac 배포) | 불가 | Developer ID 공증 또는 App Store | [추정] Safari가 ad-hoc 서명 확장을 기본 무시하므로(위 문서) 일반 사용에는 정식 서명이 필요하다고 판단 |
| Chrome 확장 개발 모드 설치 | 가능: `chrome://extensions` → 개발자 모드 → "압축해제된 확장 프로그램을 로드합니다" | 무관 | [확실] https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world |
| Chrome 네이티브 메시징 호스트 등록 | 가능: 사용자 경로에 JSON 매니페스트를 쓰면 됨 | 무관 | [확실] https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging |
| 네이티브 호스트 바이너리 서명 | ad-hoc 서명으로 동작 | Developer ID 서명 시 출처 검증 강화 | [추정] Chrome 문서에는 서명 요구가 없음. Gatekeeper는 로컬에서 빌드한 바이너리를 격리하지 않음 |

**결론**: 무료 계정만으로 쓸 수 있는 자동 채우기는 **Mac Chrome**과 **Mac Safari(개발 모드, 매번 설정)** 뿐이다. **iPhone 자동 채우기는 $99 가입이 반드시 필요하다.**

---

## 5. 보안 위험과 대응

| 위험 | 대응 |
|---|---|
| **피싱/유사 도메인** | https + PSL eTLD+1 일치, 정확한 origin 우선, 서브도메인 일치는 클릭 확인, 교차 사이트 iframe 금지, 퓨니코드 표시, `reveal` 시점 재검사 (2.6절) |
| **악성 확장이 호스트를 호출** | `allowed_origins`에 SecureVault 확장 ID만 등록(와일드카드 불가). 호스트가 첫 번째 인수(호출자 origin)를 재확인 |
| **가짜 네이티브 호스트/소켓 가로채기** | 소켓을 앱 데이터 폴더에 0600으로 생성, `getpeereid`로 UID 확인, 등록 때 만든 무작위 토큰으로 상호 확인. 소켓 경로를 외부에서 지정할 수 없게 함. 매니페스트가 다른 바이너리를 가리키면 앱이 경고하고 다시 등록 |
| **localhost 노출** | 사용하지 않음 (2.3절) |
| **클립보드** | 자동 채우기는 클립보드를 쓰지 않음(직접 입력). 복사 대비책을 쓸 때는 기존과 같이 30초 후 지우고, iOS에서는 `UIPasteboard`의 localOnly·만료 옵션 사용 [추정] |
| **메모리 잔존** | 평문 비밀번호는 Rust `zeroize`, 요청 단위로 짧게만 유지. JS에서는 채운 뒤 변수를 즉시 버림(GC 특성상 완전 제거는 불가, [추정]). 확장 저장소·IndexedDB에 비밀 저장 금지 |
| **잠금 시간** | 앱의 자동 잠금이 확장 세션에도 적용됨. 잠긴 상태에서는 메타데이터도 주지 않음. iOS 확장은 매 요청 Face ID |
| **로그** | 호스트·확장·appex에서 URL 전체·사용자 이름·비밀번호를 로그에 남기지 않음. 오류 코드만 기록. 개발 빌드도 동일 |
| **content script 공격면** | 페이지 JS와 같은 렌더러에 있으므로 서비스 워커에서 `sender` 검증. 페이지가 보낸 메시지는 무시. 사용자 동작이 있어야 채움 |
| **스냅샷 유출(iOS)** | App Group의 스냅샷은 원본과 같은 암호화 형식이며, 파일 보호 클래스 `complete` 적용 [추정] |

---

## 6. 단계별 로드맵과 대략 공수

| 단계 | 내용 | 먼저 하는 이유 | 공수(1인 기준, 대략) |
|---|---|---|---|
| 1 | 코어 `autofill` 모듈: PSL 매칭, 후보, `reveal` 재검사, 단위 테스트 | 모든 플랫폼이 공유하고 피싱 방어의 핵심. 외부 의존·계정 없이 CI로 검증 가능 | 3–5일 |
| 2 | Mac Chrome 확장(MV3) + `securevault-nmh` + Unix 소켓 + 앱 설정 "브라우저 연동" | 무료 계정으로 즉시 사용 가능, 포트 노출 없음 | 1.5–2주 |
| 3 | Mac Safari 웹 확장(같은 JS) + containing app 패키징 | 2단계 재사용. 무료 계정에서는 개발 모드만 가능 | 1–1.5주 (Tauri 번들에 appex 넣는 작업이 변수) |
| 4 | ($99 가입 후) iOS Credential Provider: App Group 스냅샷, 공유 키체인 마이그레이션, Face ID vault key, QuickType 동기화, 네이티브 목록 UI | iPhone 사용 경험의 핵심이지만 유료 계정과 메모리 검증이 선행 조건 | 2–3주 |
| 5 (선택) | 패스키, macOS 시스템 AutoFill provider, Chrome 웹 스토어/공증 배포 | 금고 형식 변경이나 배포 정책 결정 필요 | 각 1–3주 |

**검증 항목 (단계별)**

- 1단계: 코어 테스트(PSL 예: `co.uk`, `github.io`, IDN, http 거부, iframe 정책).
- 2·3단계: 실제 Mac에서 주요 로그인 페이지 수동 테스트, 잠금 상태 응답, 다른 확장 ID로 호출했을 때 거부되는지.
- 4단계: 실기기에서 메모리 측정(Instruments), Face ID 등록 변경 후 동작, 오프라인 스냅샷.

---

## 7. 참고 문서 (이 문서 작성 시 확인한 공식 링크)

- Chrome Native messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Chrome 확장 시작(압축해제 로드): https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world
- Safari 웹 확장 메시징: https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension.md
- WWDC20 Meet Safari Web Extensions: https://developer.apple.com/videos/play/wwdc2020/10665/
- WWDC26 Create web extensions for Safari: https://developer.apple.com/videos/play/wwdc2026/216/
- AutoFill Credential Provider 엔타이틀먼트: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider
- ASCredentialIdentityStore.saveCredentialIdentities: https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore/savecredentialidentities(_:completion:)-1bbx6
- Apple Platform Security, Credential provider extensions: https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web
- 지원 capability (iOS): https://developer.apple.com/help/account/reference/supported-capabilities-ios
- 지원 capability (macOS): https://developer.apple.com/help/account/reference/supported-capabilities-macos
- 개발자 계정/Personal Team: https://developer.apple.com/help/account/basics/about-your-developer-account/
- QA1915 Personal Team 제약: https://developer.apple.com/library/archive/qa/qa1915/_index.html
- 키체인 공유: https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
- Face ID/Touch ID 키체인: https://developer.apple.com/documentation/LocalAuthentication/accessing-keychain-items-with-face-id-or-touch-id
- SecAccessControlCreateFlags: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
- Public Suffix List: https://publicsuffix.org/ , 형식 https://github.com/publicsuffix/list/wiki/Format
- (비공식, 메모리 한도 추정 근거) https://support.keepassium.com/kb/autofill-memory/ , https://github.com/bitwarden/mobile/issues/2389

## 3단계 결정: Safari는 별도 소형 containing app (2026-10-27)

- **선택:** `SecureVault Safari.app` (xcodegen + xcodebuild, ad-hoc 서명)에 `.appex`를 담습니다. 메인 Tauri 앱 번들에는 넣지 않습니다.
- **이유:**
  - Safari 웹 확장 appex는 반드시 샌드박스를 켜야 하고, containing app의 번들에 Xcode 타깃으로 서명되어 들어가야 합니다. Tauri 번들러는 appex 타깃을 만들지 못하므로, 메인 앱에 넣으려면 서명 후처리가 필요하고 기존 DMG/공증 파이프라인이 깨질 위험이 있습니다.
  - 메인 앱은 샌드박스 없이 그대로 두고(기존 화면, vault.khv, 경로 변경 없음), Safari 쪽만 독립적으로 빌드하고 지울 수 있습니다.
- **샌드박스와 소켓:**
  - App Group 컨테이너는 Team ID가 필요해 ad-hoc 서명으로는 쓸 수 없습니다. 메인 앱의 소켓 경로를 옮기지도 않았습니다.
  - 그래서 appex에 `temporary-exception.files.home-relative-path.read-write` 하나만 주어, `~/Library/Application Support/com.securevault.app/autofill/`에만 접근합니다. 네트워크 entitlement는 없습니다.
- **네이티브 핸들러:** `AutofillRelay.swift`가 Chrome 호스트와 같은 규칙을 따릅니다.
  - 허용 키만 전달하고, 토큰은 0600이면서 소유자가 본인인 파일만 읽고, `getpeereid`로 상대 UID를 확인합니다.
  - 64 KiB 상한, 10초 타임아웃, 로그 없음.
  - caller origin은 고정값 `safari-web-extension://com.securevault.safari.extension/`이고, 앱 게이트가 이 값과 Chrome ID 두 개만 허용합니다.
- **JS 공유:** Chrome의 `background.js`, `popup.*`, `lib/`를 그대로 복사하고, manifest만 `scripts/safari-manifest.mjs`로 변환합니다(`key` 제거, Safari 16.4 이상).
