# SecureVault 브라우저 자동 채우기 설치 안내 (v0.6.0, Mac)

성빈 님의 Mac mini와 MacBook에서 각각 아래 순서대로 한 번씩 진행합니다. 두 Mac의 순서는 같습니다.
모든 빌드는 개인용 테스트 빌드입니다. 웹 스토어, 공증(notarization), 배포는 하지 않습니다.

## 준비물 (GitHub Actions 아티팩트)

| 아티팩트 이름 | 내용 |
| --- | --- |
| `securevault-macos-arm64-dmg` | SecureVault 앱 DMG (`SecureVault_0.6.0_aarch64.dmg`) |
| `securevault-chrome-extension` | `securevault-chrome-extension-0.6.0.zip` (Chrome 압축해제 로드용) |
| `securevault-safari-extension` | `securevault-safari-extension-0.6.0.zip` (`SecureVault Safari.app`, ad-hoc 서명) |

> 현재 GitHub 결제 문제로 CI가 실행되지 않아 아티팩트가 아직 없습니다. 결제가 해결되면 main의 최신 실행에서 받습니다.

## 1. SecureVault 앱 설치

1. `SecureVault_0.6.0_aarch64.dmg`를 열고 `SecureVault.app`을 **응용 프로그램** 폴더로 끌어 놓습니다.
   - DMG 안에서 바로 실행한 상태로는 Chrome 호스트 설치가 거부됩니다. 반드시 응용 프로그램 폴더로 옮겨 주세요.
2. 서명/공증되지 않은 빌드라면 처음 한 번은 Finder에서 앱을 **Control-클릭 → 열기**로 실행합니다.
   (막히면 시스템 설정 → 개인정보 보호 및 보안 → "확인 없이 열기")
3. 앱에서 보관함 잠금을 해제합니다.

## 2. '브라우저 확장 연결' 켜기

1. SecureVault → 설정 화면의 **브라우저 확장 연결** 카드로 갑니다.
2. **브라우저 확장 연결** 체크박스를 켭니다. 기본값은 꺼짐입니다.
   - 켜면 `~/Library/Application Support/com.securevault.app/autofill/`에 소켓(0600)과 토큰(0600)이 만들어집니다.
   - 끄면 둘 다 지워집니다. 네트워크 포트는 열지 않습니다.
3. 상태가 "연결 대기 중"으로 바뀌는지 확인합니다.

## 3. Chrome 네이티브 호스트 설치

1. 같은 카드에서 **Chrome 호스트 설치**를 누릅니다.
2. `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.securevault.nmh.json`이 만들어지고, 상태가 "Chrome 호스트: 설치됨"이 됩니다.
3. 앱을 다른 위치로 옮기거나 업데이트했다면 **Chrome 호스트 다시 설치**를 한 번 더 누릅니다.

## 4. Chrome 확장 설치 (개발자 모드, 압축해제 로드)

1. `securevault-chrome-extension-0.6.0.zip`의 압축을 풉니다. 지우지 않을 위치에 두세요
   (예: `~/Applications/SecureVault/securevault-chrome-extension-0.6.0`). 폴더를 지우면 확장도 동작하지 않습니다.
2. Chrome 주소창에 `chrome://extensions`를 입력합니다.
3. 오른쪽 위 **개발자 모드**를 켭니다.
4. **압축해제된 확장 프로그램을 로드합니다**를 누르고, 압축을 푼 폴더(안에 `manifest.json`이 있는 폴더)를 고릅니다.
5. **ID 확인:** 카드에 보이는 ID가 정확히 `lldiolamhehhhjchiinofbnbeabnclcm`이어야 합니다.
   SecureVault 설정 카드에 표시된 확장 ID와도 같아야 합니다. 다르면 사용하지 말고 알려 주세요.
6. 퍼즐 아이콘에서 SecureVault를 고정해 두면 편합니다.

## 5. Safari 확장 설치

1. `securevault-safari-extension-0.6.0.zip`을 풀고 `SecureVault Safari.app`을 응용 프로그램 폴더로 옮깁니다.
2. 처음 한 번은 Control-클릭 → **열기**로 실행합니다. 안 열리면 터미널에서 아래를 실행합니다.
   `xattr -dr com.apple.quarantine "/Applications/SecureVault Safari.app"`
3. Safari 개발자 메뉴를 켭니다. Safari → 설정 → **고급** → "웹 개발자용 기능 보기"(이전 버전은 "메뉴 막대에서 개발자용 메뉴 보기")를 켭니다.
4. **서명되지 않은 확장 프로그램 허용**을 켭니다.
   - macOS 14 이상: Safari → 설정 → **개발자** 탭 → "서명되지 않은 확장 프로그램 허용"
   - 이전 버전: 메뉴 막대 **개발자용** → "서명되지 않은 확장 프로그램 허용"
   - 관리자 암호를 물어봅니다.
   - **주의:** 이 설정은 Safari를 종료할 때마다 꺼집니다. Safari를 다시 열면 매번 다시 켜야 확장이 나타납니다.
5. `SecureVault Safari.app`을 실행해 **Safari 확장 설정 열기**를 누르거나, Safari → 설정 → **확장 프로그램**으로 갑니다.
6. 목록에서 **SecureVault**를 체크해 켭니다.
7. 처음 사용할 때 Safari가 사이트 접근 허용을 물으면, 그 사이트에서만 허용(예: "하루 동안 허용" 또는 "항상 허용")을 고릅니다.

### 5-1. Safari 목록에 SecureVault가 안 보일 때: 내 Mac에서 Personal Team으로 서명해 빌드

CI 빌드는 ad-hoc 서명이라 Team ID가 없습니다. 위 단계를 다 했는데도 설정 > 확장 프로그램에 SecureVault가 없으면, Xcode가 있는 Mac에서 무료 Apple ID(Personal Team)로 직접 서명해 빌드합니다. 이 스크립트는 repo에 비밀 정보를 쓰지 않습니다. Team ID는 실행한 셸 안에서만 쓰입니다.

1. Xcode > Settings > Accounts에서 Apple ID를 추가합니다. Personal Team이 생기고 Apple Development 인증서가 만들어집니다.
2. `brew install xcodegen`
3. repo 루트에서 아래 명령을 실행합니다. `SV_TEAM_ID`를 생략하면 키체인의 Apple Development 인증서에서 Team ID를 읽습니다.
   ```
   SV_TEAM_ID=<10자리 팀 ID> bash scripts/build-safari-local.sh
   ```
4. 스크립트가 서명을 확인하고 `/Applications`에 설치한 뒤 앱을 한 번 실행합니다.
5. Safari를 Cmd+Q로 완전히 종료했다가 다시 엽니다. 설정 > 확장 프로그램에서 SecureVault를 켭니다. 개발 인증서로 서명했으므로 '서명되지 않은 확장 프로그램 허용'은 필요 없습니다.
6. 서명이나 프로파일이 만료되면 스크립트를 다시 실행합니다.

### 5-2. 진단 명령

아래 명령은 결과를 읽기만 하고 아무것도 바꾸지 않습니다.

```
A="/Applications/SecureVault Safari.app"; X="$A/Contents/PlugIns/SecureVaultSafariExtension.appex"
codesign -dvvv --entitlements - "$A"; codesign -dvvv --entitlements - "$X"   # Authority, TeamIdentifier, flags=runtime, entitlements
codesign --verify --deep --strict -vvv "$A"
spctl -a -vvv -t exec "$A"                                                    # ad-hoc이면 rejected가 정상(Gatekeeper)
pluginkit -mAvvv -p com.apple.Safari.web-extension                            # 경로, 버전, parent bundle, 활성(+/-) 표시
plutil -lint "$X/Contents/Info.plist" "$A/Contents/Info.plist"
plutil -lint "$X/Contents/Resources/manifest.json"                            # JSON 문법 확인
log stream --style compact --predicate 'process == "Safari" OR process CONTAINS "WebExtension" OR subsystem CONTAINS "Extension" OR eventMessage CONTAINS[c] "securevault"'
#   ↑ 실행해 둔 채 Safari 설정 > 확장 프로그램을 열고, 출력된 내용을 저장합니다.
defaults read com.apple.Safari ExtensionsEnabled 2>/dev/null                  # 0이면 확장 기능 전체가 꺼진 상태
```

## 6. 동작 확인

1. SecureVault 앱이 실행 중이고 잠금 해제 상태이며 '브라우저 확장 연결'이 켜져 있는지 확인합니다.
2. 보관함에 로그인 항목이 있는 사이트(예: `https://github.com/login`)를 엽니다.
3. 툴바의 SecureVault 아이콘을 누르면 같은 사이트 항목만 목록에 나옵니다. 항목을 누르면 아이디와 비밀번호가 채워집니다.
   - 하위 도메인 항목에는 "클릭해야 채웁니다" 표시가 붙고, 클릭해야만 채워집니다.
4. 단축키 ⌘⇧L은 정확히 일치하는 항목이 하나뿐일 때만 바로 채웁니다.
5. 앱을 잠그고 다시 아이콘을 누르면 "SecureVault가 잠겨 있습니다"만 보이고, 항목 이름도 보이지 않아야 합니다.
6. 연결을 끄거나 앱을 종료하면 "앱이 실행 중이 아니거나 '브라우저 확장 연결'이 꺼져 있습니다"가 보여야 합니다.
7. `http://` 페이지나 다른 사이트 안의 iframe에서는 채워지지 않아야 합니다.

## 7. 제거

1. SecureVault 설정에서 **브라우저 확장 연결**을 끕니다. 소켓과 토큰이 지워집니다.
2. Chrome: `chrome://extensions`에서 SecureVault를 **삭제**하고, 압축을 풀었던 폴더를 지웁니다.
3. Chrome 호스트 파일을 지웁니다.
   `rm ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.securevault.nmh.json`
4. Safari: 설정 → 확장 프로그램에서 SecureVault를 끈 뒤, `SecureVault Safari.app`을 휴지통으로 옮깁니다.
5. (선택) `~/Library/Application Support/com.securevault.app/autofill/` 폴더를 지웁니다. 보관함 파일은 건드리지 않습니다.

## 알려진 한계

- **개인용 빌드라 매번 손이 갑니다:** Safari의 "서명되지 않은 확장 프로그램 허용"은 Safari를 재시작할 때마다 꺼집니다. Chrome도 개발자 모드 경고가 뜰 수 있습니다.
- **Chrome ID는 이 공개키로만 고정:** 개인키는 만들자마자 지워서 아무도 갖고 있지 않습니다. 그래서 이 ID로 웹 스토어에 올릴 수는 없고, 압축해제 로드 전용입니다.
- **다른 출처의 iframe:** activeTab 권한으로는 다른 출처 iframe 안을 읽을 수 없어서, 그런 로그인 창은 채우지 못합니다. 같은 사이트 iframe은 앱이 판단해서 허용합니다.
- **Safari 샌드박스 예외:** Safari 확장은 샌드박스 안에서 돌아야 합니다. App Group은 Apple Team ID가 필요해서, 대신 `~/Library/Application Support/com.securevault.app/autofill/` 한 폴더에만 접근하는 임시 예외 entitlement를 씁니다. 앱스토어 배포에는 쓸 수 없는 방식입니다.
- **Safari 출처 식별:** Safari 확장의 출처는 설치마다 바뀌는 UUID라서, 앱은 Safari 쪽을 고정 출처 `safari-web-extension://com.securevault.safari.extension/`와 토큰으로 식별합니다. 같은 사용자 계정에서 토큰 파일(0600)을 읽을 수 있는 프로그램은 Chrome 경로와 마찬가지로 신뢰 범위 안에 있습니다.
- **비밀번호는 메모리에 잠시 남습니다:** 브라우저 JS와 Swift 문자열은 확실히 지울 수 없어서, 채우는 순간 확장과 Safari 핸들러 메모리에 잠시 남습니다. 로그로는 남기지 않습니다.
- **Mac 전용:** Chrome은 Mac용 설치 경로만 다룹니다. iOS 자동 채우기는 이번 범위에 없습니다.
- **아이콘 없음:** 확장 아이콘은 아직 브라우저 기본 아이콘으로 보입니다.
- **검증 상태:** 결제 문제로 CI가 막혀 있어 macOS 빌드, DMG, Safari 앱 빌드와 실제 브라우저 동작은 아직 확인하지 못했습니다.
