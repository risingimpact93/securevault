# iOS Face ID 잠금 해제 (v0.6.1)

iPhone 앱에서만 동작합니다. Mac 앱의 Touch ID, 웹 패스키, Linux 동작은 그대로입니다.

## 무엇을 저장하는가

Face ID 키체인에는 **2SKD로 만든 금고 열기 키**(32바이트)만 넣습니다.

- 마스터 비밀번호를 Argon2id로 돌린 뒤, Secret Key가 켜져 있으면 HKDF(2SKD)를 한 값이 금고 암호문을 엽니다. 이 값이 `UnlockedVault.key`이고, 비밀번호로 연 직후 `export_unlock_key()`로 꺼냅니다.
- **마스터 비밀번호 원문과 Secret Key 원문은 키체인에 넣지 않습니다.** Secret Key는 기존처럼 이 기기 Secret Key 저장소에만 있습니다.
- 금고 파일(`.khv`) 형식은 바꾸지 않습니다. Face ID 켜짐 여부·부팅 시각·마지막 비밀번호 시각은 앱 데이터 `face-id.json`에 있습니다. 금고 설정(`biometricsEnabled`)을 쓰지 않으므로 iCloud로 Mac에 동기화돼도 Mac Touch ID가 켜지지 않습니다.

비밀번호로 연 키를 저장하는 이유: Face ID로 열 때 Argon2를 다시 돌릴 필요가 없고, 비밀번호가 키체인에 남지 않습니다. 생체 정보가 바뀌면(`biometryCurrentSet`) 항목이 무효가 되어 비밀번호가 다시 필요합니다.

## 키체인 속성

| 속성 | 값 |
|---|---|
| class | `kSecClassGenericPassword` |
| service | `com.securevault.app.biometric` |
| account | `unlock-key` |
| accessible | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` |
| access control | `SecAccessControlCreateWithFlags(.biometryCurrentSet)` |
| synchronizable | `false` (iCloud 키체인 없음) |
| access group | 없음 (Personal Team, 유료 entitlement 없음) |

프롬프트 문구는 `NSFaceIDUsageDescription` / `localizedReason`: 「SecureVault 금고를 Face ID로 잠금 해제합니다.」 대체 버튼 제목은 「마스터 비밀번호 사용」입니다.

## 다시 인증 정책

정책은 `crates/securevault-core/src/biometric_policy.rs`에 있고 플랫폼과 무관합니다.

Face ID로 열 수 있는 경우:

- 토글이 켜져 있고
- 키체인 항목이 있으며
- 기록한 `kern.boottime`이 현재와 같고
- 마지막 **마스터 비밀번호** 잠금 해제 후 7일이 지나지 않았을 때

그 외에는 마스터 비밀번호가 필요합니다.

| 이유 | 화면 문구 |
|---|---|
| 재부팅 (`boot_time` 불일치) | 기기를 다시 시작해 마스터 비밀번호가 필요합니다. |
| 7일 경과 | 보안을 위해 7일마다 마스터 비밀번호가 필요합니다. |
| 항목 없음 / Face ID 변경 | Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요. |

비밀번호로 성공하면 `last_password_unlock`을 갱신하고, Face ID가 켜져 있으면 현재 부팅 시각을 기록합니다. 그래서 재부팅 후 한 번 비밀번호로 열면 Face ID가 다시 됩니다. 키체인 항목은 재부팅을 견딥니다. 마스터 비밀번호나 Secret Key가 바뀌면 파생 키가 달라지므로 키체인 항목을 다시 씁니다.

아래 작업은 Face ID로 대신할 수 없습니다. 금고가 열린 뒤에도 마스터 비밀번호를 다시 묻습니다.

- Secret Key 보기
- Secret Key / 비상 키트 내보내기
- 마스터 비밀번호 변경
- 관리 기기 지정·넘겨받기·넘기기

## Personal Team 빌드

유료 Apple Developer 프로그램이나 Keychain Sharing entitlement가 필요 없습니다.

- `LocalAuthentication`과 기본 키체인은 Personal Team으로 설치한 앱에서 동작합니다.
- `kSecAttrAccessGroup`을 넣지 않습니다. 넣으면 그룹 entitlement가 필요합니다.
- iCloud 키체인 동기화를 끕니다.
- 번들 ID는 `com.securevault.ios`입니다. Mac 앱(`com.securevault.app`)과 키체인이 겹치지 않습니다.
- `src-tauri/Info.ios.plist`의 `NSFaceIDUsageDescription`이 `tauri.ios.conf.json` `bundle.iOS.infoPlist`로 들어갑니다. CI의 `tauri ios init` 뒤에는 `scripts/ios-prepare.sh`가 생성된 Info.plist에 키가 없으면 넣습니다.

## 실제 iPhone에서 확인

1. Personal Team으로 기기에 설치합니다. 설정 → Face ID 및 암호가 켜져 있어야 합니다.
2. 금고를 마스터 비밀번호로 엽니다.
3. 설정 → **Face ID로 잠금 해제**를 켭니다. 마스터 비밀번호를 확인하고 Face ID를 등록합니다.
4. 지금 잠그기를 누른 뒤 잠금 화면에서 Face ID 프롬프트(또는 **Face ID로 잠금 해제** 버튼)로 엽니다. 비밀번호 칸은 항상 있습니다.
5. 기기를 재시작한 뒤 앱을 열면 Face ID가 거부되고 「기기를 다시 시작해…」가 보입니다. 비밀번호로 연 다음 Face ID가 다시 됩니다.
6. 설정에서 Face ID를 지우고 다시 등록하면 항목이 무효가 되고 토글이 꺼집니다. 비밀번호로 연 뒤 토글을 다시 켭니다.

시뮬레이터에는 Face ID 하드웨어가 없습니다. CI 스크린샷은 `SECUREVAULT_DEMO=1`과 `DEMO_VIEW=unlock`으로 버튼만 그립니다.

## 한계

- Face ID는 **이 iPhone에서만** 동작합니다. 금고 파일을 다른 기기로 복사해도 키체인 항목은 따라가지 않습니다.
- 기기 암호가 없으면 `WhenPasscodeSetThisDeviceOnly` 때문에 저장할 수 없습니다.
- 7일 창과 재부팅 검사는 앱이 기록한 메타데이터에 의존합니다. 앱 데이터를 지우면 Face ID 토글이 꺼집니다.
- 시뮬레이터와 Linux/Mac 데스크톱 빌드에는 Face ID 명령이 `unsupported`를 돌려주고 UI에 나오지 않습니다 (iOS 앱·iOS 데모 화면 제외).
