// Containing app for the SecureVault Safari extension. It only explains the
// setup and opens Safari's extension settings; it never touches the vault.
import AppKit
import SafariServices

let extensionID = "com.securevault.safari.extension"

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let status = NSTextField(labelWithString: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 220),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "SecureVault Safari"
        let text = NSTextField(wrappingLabelWithString:
            "Safari 설정 > 확장 프로그램에서 'SecureVault'를 켜 주세요.\n" +
            "SecureVault 앱에서 '브라우저 확장 연결'을 켜야 동작합니다.\n" +
            "서명되지 않은 확장이므로 Safari를 다시 열 때마다 개발자 메뉴에서 " +
            "'서명되지 않은 확장 프로그램 허용'을 다시 켜야 합니다.")
        let button = NSButton(title: "Safari 확장 설정 열기", target: self, action: #selector(openPrefs))
        let stack = NSStackView(views: [text, button, status])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        window.contentView = stack
        window.center()
        window.makeKeyAndOrderFront(nil)
        refresh()
    }

    func refresh() {
        SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: extensionID) { state, _ in
            DispatchQueue.main.async {
                self.status.stringValue = (state?.isEnabled ?? false) ? "상태: Safari에서 켜져 있음" : "상태: Safari에서 꺼져 있음"
            }
        }
    }

    @objc func openPrefs() {
        SFSafariApplication.showPreferencesForExtension(withIdentifier: extensionID) { _ in }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
