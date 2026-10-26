import Foundation
import SafariServices

/// Receives `browser.runtime.sendNativeMessage` from the extension's service
/// worker and relays it to the SecureVault app socket. Never logs.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let key: String
        if #available(macOS 11.0, *) { key = SFExtensionMessageKey } else { key = "message" }
        let message = item?.userInfo?[key] as? [String: Any] ?? [:]
        let reply = AutofillRelay.answer(message)
        let out = NSExtensionItem()
        out.userInfo = [key: reply]
        context.completeRequest(returningItems: [out], completionHandler: nil)
    }
}
