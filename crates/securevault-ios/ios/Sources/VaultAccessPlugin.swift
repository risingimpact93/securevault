import Foundation
import Tauri
import UIKit
import UniformTypeIdentifiers

struct PickResult: Encodable {
  let path: String
  let bookmark: String
  let cancelled: Bool
  let copied: Bool
}

/// Opens an existing vault with UIDocumentPicker in place (not a copy into a
/// temp file) and returns security-scoped bookmark bytes.
class VaultAccessPlugin: Plugin {
  private var picker: UIDocumentPickerViewController?
  private var pending: Invoke?

  /// CI and the app call this to prove the Swift plugin is registered.
  @objc public func ping(_ invoke: Invoke) throws {
    invoke.resolve(["ok": true, "plugin": "vault-access"])
  }

  @objc public func pickVault(_ invoke: Invoke) throws {
    if Thread.isMainThread {
      present(invoke)
    } else {
      DispatchQueue.main.async {
        self.present(invoke)
      }
    }
  }

  /// The webview controller may already be presenting (e.g. a sheet); walk to the top.
  private func topViewController() -> UIViewController? {
    var root = manager.viewController
    if root == nil {
      root = UIApplication.shared.connectedScenes
        .compactMap { $0 as? UIWindowScene }
        .flatMap { $0.windows }
        .first { $0.isKeyWindow }?.rootViewController
    }
    var top = root
    while let next = top?.presentedViewController, !next.isBeingDismissed {
      top = next
    }
    return top
  }

  private func present(_ invoke: Invoke) {
    let khv = UTType(filenameExtension: "khv") ?? .data
    let picker = UIDocumentPickerViewController(forOpeningContentTypes: [khv, .data], asCopy: false)
    picker.allowsMultipleSelection = false
    picker.shouldShowFileExtensions = true
    picker.delegate = self
    if pending != nil {
      invoke.reject("문서 선택기가 이미 열려 있습니다.")
      return
    }
    guard let host = topViewController() else {
      invoke.reject("문서 선택기를 띄울 화면을 찾지 못했습니다.")
      return
    }
    self.picker = picker
    self.pending = invoke
    host.present(picker, animated: true)
  }

  private func finish(_ invoke: Invoke?, result: PickResult?, error: String?) {
    if let result = result {
      invoke?.resolve(result)
    } else {
      invoke?.reject(error ?? "금고를 열지 못했습니다.")
    }
    pending = nil
    picker = nil
  }

  /// Bookmark failed. Keep a sandbox copy so the vault can still be read.
  private func copyIntoDocuments(_ url: URL) -> URL? {
    guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
      return nil
    }
    let name = url.lastPathComponent.isEmpty ? "vault.khv" : url.lastPathComponent
    let dest = docs.appendingPathComponent(name)
    if FileManager.default.fileExists(atPath: dest.path) {
      try? FileManager.default.removeItem(at: dest)
    }
    do {
      try FileManager.default.copyItem(at: url, to: dest)
      return dest
    } catch {
      return nil
    }
  }
}

extension VaultAccessPlugin: UIDocumentPickerDelegate {
  public func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    guard let url = urls.first else {
      finish(pending, result: PickResult(path: "", bookmark: "", cancelled: true, copied: false), error: nil)
      return
    }
    // Keep the scope open for this process (Rust reads/writes the path).
    // On the next launch Rust resolves the bookmark and starts access again.
    let started = url.startAccessingSecurityScopedResource()
    // Coordinate with iCloud so a not-yet-downloaded file is materialized first.
    var coordError: NSError?
    NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: [], error: &coordError) { _ in }
    if let coordError = coordError, !started {
      finish(pending, result: nil, error: "금고 파일에 접근하지 못했습니다: \(coordError.localizedDescription)")
      return
    }
    do {
      let data = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
      finish(
        pending,
        result: PickResult(
          path: url.path,
          bookmark: data.base64EncodedString(),
          cancelled: false,
          copied: false
        ),
        error: nil
      )
    } catch {
      if let copied = copyIntoDocuments(url) {
        finish(
          pending,
          result: PickResult(path: copied.path, bookmark: "", cancelled: false, copied: true),
          error: nil
        )
      } else {
        finish(pending, result: nil, error: error.localizedDescription)
      }
    }
  }

  public func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
    finish(pending, result: PickResult(path: "", bookmark: "", cancelled: true, copied: false), error: nil)
  }
}

@_cdecl("init_plugin_vault_access")
func initPlugin() -> Plugin {
  return VaultAccessPlugin()
}
