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

  @objc public func pickVault(_ invoke: Invoke) throws {
    DispatchQueue.main.async {
      self.present(invoke)
    }
  }

  private func present(_ invoke: Invoke) {
    let khv = UTType(filenameExtension: "khv") ?? .data
    let picker = UIDocumentPickerViewController(forOpeningContentTypes: [khv, .data], asCopy: false)
    picker.allowsMultipleSelection = false
    picker.shouldShowFileExtensions = true
    picker.delegate = self
    self.picker = picker
    self.pending = invoke
    guard let host = manager.viewController else {
      finish(invoke, result: nil, error: "화면을 찾지 못했습니다.")
      return
    }
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
    let started = url.startAccessingSecurityScopedResource()
    // Leave the scope open for this process. Rust resolves the bookmark again
    // on the next launch and holds that URL.
    _ = started
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
