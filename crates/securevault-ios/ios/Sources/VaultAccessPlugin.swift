import Foundation
import Tauri
import UIKit
import UniformTypeIdentifiers
import WebKit

struct PickResult: Encodable {
  let path: String
  let bookmark: String
  let cancelled: Bool
  let copied: Bool
}

struct FileArgs: Decodable {
  let bookmark: String
  let path: String?
  let data: String?
  let timeoutSecs: Double?
}

/// A failure at one stage of scoped file access. The message names the stage in Korean.
struct StageError: Error {
  let stage: String
  let detail: String
  var message: String { "[\(stage)] \(detail)" }
}

/// Opens an existing vault with UIDocumentPicker in place (not a copy into a
/// temp file) and returns security-scoped bookmark bytes.
class VaultAccessPlugin: Plugin {
  // The web UI handles safe areas itself (viewport-fit=cover + env()).
  // Without this, UIKit adds automatic scroll insets and the page's
  // viewport ends ~93pt above the bottom of the screen.
  override func load(webview: WKWebView) {
    super.load(webview: webview)
    DispatchQueue.main.async {
      webview.scrollView.contentInsetAdjustmentBehavior = .never
      webview.scrollView.contentInset = .zero
      webview.scrollView.scrollIndicatorInsets = .zero
      webview.scrollView.bounces = false
    }
  }

  private var picker: UIDocumentPickerViewController?
  private var pending: Invoke?

  /// CI and the app call this to prove the Swift plugin is registered.
  @objc public func ping(_ invoke: Invoke) throws {
    invoke.resolve(["ok": true, "plugin": "vault-access"])
  }

  // MARK: scoped file IO (runs on Tauri's ipc queue, never the main thread)

  /// Resolve the bookmark and start security-scoped access. Caller must stop.
  private func resolve(_ args: FileArgs) throws -> (URL, Bool, String?) {
    guard let data = Data(base64Encoded: args.bookmark), !data.isEmpty else {
      throw StageError(stage: "북마크", detail: "저장된 북마크가 비어 있거나 손상되었습니다. 금고를 다시 선택해 주세요.")
    }
    var stale = false
    let url: URL
    do {
      url = try URL(resolvingBookmarkData: data, options: [.withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
    } catch {
      throw StageError(stage: "북마크", detail: "북마크를 해석하지 못했습니다. 금고를 다시 선택해 주세요. (\(error.localizedDescription))")
    }
    let started = url.startAccessingSecurityScopedResource()
    var refreshed: String?
    if stale, let fresh = try? url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) {
      refreshed = fresh.base64EncodedString()
    }
    NSLog("SecureVault vault-access: resolved %@ (scope started: %@, stale: %@)", url.lastPathComponent, started ? "yes" : "no", stale ? "yes" : "no")
    return (url, started, refreshed)
  }

  /// Make sure an iCloud item is downloaded locally before reading it.
  private func ensureDownloaded(_ url: URL, timeout: Double) throws {
    let keys: Set<URLResourceKey> = [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey]
    guard let values = try? url.resourceValues(forKeys: keys), values.isUbiquitousItem == true else {
      return
    }
    if values.ubiquitousItemDownloadingStatus == .current {
      return
    }
    do {
      try FileManager.default.startDownloadingUbiquitousItem(at: url)
    } catch {
      throw StageError(stage: "다운로드", detail: "iCloud에서 금고 파일 내려받기를 시작하지 못했습니다. (\(error.localizedDescription))")
    }
    NSLog("SecureVault vault-access: waiting for iCloud download of %@", url.lastPathComponent)
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      Thread.sleep(forTimeInterval: 0.5)
      var fresh = url
      fresh.removeAllCachedResourceValues()
      if let status = try? fresh.resourceValues(forKeys: keys).ubiquitousItemDownloadingStatus, status == .current {
        return
      }
    }
    throw StageError(stage: "다운로드", detail: "iCloud에서 금고 파일을 \(Int(timeout))초 안에 내려받지 못했습니다. 네트워크와 iCloud Drive 상태를 확인한 뒤 다시 시도해 주세요.")
  }

  private func statInfo(_ url: URL) -> JsonObject {
    var fresh = url
    fresh.removeAllCachedResourceValues()
    let values = try? fresh.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
    let mtime = values?.contentModificationDate?.timeIntervalSince1970 ?? 0
    return ["size": values?.fileSize ?? 0, "mtimeMs": Int64(mtime * 1000)]
  }

  private func runScoped(_ invoke: Invoke, _ body: (URL, FileArgs) throws -> JsonObject) {
    do {
      let args = try invoke.parseArgs(FileArgs.self)
      let (url, started, refreshed) = try resolve(args)
      defer {
        if started { url.stopAccessingSecurityScopedResource() }
      }
      var result = try body(url, args)
      result["path"] = url.path
      if let refreshed = refreshed { result["bookmark"] = refreshed }
      invoke.resolve(result)
    } catch let error as StageError {
      NSLog("SecureVault vault-access error: %@", error.message)
      invoke.reject(error.message)
    } catch {
      NSLog("SecureVault vault-access error: %@", error.localizedDescription)
      invoke.reject("[접근] \(error.localizedDescription)")
    }
  }

  @objc public func vaultStat(_ invoke: Invoke) throws {
    runScoped(invoke) { url, _ in
      var coordError: NSError?
      var info: JsonObject = ["exists": false]
      NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: [.immediatelyAvailableMetadataOnly], error: &coordError) { readURL in
        var exists = FileManager.default.fileExists(atPath: readURL.path)
        if !exists, let values = try? readURL.resourceValues(forKeys: [.isUbiquitousItemKey]), values.isUbiquitousItem == true {
          exists = true // not yet downloaded placeholder
        }
        info = self.statInfo(readURL)
        info["exists"] = exists
      }
      if let coordError = coordError {
        throw StageError(stage: "접근", detail: "금고 파일 정보를 읽지 못했습니다. (\(coordError.localizedDescription))")
      }
      return info
    }
  }

  @objc public func vaultRead(_ invoke: Invoke) throws {
    runScoped(invoke) { url, args in
      try self.ensureDownloaded(url, timeout: args.timeoutSecs ?? 60)
      var coordError: NSError?
      var bytes: Data?
      var readError: Error?
      var info: JsonObject = [:]
      NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: [], error: &coordError) { readURL in
        do {
          bytes = try Data(contentsOf: readURL)
          info = self.statInfo(readURL)
        } catch {
          readError = error
        }
      }
      if let coordError = coordError {
        throw StageError(stage: "읽기", detail: "파일 조정(NSFileCoordinator)에 실패했습니다. (\(coordError.localizedDescription))")
      }
      if let readError = readError {
        throw StageError(stage: "읽기", detail: "금고 파일을 읽지 못했습니다. (\(readError.localizedDescription))")
      }
      info["data"] = (bytes ?? Data()).base64EncodedString()
      return info
    }
  }

  @objc public func vaultWrite(_ invoke: Invoke) throws {
    runScoped(invoke) { url, args in
      guard let b64 = args.data, let payload = Data(base64Encoded: b64) else {
        throw StageError(stage: "쓰기", detail: "저장할 데이터가 비어 있습니다.")
      }
      var coordError: NSError?
      var writeError: Error?
      var mode = "atomic"
      var info: JsonObject = [:]
      NSFileCoordinator(filePresenter: nil).coordinate(writingItemAt: url, options: [.forReplacing], error: &coordError) { writeURL in
        // A single picked file grants no access to its folder, so the atomic
        // temp-file write may be refused; then write the bytes in place.
        do {
          try payload.write(to: writeURL, options: [.atomic])
        } catch {
          mode = "direct"
          do {
            try payload.write(to: writeURL, options: [])
          } catch {
            writeError = error
          }
        }
        info = self.statInfo(writeURL)
      }
      if let coordError = coordError {
        throw StageError(stage: "쓰기", detail: "파일 조정(NSFileCoordinator)에 실패했습니다. (\(coordError.localizedDescription))")
      }
      if let writeError = writeError {
        throw StageError(stage: "쓰기", detail: "금고 파일을 저장하지 못했습니다. (\(writeError.localizedDescription))")
      }
      NSLog("SecureVault vault-access: wrote %d bytes (%@)", payload.count, mode)
      info["mode"] = mode
      return info
    }
  }

  /// Make a bookmark for a file inside the app (CI self-test and adopt path).
  /// Opens an http(s) address from a login item in the system browser.
  @objc public func openUrl(_ invoke: Invoke) throws {
    struct Args: Decodable { let url: String }
    let args = try invoke.parseArgs(Args.self)
    guard let url = URL(string: args.url),
          let scheme = url.scheme?.lowercased(),
          scheme == "http" || scheme == "https" else {
      invoke.reject("열 수 없는 주소입니다.")
      return
    }
    DispatchQueue.main.async {
      UIApplication.shared.open(url, options: [:]) { ok in
        if ok {
          invoke.resolve(["ok": true])
        } else {
          invoke.reject("주소를 열지 못했습니다.")
        }
      }
    }
  }

  @objc public func makeBookmark(_ invoke: Invoke) throws {
    struct Args: Decodable { let path: String }
    do {
      let args = try invoke.parseArgs(Args.self)
      let data = try URL(fileURLWithPath: args.path).bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
      invoke.resolve(["bookmark": data.base64EncodedString()])
    } catch {
      invoke.reject("[북마크] 북마크를 만들지 못했습니다. (\(error.localizedDescription))")
    }
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
    // Access is only needed to make the bookmark; every later read/write
    // resolves the bookmark and starts/stops access around the operation.
    let started = url.startAccessingSecurityScopedResource()
    defer {
      if started { url.stopAccessingSecurityScopedResource() }
    }
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
