import Darwin
import Foundation

/// Relay from the Safari extension to the SecureVault app's Unix socket.
/// Same rules as the Chrome native host (crates/securevault-core/src/autofill_ipc.rs):
/// only known keys from the extension, the token and caller origin are added
/// here, the token file must be 0600 and ours, the socket peer must be our UID,
/// 64 KiB line cap, 10 s timeout, no TCP, no logging.
enum AutofillRelay {
    static let callerOrigin = "safari-web-extension://com.securevault.safari.extension/"
    static let allowedKeys = ["op", "page_url", "top_url", "item_id", "user_confirmed"]
    static let maxLine = 64 * 1024

    static let unavailable: [String: Any] = ["status": "unavailable"]

    /// Real home folder (the sandbox redirects NSHomeDirectory to the container).
    static func autofillDir() -> String? {
        guard let pw = getpwuid(getuid()), let home = pw.pointee.pw_dir else { return nil }
        return String(cString: home) + "/Library/Application Support/com.securevault.app/autofill"
    }

    static func answer(_ message: [String: Any]) -> [String: Any] {
        guard let dir = autofillDir(), let token = readToken(dir + "/token") else { return unavailable }
        var req: [String: Any] = [:]
        for k in allowedKeys { if let v = message[k] { req[k] = v } }
        req["token"] = token
        req["caller_origin"] = callerOrigin
        guard JSONSerialization.isValidJSONObject(req),
              var body = try? JSONSerialization.data(withJSONObject: req) else { return ["status": "denied"] }
        defer { body.resetBytes(in: 0..<body.count) }
        body.append(0x0A)
        guard let line = exchange(socketPath: dir + "/af.sock", request: body),
              let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              obj["status"] is String else { return unavailable }
        return obj
    }

    static func readToken(_ path: String) -> String? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == getuid(), (st.st_mode & 0o077) == 0,
              (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        var buf = [UInt8](repeating: 0, count: 256)
        let n = read(fd, &buf, buf.count)
        defer { buf.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard n > 0 else { return nil }
        let s = String(decoding: buf[0..<n], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return s.isEmpty ? nil : s
    }

    static func exchange(socketPath: String, request: Data) -> Data? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
            raw[pathBytes.count] = 0
        }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard ok == 0 else { return nil }

        // The listener must be our own user (the SecureVault app).
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return nil }

        let sent = request.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard sent == request.count else { return nil }

        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while out.count <= maxLine {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            out.append(contentsOf: chunk[0..<n])
            if let nl = out.firstIndex(of: 0x0A) { return out.prefix(upTo: nl) }
        }
        return nil
    }
}
