import Foundation

/// Files shared from 1Password into the share extension, waiting for the
/// app to attach one to a program read that describes an item
///
/// They sit in the app group's container, which only the app and its
/// extension can open, with complete file protection, so they are
/// unreadable while the iPhone is locked. The app deletes each once it is
/// sent or the read ends, and anything older than a read can wait
enum SharedInbox {
    static let group = "group.com.avencera.codemode-mcp.companion"

    /// No read waits longer than the gateway's 300 s, so an older file is
    /// never attached and is deleted unread
    static let lifetime: TimeInterval = 300

    /// Most bytes the extension keeps; the app refuses what the core cannot
    /// send, which is far less
    static let maxBytes = 1 << 20

    struct File: Equatable {
        let url: URL
        let name: String
        let size: Int
        let received: Date
    }

    enum StoreError: LocalizedError {
        case noContainer
        case tooLarge(Int)

        var errorDescription: String? {
            switch self {
            case .noContainer:
                "The Companion app's shared storage is unavailable."
            case let .tooLarge(size):
                "The file is \(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)), too large to send."
            }
        }
    }

    private static var directory: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: group)?
            .appendingPathComponent("Inbox", isDirectory: true)
    }

    /// Keeps `data` as the newest shared file, named `name`
    static func store(_ data: Data, name: String) throws {
        guard data.count <= maxBytes else { throw StoreError.tooLarge(data.count) }
        guard let directory else { throw StoreError.noContainer }
        // one folder per share, so two files of the same name never collide
        let folder = directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let safe = name.replacingOccurrences(of: "/", with: "_")
        try data.write(
            to: folder.appendingPathComponent(safe.isEmpty ? "file" : safe),
            options: [.atomic, .completeFileProtection]
        )
    }

    /// The newest file shared within `lifetime`, after deleting older ones
    static func latest() -> File? {
        purgeExpired()

        return files().max { $0.received < $1.received }
    }

    /// The file's bytes, or nil when it is gone
    static func bytes(of file: File) -> Data? {
        try? Data(contentsOf: file.url)
    }

    /// Deletes `file` and the folder it came in
    static func remove(_ file: File) {
        try? FileManager.default.removeItem(at: file.url.deletingLastPathComponent())
    }

    /// Deletes every file older than `lifetime`
    static func purgeExpired() {
        let cutoff = Date().addingTimeInterval(-lifetime)
        for file in files() where file.received < cutoff {
            remove(file)
        }
    }

    private static func files() -> [File] {
        guard let directory,
              let folders = try? FileManager.default.contentsOfDirectory(
                  at: directory,
                  includingPropertiesForKeys: nil
              )
        else { return [] }

        return folders.compactMap { folder in
            let keys: [URLResourceKey] = [.fileSizeKey, .creationDateKey]
            guard let url = try? FileManager.default.contentsOfDirectory(
                at: folder,
                includingPropertiesForKeys: keys
            ).first,
                let values = try? url.resourceValues(forKeys: Set(keys))
            else {
                // an empty or unreadable folder is left over from a failed share
                try? FileManager.default.removeItem(at: folder)
                return nil
            }

            return File(
                url: url,
                name: url.lastPathComponent,
                size: values.fileSize ?? 0,
                received: values.creationDate ?? .distantPast
            )
        }
    }
}
