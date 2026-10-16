import Foundation

/// A debug build's event trail in Documents/debug.log, for following a read
/// on a phone without a console; it holds ids and statuses, never values
enum DebugLog {
    private static let lock = NSLock()

    static func write(_ line: @autoclosure () -> String) {
        #if DEBUG
            let entry = "\(ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withInternetDateTime, .withFractionalSeconds])) \(line())\n"
            lock.withLock {
                guard let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
                    .appendingPathComponent("debug.log")
                else { return }
                if let handle = try? FileHandle(forWritingTo: url) {
                    handle.seekToEndOfFile()
                    handle.write(Data(entry.utf8))
                    try? handle.close()
                } else {
                    try? Data(entry.utf8).write(to: url)
                }
            }
        #endif
    }
}
