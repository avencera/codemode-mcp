import Foundation

extension Bundle {
    /// The release and build this app was built as, such as "0.10.0 (202610182031)",
    /// so the owner can tell which TestFlight build is installed
    var versionText: String {
        let version = infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = infoDictionary?["CFBundleVersion"] as? String ?? "unknown"

        return "\(version) (\(build))"
    }
}
