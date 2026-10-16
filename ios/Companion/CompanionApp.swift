import CompanionCore
import SwiftUI
import UIKit
import UserNotifications

@main
struct CompanionApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(AppManager.shared)
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            switch phase {
            case .active:
                AppManager.shared.dispatch(.foreground)
            case .background:
                // iOS suspends the app within seconds; hanging up first tells
                // the gateway to wait for the next dial instead of a dead link
                AppManager.shared.dispatch(.background)
            default:
                break
            }
        }
    }
}

/// Push registration and taps on the pushes that wake the app
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    /// Which APNs environment issued this build's token, as its signing
    /// says: a development profile (any build from Xcode, Debug or Release)
    /// gets sandbox tokens; TestFlight and the App Store, whose builds carry
    /// a distribution profile or none, get production ones
    private let environment = AppDelegate.signedEnvironment()

    private static func signedEnvironment() -> PushEnvironment {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              // the profile is a signed blob around a plain XML plist
              let text = String(data: data, encoding: .isoLatin1),
              let start = text.range(of: "<?xml"),
              let end = text.range(of: "</plist>"),
              let plist = text[start.lowerBound ..< end.upperBound].data(using: .isoLatin1),
              let profile = try? PropertyListSerialization.propertyList(from: plist, format: nil) as? [String: Any],
              let entitlements = profile["Entitlements"] as? [String: Any],
              entitlements["aps-environment"] as? String == "development"
        else {
            return .production
        }

        return .development
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // built here, on the main thread, before any callback can reach it
        _ = AppManager.shared
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            if granted {
                DispatchQueue.main.async { application.registerForRemoteNotifications() }
            } else {
                AppManager.shared.dispatch(.pushToken(token: nil, environment: self.environment))
            }
        }

        return true
    }

    func application(_: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        AppManager.shared.dispatch(.pushToken(token: token, environment: environment))
    }

    func application(_: UIApplication, didFailToRegisterForRemoteNotificationsWithError _: Error) {
        AppManager.shared.dispatch(.pushToken(token: nil, environment: environment))
    }

    /// The owner tapped the push: show that read once the gateway sends it
    func userNotificationCenter(
        _: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let info = response.notification.request.content.userInfo
        guard let id = info["request"] as? String,
              let reference = info["reference"] as? String,
              let gateway = info["gateway"] as? String
        else { return }

        AppManager.shared.dispatch(.openedFromPush(id: id, reference: reference, gateway: gateway))
    }

    /// While the app is open the read shows on screen, so the push stays
    /// quiet
    func userNotificationCenter(
        _: UNUserNotificationCenter,
        willPresent _: UNNotification
    ) async -> UNNotificationPresentationOptions {
        []
    }
}
