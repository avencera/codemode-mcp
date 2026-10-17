import CompanionCore
import Foundation
import Observation

/// The UI's copy of the core's state, kept current by the core's updates
@Observable
final class AppManager: Reconciler, @unchecked Sendable {
    static let shared = AppManager()

    private(set) var state: AppState

    @ObservationIgnored private let rust: FfiApp

    private init() {
        rust = FfiApp(platform: SystemPlatform())
        state = rust.state()
        rust.listenForUpdates(reconciler: WeakReconciler(self))
    }

    func dispatch(_ action: AppAction) {
        rust.dispatch(action: action)
    }

    /// Sends a value the owner pasted or filled in as the read's answer
    func answer(id: String, value: String) {
        rust.answer(id: id, value: value)
    }

    /// Approves a program read: sends the values the owner pasted or filled
    /// in, by item index, and opens the sealed rest with one Face ID
    func answerProgram(id: String, entered: [UInt32: String]) {
        rust.answerProgram(id: id, entered: entered)
    }

    /// The read the request screen shows: the first one still waiting on
    /// the owner, else the newest finished one until it is dismissed
    var shownRead: PendingRead? {
        state.reads.first { !$0.status.isFinished } ?? state.reads.last
    }

    func reconcile(update: Update) {
        DispatchQueue.main.async { [weak self] in self?.apply(update) }
    }

    @MainActor
    private func apply(_ update: Update) {
        switch update {
        case let .gateway(gateway):
            state.gateway = gateway
        case let .connection(connection):
            state.connection = connection
        case let .reads(reads):
            state.reads = reads
        case let .pairing(pairing):
            state.pairing = pairing
        }
    }
}

extension ReadStatus {
    var isFinished: Bool {
        switch self {
        case .connecting, .waiting, .approving:
            false
        default:
            true
        }
    }
}

/// Holds the manager weakly, so the core's reference does not keep it alive
final class WeakReconciler: Reconciler, @unchecked Sendable {
    private weak var target: AppManager?

    init(_ target: AppManager) {
        self.target = target
    }

    func reconcile(update: Update) {
        target?.reconcile(update: update)
    }
}

/// Whole minutes in a program read's keep, rounded up, as prompts show it
func keepMinutes(_ secs: UInt64) -> UInt64 {
    (secs + 59) / 60
}
