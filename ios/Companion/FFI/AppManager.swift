import CompanionCore
import Foundation
import Observation
import UIKit

/// The UI's copy of the core's state, kept current by the core's updates
@Observable
final class AppManager: Reconciler, @unchecked Sendable {
    static let shared = AppManager()

    private(set) var state: AppState

    /// The newest image of the taken-over page, decoded; the core's state
    /// never holds images
    private(set) var screen: TakeoverScreen?

    /// Whether the owner put the handoff cards aside for the session list;
    /// a new handoff or read brings them back
    private(set) var browsing = false

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

    /// Approves a program read: sends the values the owner pasted, filled in
    /// or shared from 1Password, by item index, and opens the sealed rest
    /// with one Face ID
    func answerProgram(id: String, entered: [UInt32: EnteredValue]) {
        rust.answerProgram(id: id, entered: entered)
    }

    /// Sends what the owner did on the takeover
    func takeover(_ input: TakeoverInput) {
        rust.takeover(input: input)
    }

    /// Types `text` into the taken-over page's focused element
    func takeoverText(_ text: String) {
        rust.takeoverText(text: text)
    }

    /// Fills `value` into the taken-over page's focused `field`
    func takeoverFill(field: LoginField, value: String, submit: Bool) {
        rust.takeoverFill(field: field, value: value, submit: submit)
    }

    /// Shows the gateway's session list until a new handoff or read comes
    func browse() {
        browsing = true
    }

    /// What the app shows: the takeover while one is open, then a read still
    /// waiting, a handoff still waiting, and the newest finished read or
    /// handoff until it is dismissed; while the owner browses, the session
    /// list in place of the handoffs and finished reads
    var shown: Shown {
        if let takeover = state.takeover { return .takeover(takeover) }
        if let read = state.reads.first(where: { !$0.status.isFinished }) { return .read(read) }
        if browsing { return .gateway }
        if let handoff = state.handoffs.first(where: { !$0.status.isFinished }) { return .handoff(handoff) }
        if let read = state.reads.last { return .read(read) }
        if let handoff = state.handoffs.last { return .handoff(handoff) }
        return .gateway
    }

    func reconcile(update: Update) {
        // decoded here, off the main thread, so a large image never holds
        // the UI
        if case let .screen(image) = update {
            guard let decoded = UIImage(data: image.jpeg)?.preparingForDisplay() else { return }
            let screen = TakeoverScreen(seq: image.seq, image: decoded)
            DispatchQueue.main.async { [weak self] in self?.show(screen) }
            return
        }
        DispatchQueue.main.async { [weak self] in self?.apply(update) }
    }

    /// Shows a new image, then tells the core it is drawn once SwiftUI has
    /// had its turn, so the gateway sends the next no faster than this
    /// phone shows them
    @MainActor
    private func show(_ screen: TakeoverScreen) {
        guard state.takeover != nil else { return }
        self.screen = screen
        DispatchQueue.main.async { [weak self] in
            self?.rust.takeover(input: .drawn(seq: screen.seq))
        }
    }

    @MainActor
    private func apply(_ update: Update) {
        switch update {
        case let .gateway(gateway):
            state.gateway = gateway
        case let .connection(connection):
            state.connection = connection
        case let .reads(reads):
            if reads.contains(where: { read in !state.reads.contains { $0.id == read.id } }) {
                browsing = false
            }
            state.reads = reads
        case let .pairing(pairing):
            state.pairing = pairing
        case let .handoffs(handoffs):
            if handoffs.contains(where: { handoff in !state.handoffs.contains { $0.id == handoff.id } }) {
                browsing = false
            }
            state.handoffs = handoffs
        case let .sessions(sessions):
            state.sessions = sessions
        case let .takeover(takeover):
            // a new takeover, or none, starts without the last one's image
            if takeover?.session != state.takeover?.session || takeover?.handoff != state.takeover?.handoff
                || takeover?.host != state.takeover?.host
            {
                screen = nil
            }
            state.takeover = takeover
        case .screen:
            break
        }
    }
}

/// One decoded image of the taken-over page
struct TakeoverScreen {
    /// The image's number, which taps and scrolls name
    let seq: UInt32
    let image: UIImage
}

/// What the app shows, in order of what needs the owner most
enum Shown {
    case takeover(TakeoverState)
    case read(PendingRead)
    case handoff(PendingHandoff)
    case gateway
}

extension HandoffStatus {
    var isFinished: Bool {
        self != .waiting
    }
}

extension LoginField {
    /// The field as prompts name it
    var label: String {
        switch self {
        case .username: "Username"
        case .password: "Password"
        case .code: "One-time code"
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
