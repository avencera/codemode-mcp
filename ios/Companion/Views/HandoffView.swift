import CompanionCore
import SwiftUI

/// One handoff: an agent asks the owner to do a step in a browser session on
/// the gateway or a machine it vouches for, such as a passkey or a captcha. Take over opens the
/// session live on this phone; Cancel tells the agent the owner will not
struct HandoffView: View {
    @Environment(AppManager.self) private var manager
    let handoff: PendingHandoff
    /// Each button waits a moment after it appears, so a tap meant for the
    /// screen before does not land on Take over or Cancel
    @State private var armed = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: icon)
                    .font(.system(size: 48))
                    .foregroundStyle(tint)
                VStack(spacing: 8) {
                    Text("An agent on \(handoff.host.place(gatewayName: handoff.gatewayName)) needs you in its browser")
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    Label(handoff.session, systemImage: "safari")
                        .font(.callout.weight(.medium))
                    if let url = handoff.url {
                        Text(url)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                    }
                }
                if let reason = handoff.reason {
                    VStack(spacing: 4) {
                        Text("The agent says")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("“\(reason)”")
                            .italic()
                            .multilineTextAlignment(.center)
                    }
                }
                status
                actions
            }
            .padding(24)
        }
        .task(id: "\(handoff.id) \(handoff.status.isFinished)") {
            armed = false
            try? await Task.sleep(for: .seconds(1))
            armed = true
        }
        .navigationTitle("Browser handoff")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                // puts the card aside for the session list, which still
                // lists this handoff
                Button {
                    manager.browse()
                } label: {
                    Label("Sessions", systemImage: "chevron.backward")
                        .labelStyle(.titleAndIcon)
                }
            }
        }
    }

    @ViewBuilder
    private var actions: some View {
        if handoff.status.isFinished {
            Button("Done") { manager.dispatch(.dismiss(id: handoff.id)) }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!armed)
        } else {
            VStack(spacing: 12) {
                Button {
                    manager.dispatch(.openTakeover(session: handoff.session, handoff: handoff.id, host: handoff.host))
                } label: {
                    Label("Take over", systemImage: "hand.tap")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!armed)

                Button(role: .destructive) {
                    manager.dispatch(.cancelHandoff(id: handoff.id))
                } label: {
                    Text("Cancel").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(!armed)
            }
        }
    }

    @ViewBuilder
    private var status: some View {
        switch handoff.status {
        case .waiting:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Text(timeLeft(at: context.date))
                    .monospacedDigit()
            }
            .foregroundStyle(.secondary)
        case .cancelled:
            Text("Cancelled. The agent was told you will not do it.")
        case .expired:
            Text("The agent stopped waiting.")
        case .over:
            Text("Finished, or answered elsewhere.")
        }
    }

    private var icon: String {
        switch handoff.status {
        case .waiting: "hand.raised.fill"
        case .cancelled: "xmark.circle.fill"
        case .expired, .over: "clock.badge.xmark"
        }
    }

    private var tint: Color {
        switch handoff.status {
        case .waiting: .accentColor
        case .cancelled: .red
        case .expired, .over: .secondary
        }
    }

    private func timeLeft(at date: Date) -> String {
        let seconds = max(0, Int((Double(handoff.expiresAtMs) / 1000 - date.timeIntervalSince1970).rounded(.down)))
        if seconds < 60 { return "\(seconds) s left" }
        return "\(seconds / 60) min \(seconds % 60) s left"
    }
}
