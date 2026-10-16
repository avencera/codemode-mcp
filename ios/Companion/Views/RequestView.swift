import CompanionCore
import SwiftUI

/// One read: what it is for, how long the gateway waits, Approve and Deny
struct RequestView: View {
    @Environment(AppManager.self) private var manager
    let read: PendingRead
    /// Approve waits a moment after a read appears: it takes the place of
    /// the last read's Done button, and a tap meant for that must not
    /// approve the new one
    @State private var armed = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: icon)
                .font(.system(size: 56))
                .foregroundStyle(tint)
            VStack(spacing: 8) {
                Text("codemode-mcp on \(read.gatewayName) wants to read")
                    .font(.headline)
                    .multilineTextAlignment(.center)
                Text(read.reference)
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
            }
            status
            Spacer()
            actions
        }
        .padding(24)
        .task(id: read.id) {
            armed = false
            try? await Task.sleep(for: .seconds(1.5))
            armed = true
        }
        .navigationTitle("Approve a read")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private var status: some View {
        switch read.status {
        case .connecting:
            Label("Reaching the gateway…", systemImage: "antenna.radiowaves.left.and.right")
                .foregroundStyle(.secondary)
        case .waiting, .approving:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Text("\(secondsLeft(at: context.date)) s left")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
        case .approved:
            Text("Sent to the gateway.")
        case .denied:
            Text("Denied. Nothing was sent.")
        case .expired:
            Text("The gateway stopped waiting. Nothing was sent.")
        case .withdrawn:
            Text("Answered elsewhere. Nothing was sent.")
        case .notAllowed:
            Text("Refused: this reference is not on this iPhone's allow list.")
        case let .failed(message):
            Text("Failed: \(message)")
        }
    }

    @ViewBuilder
    private var actions: some View {
        if read.status.isFinished {
            Button("Done") { manager.dispatch(.dismiss(id: read.id)) }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        } else {
            VStack(spacing: 12) {
                Button {
                    manager.dispatch(.approve(id: read.id))
                } label: {
                    Label("Approve with Face ID", systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(read.status != .waiting || !armed)

                Button(role: .destructive) {
                    manager.dispatch(.deny(id: read.id))
                } label: {
                    Text("Deny").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
        }
    }

    private var icon: String {
        switch read.status {
        case .approved: "checkmark.circle.fill"
        case .denied, .notAllowed, .failed: "xmark.circle.fill"
        case .expired, .withdrawn: "clock.badge.xmark"
        default: "key.fill"
        }
    }

    private var tint: Color {
        switch read.status {
        case .approved: .green
        case .denied, .notAllowed, .failed: .red
        case .expired, .withdrawn: .secondary
        default: .accentColor
        }
    }

    private func secondsLeft(at date: Date) -> Int {
        max(0, Int((Double(read.expiresAtMs) / 1000 - date.timeIntervalSince1970).rounded(.down)))
    }
}
