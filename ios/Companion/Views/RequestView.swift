import CompanionCore
import SwiftUI

/// One read: what it is for, how long the gateway waits, and the answers:
/// Face ID opens the copy the gateway sealed to this phone, or the owner
/// pastes or fills in the value when there is no copy or it is stale
struct RequestView: View {
    @Environment(AppManager.self) private var manager
    let read: PendingRead
    @State private var entering = false
    @State private var value = ""
    /// Each button waits a moment after it appears: Allow, Approve and Done
    /// take each other's place, so a tap meant for one must not land on the
    /// next, and a result stays readable before it can be dismissed
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
        .task(id: "\(read.id) \(read.status.isFinished) \(read.listed)") {
            // a new read, or one that just finished, starts with no value
            armed = false
            value = ""
            entering = false
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
            VStack(spacing: 4) {
                Label("Reaching the gateway…", systemImage: "antenna.radiowaves.left.and.right")
                // once linked, a read that does not come within seconds is
                // gone, so the gateway's deadline would mislead
                if manager.state.connection != .connected {
                    countdown
                }
            }
            .foregroundStyle(.secondary)
        case .waiting, .approving:
            countdown
                .foregroundStyle(.secondary)
        case .approved:
            Text("Sent to the gateway.")
        case .denied:
            Text("Denied. Nothing was sent.")
        case .expired:
            Text("The gateway stopped waiting. Nothing was sent.")
        case .withdrawn:
            Text("Answered elsewhere. Nothing was sent.")
        case let .failed(message):
            Text("Failed: \(message)")
        }
    }

    private var countdown: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            Text("\(secondsLeft(at: context.date)) s left")
                .monospacedDigit()
        }
    }

    @ViewBuilder
    private var actions: some View {
        if read.status.isFinished {
            Button("Done") { manager.dispatch(.dismiss(id: read.id)) }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!armed)
        } else {
            VStack(spacing: 12) {
                // opened from a push: whether a copy came is not known yet
                if read.status == .connecting {
                    EmptyView()
                } else if !read.listed {
                    Text("This iPhone has not answered this reference before. Allow it only if you expect codemode-mcp to need it.")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                    Button {
                        manager.dispatch(.allow(id: read.id))
                    } label: {
                        Label("Allow this reference", systemImage: "checkmark.shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(read.status != .waiting || !armed)
                } else if read.sealed && !entering {
                    Button {
                        manager.dispatch(.approve(id: read.id))
                    } label: {
                        Label("Approve with Face ID", systemImage: "faceid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(read.status != .waiting || !armed)

                    Button("Enter a different value") { entering = true }
                        .disabled(read.status != .waiting)
                } else {
                    entry
                }

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

    /// The value field: paste it, or fill it from 1Password or Passwords
    /// through AutoFill
    @ViewBuilder
    private var entry: some View {
        if !read.sealed {
            Text("This iPhone has no copy of the value yet. Paste it, or fill it in from your password manager.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        HStack {
            SecureField("Value", text: $value)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .privacySensitive()
                .textFieldStyle(.roundedBorder)
                .submitLabel(.send)
                .onSubmit(send)
            PasteButton(payloadType: String.self) { strings in
                let pasted = strings.first ?? ""
                DispatchQueue.main.async { value = pasted }
            }
            .labelStyle(.iconOnly)
        }
        Button(action: send) {
            Label("Send value", systemImage: "paperplane")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .disabled(value.isEmpty || !armed || read.status.isFinished)
    }

    private func send() {
        guard !value.isEmpty, armed, !read.status.isFinished else { return }
        manager.answer(id: read.id, value: value)
        value = ""
    }

    private var icon: String {
        switch read.status {
        case .approved: "checkmark.circle.fill"
        case .denied, .failed: "xmark.circle.fill"
        case .expired, .withdrawn: "clock.badge.xmark"
        default: "key.fill"
        }
    }

    private var tint: Color {
        switch read.status {
        case .approved: .green
        case .denied, .failed: .red
        case .expired, .withdrawn: .secondary
        default: .accentColor
        }
    }

    private func secondsLeft(at date: Date) -> Int {
        max(0, Int((Double(read.expiresAtMs) / 1000 - date.timeIntervalSince1970).rounded(.down)))
    }
}
