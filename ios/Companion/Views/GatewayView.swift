import CompanionCore
import SwiftUI

/// The paired gateway: its name, the link, its browser sessions, and
/// unpairing
struct GatewayView: View {
    @Environment(AppManager.self) private var manager
    /// The session New session starts, while its sheet is up
    @State private var starting: NewSession?

    var body: some View {
        if let gateway = manager.state.gateway {
            GatewayDetails(
                gateway: gateway,
                connection: manager.state.connection,
                pairing: manager.state.pairing,
                unpair: { manager.dispatch(.unpair) }
            ) {
                BrowserSessionsSection(gatewayName: gateway.name, starting: $starting)
            }
            .sheet(item: $starting) { session in
                NewSessionSheet(
                    session: session,
                    gatewayName: gateway.name,
                    machines: manager.state.sessions.machines
                ) { name, url, host in
                    manager.dispatch(.startSession(session: name, url: url, host: host))
                }
            }
            // listed when the screen shows and each time the link comes back
            .task(id: manager.state.connection == .connected) {
                guard manager.state.connection == .connected else { return }
                manager.dispatch(.refreshSessions)
            }
        }
    }
}

/// The gateway screen drawn from plain values, so previews can show each
/// connection state without a core; `sessions` is the browser's section
struct GatewayDetails<Sessions: View>: View {
    let gateway: GatewayInfo
    let connection: ConnectionState
    let pairing: PairingState
    let unpair: () -> Void
    @ViewBuilder let sessions: Sessions
    @State private var confirmingUnpair = false

    var body: some View {
        List {
            // the pairing result shows inside this row rather than as its own
            // section: a section that comes and goes left the card above it
            // drawn at its old height
            Section { header }

            sessions

            Section {
                LabeledContent("Listed on the Mac as", value: gateway.phoneName)
            } footer: {
                Text("When codemode-mcp on \(gateway.name) needs a 1Password value, the request opens here.")
            }

            Section {
                Button("Unpair", role: .destructive) { confirmingUnpair = true }
            } footer: {
                Text("To pair again, run `codemode-mcp companion invite` on the Mac.")
            }

            Section {
                LabeledContent("Version", value: Bundle.main.versionText)
            }
        }
        .navigationTitle("Companion")
        .confirmationDialog(
            "Unpair from this gateway?",
            isPresented: $confirmingUnpair,
            titleVisibility: .visible
        ) {
            Button("Unpair", role: .destructive, action: unpair)
        } message: {
            Text("This iPhone's keys are deleted, so the values sealed to it can no longer be opened.")
        }
    }

    private var header: some View {
        VStack(spacing: 14) {
            Image(systemName: "laptopcomputer.and.iphone")
                .font(.system(size: 36))
                .foregroundStyle(.tint)
                .frame(width: 84, height: 84)
                .background(.tint.opacity(0.12), in: .circle)

            VStack(spacing: 4) {
                Text(gateway.name)
                    .font(.title2.bold())
                    .multilineTextAlignment(.center)
                Text("Gateway")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            status

            if let pairing = pairingMessage {
                Text(pairing.text)
                    .font(.footnote)
                    .foregroundStyle(pairing.failed ? .red : .secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
    }

    private var status: some View {
        VStack(spacing: 6) {
            HStack(spacing: 6) {
                if connection == .connecting {
                    ProgressView().controlSize(.mini)
                } else {
                    Circle().frame(width: 8, height: 8)
                }
                Text(statusText)
            }
            .font(.subheadline.weight(.medium))
            .foregroundStyle(statusTint)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(statusTint.opacity(0.12), in: .capsule)

            if case let .retrying(_, error) = connection {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }

    private var statusText: String {
        switch connection {
        case .connected: "Connected"
        case .connecting: "Connecting…"
        case .offline: "Offline"
        case let .retrying(inSecs, _): "Retrying in \(inSecs) s"
        }
    }

    private var statusTint: Color {
        switch connection {
        case .connected: .green
        case .connecting, .offline: .secondary
        case .retrying: .orange
        }
    }

    private var pairingMessage: (text: String, failed: Bool)? {
        switch pairing {
        case .checking: ("The gateway is checking the pairing…", false)
        case let .done(message): (message, false)
        case let .failed(message): (message, true)
        default: nil
        }
    }
}

#Preview("Connected") {
    NavigationStack {
        GatewayDetails(
            gateway: GatewayInfo(name: "Praveens-Mac-mini", id: "", phoneName: "iPhone"),
            connection: .connected,
            pairing: .idle,
            unpair: {}
        ) {
            EmptyView()
        }
    }
}

#Preview("Retrying") {
    NavigationStack {
        GatewayDetails(
            gateway: GatewayInfo(name: "Praveens-Mac-mini", id: "", phoneName: "iPhone"),
            connection: .retrying(inSecs: 8, error: "the gateway did not answer"),
            pairing: .failed(message: "The check read failed"),
            unpair: {}
        ) {
            EmptyView()
        }
    }
}
