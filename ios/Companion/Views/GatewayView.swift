import CompanionCore
import SwiftUI

/// The paired gateway: its name, the link, what this iPhone may read, and
/// unpairing
struct GatewayView: View {
    @Environment(AppManager.self) private var manager
    @State private var confirmingUnpair = false

    var body: some View {
        List {
            if let gateway = manager.state.gateway {
                Section {
                    LabeledContent("Gateway", value: gateway.name)
                    LabeledContent("This iPhone", value: gateway.phoneName)
                    LabeledContent("Connection") { connection }
                }
                if let pairing = pairingMessage {
                    Section("Pairing") { Text(pairing) }
                }
                Section {
                    ForEach(gateway.allow, id: \.self) { reference in
                        Text(reference).font(.system(.footnote, design: .monospaced))
                    }
                } header: {
                    Text("Allowed references")
                } footer: {
                    Text("The gateway can ask this iPhone for these only, and each read needs Face ID.")
                }
                Section {
                    Button("Unpair", role: .destructive) { confirmingUnpair = true }
                }
            }
        }
        .navigationTitle("Companion")
        .confirmationDialog(
            "Unpair from this gateway?",
            isPresented: $confirmingUnpair,
            titleVisibility: .visible
        ) {
            Button("Unpair", role: .destructive) { manager.dispatch(.unpair) }
        } message: {
            Text("This iPhone's keys are deleted, so the values sealed to it can no longer be opened.")
        }
    }

    @ViewBuilder
    private var connection: some View {
        switch manager.state.connection {
        case .connected:
            Label("Connected", systemImage: "circle.fill").foregroundStyle(.green)
        case .connecting:
            Label("Connecting…", systemImage: "circle.dotted")
        case .offline:
            Label("Offline", systemImage: "circle").foregroundStyle(.secondary)
        case let .retrying(inSecs, error):
            VStack(alignment: .trailing) {
                Text("Retrying in \(inSecs) s").foregroundStyle(.orange)
                Text(error).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var pairingMessage: String? {
        switch manager.state.pairing {
        case .checking: "The gateway is checking the pairing…"
        case let .done(message): message
        case let .failed(message): message
        default: nil
        }
    }
}
