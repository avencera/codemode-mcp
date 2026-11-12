import CompanionCore
import SwiftUI

/// The gateway's browser sessions: the handoffs waiting on the owner, the
/// sessions running, which any can take over, the saved ones to start again,
/// and New session
struct BrowserSessionsSection: View {
    @Environment(AppManager.self) private var manager
    let gatewayName: String
    /// The session New session starts, while its sheet is up; the list
    /// holds the sheet, since a section's own modifiers do not reliably run
    @Binding var starting: NewSession?

    var body: some View {
        let sessions = manager.state.sessions
        let waiting = manager.state.handoffs.filter { !$0.status.isFinished }
        Section {
            ForEach(waiting, id: \.id) { handoff in
                Button {
                    manager.dispatch(.openTakeover(session: handoff.session, handoff: handoff.id))
                } label: {
                    SessionRow(
                        name: handoff.session,
                        detail: handoff.reason ?? "An agent needs you",
                        icon: "hand.raised.fill",
                        tint: .orange
                    )
                }
            }
            // a session with a waiting handoff shows once, as the handoff, so
            // Done there answers the agent
            ForEach(sessions.running.filter { session in !waiting.contains { $0.session == session.name } }, id: \.name) { session in
                Button {
                    manager.dispatch(.openTakeover(session: session.name, handoff: nil))
                } label: {
                    SessionRow(name: session.name, detail: session.detail, icon: "safari", tint: .accentColor)
                }
            }
            ForEach(sessions.saved, id: \.self) { name in
                Button {
                    starting = NewSession(name: name)
                } label: {
                    SessionRow(name: name, detail: "Not running · tap to start", icon: "moon.zzz", tint: .secondary)
                }
            }
            Button {
                starting = NewSession(name: "")
            } label: {
                Label("New session", systemImage: "plus")
            }
        } header: {
            HStack {
                Text("Browser sessions")
                Spacer()
                if sessions.status == .loading {
                    ProgressView().controlSize(.mini)
                } else {
                    Button {
                        manager.dispatch(.refreshSessions)
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("Refresh the sessions")
                }
            }
        } footer: {
            if case let .failed(message) = sessions.status {
                Text(message).foregroundStyle(.red)
            } else {
                Text("Sessions of the browser on \(gatewayName). Take one over to use it here; agents keep using it after you leave.")
            }
        }
    }
}

/// The session New session starts, by name; empty for a new one
struct NewSession: Identifiable {
    let name: String
    var id: String { name }
}

private struct SessionRow: View {
    let name: String
    let detail: String
    let icon: String
    let tint: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(tint)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .foregroundStyle(.primary)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }
}

extension BrowserSession {
    /// The page's title, else its address without the scheme
    var detail: String {
        if let title, !title.isEmpty { return title }
        guard let url else { return "Running" }
        return url.replacingOccurrences(of: "https://", with: "")
    }
}

/// Names a session and the https address it starts at. A saved session
/// launches with its profile, so a site it signed in to before still is
struct NewSessionSheet: View {
    @Environment(\.dismiss) private var dismiss
    let gatewayName: String
    let onStart: (String, String) -> Void

    @State private var name: String
    @State private var address = ""
    @FocusState private var focused: Field?

    private enum Field {
        case name, address
    }

    init(name: String, gatewayName: String, onStart: @escaping (String, String) -> Void) {
        _name = State(initialValue: name)
        self.gatewayName = gatewayName
        self.onStart = onStart
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name, such as github", text: $name)
                        .focused($focused, equals: .name)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.next)
                        .onSubmit { focused = .address }
                    TextField("Address, such as github.com/login", text: $address)
                        .focused($focused, equals: .address)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.go)
                        .onSubmit(start)
                } footer: {
                    Text(footer)
                }
            }
            .navigationTitle("New session")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Start", action: start)
                        .disabled(!Self.valid(name: name) || url == nil)
                }
            }
            .onAppear { focused = name.isEmpty ? .name : .address }
        }
        .presentationDetents([.medium])
    }

    private var footer: String {
        if !name.isEmpty, !Self.valid(name: name) {
            return "A name is letters, digits, - and _."
        }
        return "Opens in the browser on \(gatewayName), with the session's saved sign-ins when it has some."
    }

    /// The address as `https`, which is all a session starts at
    private var url: String? {
        let typed = address.trimmingCharacters(in: .whitespaces)
        let full = typed.contains("://") ? typed : "https://\(typed)"
        guard let url = URL(string: full), url.scheme == "https", url.host() != nil else { return nil }
        return url.absoluteString
    }

    /// Matches the gateway's session names, so it never refuses one here
    private static func valid(name: String) -> Bool {
        (1 ... 64).contains(name.count)
            && name.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_") }
    }

    private func start() {
        guard Self.valid(name: name), let url else { return }
        onStart(name, url)
        dismiss()
    }
}
