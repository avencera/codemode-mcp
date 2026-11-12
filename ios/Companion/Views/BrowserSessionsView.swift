import CompanionCore
import SwiftUI

/// The gateway's browser sessions: the handoffs waiting on the owner, the
/// sessions running, which any can take over or close, the saved ones to
/// start again or remove, and New session
struct BrowserSessionsSection: View {
    @Environment(AppManager.self) private var manager
    let gatewayName: String
    /// The session New session starts, while its sheet is up; the list
    /// holds the sheet, since a section's own modifiers do not reliably run
    @Binding var starting: NewSession?
    /// The running session whose Close waits on the owner's confirmation
    @State private var closing: String?
    /// The saved session whose Remove waits on the owner's confirmation
    @State private var removing: String?

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
                .swipeActions {
                    Button("Close", systemImage: "xmark.circle") { closing = session.name }
                        .tint(.red)
                }
                .contextMenu {
                    Button("Close Session", systemImage: "xmark.circle", role: .destructive) { closing = session.name }
                }
                // on the row, since a section's own modifiers do not reliably
                // run
                .confirmationDialog(
                    "Close \(session.name)?",
                    isPresented: Binding(
                        get: { closing == session.name },
                        set: { if !$0 { closing = nil } }
                    ),
                    titleVisibility: .visible
                ) {
                    Button("Close Session", role: .destructive) {
                        manager.dispatch(.closeSession(session: session.name))
                    }
                } message: {
                    Text("Its browser on \(gatewayName) quits, and an agent using it loses the page. Its saved sign-ins stay, so it starts again signed in.")
                }
            }
            ForEach(sessions.saved, id: \.name) { saved in
                let name = saved.name
                // starts where it left off; only a session whose last page
                // the gateway does not know asks for an address
                Button {
                    if let page = saved.lastPage {
                        manager.dispatch(.startSession(session: name, url: page))
                    } else {
                        starting = NewSession(name: name)
                    }
                } label: {
                    SessionRow(name: name, detail: saved.detail, icon: "moon.zzz", tint: .secondary)
                }
                .swipeActions {
                    Button("Remove", systemImage: "trash") { removing = name }
                        .tint(.red)
                }
                .contextMenu {
                    Button("Start at Another Address", systemImage: "link") {
                        starting = NewSession(name: name)
                    }
                    Button("Remove Session", systemImage: "trash", role: .destructive) { removing = name }
                }
                .confirmationDialog(
                    "Remove \(name)?",
                    isPresented: Binding(
                        get: { removing == name },
                        set: { if !$0 { removing = nil } }
                    ),
                    titleVisibility: .visible
                ) {
                    Button("Remove Session", role: .destructive) {
                        manager.dispatch(.removeSession(session: name))
                    }
                } message: {
                    Text("Its saved sign-ins move to the Trash on \(gatewayName), and it leaves this list.")
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
                Text("Sessions of the browser on \(gatewayName). Take one over to use it here; agents keep using it after you leave. Swipe one to close or remove it.")
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

extension SavedSession {
    /// Where tapping it starts it
    var detail: String {
        guard let lastPage else { return "Not running · tap to start" }
        return "Not running · tap to open \(lastPage.replacingOccurrences(of: "https://", with: ""))"
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
