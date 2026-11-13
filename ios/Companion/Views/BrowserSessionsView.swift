import CompanionCore
import SwiftUI

/// The browser sessions: the gateway's, then a section for each machine the
/// gateway vouches for, such as a Linux spoke, which the phone lists on a
/// link of its own; New session starts one on any of them
struct BrowserSessionsSection: View {
    @Environment(AppManager.self) private var manager
    let gatewayName: String
    /// The session New session starts, while its sheet is up; the list
    /// holds the sheet, since a section's own modifiers do not reliably run
    @Binding var starting: NewSession?

    var body: some View {
        let sessions = manager.state.sessions
        let waiting = manager.state.handoffs.filter { !$0.status.isFinished }
        HostSessionsSection(
            host: .gateway,
            place: gatewayName,
            title: "Browser sessions",
            status: sessions.status,
            running: sessions.running,
            saved: sessions.saved,
            waiting: waiting.filter { $0.host.key == SessionHost.gateway.key },
            starting: $starting
        ) {
            Button {
                starting = NewSession(name: "", host: .gateway, movable: true)
            } label: {
                Label("New session", systemImage: "plus")
            }
        }
        ForEach(sessions.machines, id: \.id) { machine in
            let host = SessionHost.machine(id: machine.id, name: machine.name)
            let place = machine.label(among: sessions.machines)
            HostSessionsSection(
                host: host,
                place: place,
                title: "Browser on \(place)",
                status: machine.status,
                running: machine.running,
                saved: machine.saved,
                waiting: waiting.filter { $0.host.key == host.key },
                starting: $starting
            ) {
                EmptyView()
            }
        }
    }
}

/// One machine's browser sessions: the handoffs waiting on the owner, the
/// sessions running, which any can take over or close, and the saved ones
/// to start again or remove
private struct HostSessionsSection<Extra: View>: View {
    @Environment(AppManager.self) private var manager
    let host: SessionHost
    /// The machine's name, as the owner knows it
    let place: String
    let title: String
    let status: SessionsStatus
    let running: [BrowserSession]
    let saved: [SavedSession]
    /// The handoffs waiting on this machine's sessions
    let waiting: [PendingHandoff]
    @Binding var starting: NewSession?
    /// Rows after the sessions, such as New session
    @ViewBuilder let extra: Extra
    /// The running session whose Close waits on the owner's confirmation
    @State private var closing: String?
    /// The saved session whose Remove waits on the owner's confirmation
    @State private var removing: String?

    var body: some View {
        Section {
            ForEach(waiting, id: \.id) { handoff in
                Button {
                    manager.dispatch(.openTakeover(session: handoff.session, handoff: handoff.id, host: host))
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
            ForEach(running.filter { session in !waiting.contains { $0.session == session.name } }, id: \.name) { session in
                Button {
                    manager.dispatch(.openTakeover(session: session.name, handoff: nil, host: host))
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
                        manager.dispatch(.closeSession(session: session.name, host: host))
                    }
                } message: {
                    Text("Its browser on \(place) quits, and an agent using it loses the page. Its saved sign-ins stay, so it starts again signed in.")
                }
            }
            ForEach(saved, id: \.name) { saved in
                let name = saved.name
                // starts where it left off; only a session whose last page
                // the machine does not know asks for an address
                Button {
                    if let page = saved.lastPage {
                        manager.dispatch(.startSession(session: name, url: page, host: host))
                    } else {
                        starting = NewSession(name: name, host: host, movable: false)
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
                        starting = NewSession(name: name, host: host, movable: false)
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
                        manager.dispatch(.removeSession(session: name, host: host))
                    }
                } message: {
                    Text("Its saved sign-ins move to the Trash on \(place), and it leaves this list.")
                }
            }
            extra
        } header: {
            HStack {
                Text(title)
                Spacer()
                if status == .loading {
                    ProgressView().controlSize(.mini)
                } else if host == .gateway {
                    // lists the machines again too, since the gateway names
                    // them
                    Button {
                        manager.dispatch(.refreshSessions)
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("Refresh the sessions")
                }
            }
        } footer: {
            switch status {
            case let .failed(message):
                Text(message).foregroundStyle(.red)
            case let .unreachable(message):
                Text(message).foregroundStyle(.orange)
            case .idle, .loading, .listed:
                Text(footer)
            }
        }
    }

    private var footer: String {
        switch host {
        case .gateway:
            "Sessions of the browser on \(place). Take one over to use it here; agents keep using it after you leave. Swipe one to close or remove it."
        case .machine:
            "Sessions of the browser on \(place), which this iPhone reaches directly. Take one over to use it here; swipe one to close or remove it."
        }
    }
}

/// The session New session starts, by name, and where; empty for a new one
struct NewSession: Identifiable {
    let name: String
    let host: SessionHost
    /// Whether the owner may pick another machine; a saved session's
    /// sign-ins live on its own
    let movable: Bool
    var id: String { "\(host.key)/\(name)" }
}

extension SessionHost {
    /// The machine's name as the owner knows it, the gateway's own for the
    /// gateway
    func place(gatewayName: String) -> String {
        switch self {
        case .gateway: gatewayName
        case let .machine(_, name): name
        }
    }

    /// The machine a link or push names by its endpoint id; none names the
    /// gateway. A link carries no name, so the id's start shows until the
    /// gateway's listing names it
    init(machineId: String?, name: String?) {
        guard let machineId, !machineId.isEmpty else {
            self = .gateway
            return
        }
        let name = name.flatMap { $0.isEmpty ? nil : $0 } ?? String(machineId.prefix(10))
        self = .machine(id: machineId, name: name)
    }

    /// Tells hosts apart in an identity, a machine by its endpoint id,
    /// since two machines may share a name; an id never has `/`
    var key: String {
        switch self {
        case .gateway: ""
        case let .machine(id, _): "machine:\(id)"
        }
    }
}

extension MachineSessions {
    /// The machine's name, with the start of its endpoint id when another
    /// of `machines` shares the name, so the owner can tell them apart
    func label(among machines: [MachineSessions]) -> String {
        let shared = machines.contains { $0.id != id && $0.name == name }
        return shared ? "\(name) (\(id.prefix(10)))" : name
    }
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

/// Names a session, the machine it runs on and the https address it starts
/// at. A saved session launches with its profile, so a site it signed in to
/// before still is
struct NewSessionSheet: View {
    @Environment(\.dismiss) private var dismiss
    let gatewayName: String
    /// The machines besides the gateway New session can start on
    let machines: [MachineSessions]
    /// Whether the owner may pick the machine
    let movable: Bool
    let onStart: (String, String, SessionHost) -> Void

    @State private var name: String
    @State private var host: SessionHost
    @State private var address = ""
    @FocusState private var focused: Field?

    private enum Field {
        case name, address
    }

    init(
        session: NewSession,
        gatewayName: String,
        machines: [MachineSessions],
        onStart: @escaping (String, String, SessionHost) -> Void
    ) {
        _name = State(initialValue: session.name)
        _host = State(initialValue: session.host)
        movable = session.movable
        self.gatewayName = gatewayName
        self.machines = machines
        self.onStart = onStart
    }

    var body: some View {
        NavigationStack {
            Form {
                if movable, !machines.isEmpty {
                    Section {
                        Picker("Runs on", selection: $host) {
                            Text(gatewayName).tag(SessionHost.gateway)
                            ForEach(machines, id: \.id) { machine in
                                Text(machine.label(among: machines))
                                    .tag(SessionHost.machine(id: machine.id, name: machine.name))
                            }
                        }
                    }
                }
                Section {
                    TextField("Name, such as github", text: $name)
                        .focused($focused, equals: .name)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.next)
                        .onSubmit { focused = .address }
                        .onChange(of: name) { _, typed in
                            let fixed = Self.sessionName(typed)
                            if fixed != typed { name = fixed }
                        }
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
        "Opens in the browser on \(host.place(gatewayName: gatewayName)), with the session's saved sign-ins when it has some."
    }

    /// The address as `https`, which is all a session starts at
    private var url: String? {
        httpsAddress(address)
    }

    /// Matches the gateway's session names, so it never refuses one here
    private static func valid(name: String) -> Bool {
        (1 ... 64).contains(name.count)
            && name.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_") }
    }

    /// The typed name with each character a session name can't hold made
    /// `-`, such as `github.com` to `github-com`, so Start never stays off
    /// for a reason the field hides
    private static func sessionName(_ typed: String) -> String {
        let scalars = typed.unicodeScalars.prefix(64).map { scalar -> Character in
            let allowed = scalar.isASCII
                && (CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == "_")
            return allowed ? Character(scalar) : "-"
        }
        return String(scalars)
    }

    private func start() {
        guard Self.valid(name: name), let url else { return }
        onStart(name, url, host)
        dismiss()
    }
}

/// An address the owner typed as `https`, with the scheme added when they
/// left it out, such as `github.com/login`; nil for any other scheme or no
/// host, which the gateway would refuse
func httpsAddress(_ typed: String) -> String? {
    let typed = typed.trimmingCharacters(in: .whitespaces)
    let full = typed.contains("://") ? typed : "https://\(typed)"
    guard let url = URL(string: full), url.scheme == "https", url.host() != nil else { return nil }
    return url.absoluteString
}
