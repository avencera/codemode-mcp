import CompanionCore
import SwiftUI

/// One read: what it is for, how long the gateway waits, and the answers:
/// Face ID opens the copy the gateway sealed to this phone, or the owner
/// pastes or fills in the value when there is no copy or it is stale. A
/// program read lists every item it asks for and sends them together; a
/// described item may instead take a file shared from 1Password
struct RequestView: View {
    @Environment(AppManager.self) private var manager
    @Environment(\.scenePhase) private var scenePhase
    let read: PendingRead
    @State private var entering = false
    @State private var value = ""
    /// A program read's entered values, by item index
    @State private var values: [Int: String] = [:]
    /// A program read's sealed items the owner enters instead
    @State private var replacing: Set<Int> = []
    /// Files shared from 1Password for described items, by item index
    @State private var attached: [Int: SharedInbox.File] = [:]
    /// The described item the owner went to 1Password for, and when
    @State private var fetching: (index: Int, since: Date)?
    /// Why the last shared file was not attached
    @State private var attachError: String?
    /// Each button waits a moment after it appears: Approve and Done take
    /// each other's place, so a tap meant for one must not land on the
    /// next, and a result stays readable before it can be dismissed
    @State private var armed = false

    var body: some View {
        Group {
            if let program = read.program {
                programBody(program)
            } else {
                singleBody
            }
        }
        // a program read's items arrive after its push placeholder, so the
        // buttons arm again then
        .task(id: "\(read.id) \(read.status.isFinished) \(read.program?.items.count ?? -1)") {
            // a new read, or one that just finished, starts with no value
            armed = false
            value = ""
            values = [:]
            replacing = []
            entering = false
            // a finished read takes no file, so what it was shared is gone
            if read.status.isFinished {
                for file in attached.values { SharedInbox.remove(file) }
                attached = [:]
                fetching = nil
            }
            try? await Task.sleep(for: .seconds(1.5))
            armed = true
        }
        // back from 1Password's share sheet: attach what it shared
        .onChange(of: scenePhase, initial: true) { _, phase in
            if phase == .active { attachShared() }
        }
        .navigationTitle(read.program == nil ? "Approve a read" : "Approve a program's read")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: One read

    private var singleBody: some View {
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
    }

    @ViewBuilder
    private var actions: some View {
        if read.status.isFinished {
            done
        } else {
            VStack(spacing: 12) {
                // opened from a push: whether a copy came is not known yet
                if read.status == .connecting {
                    EmptyView()
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

                deny
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

    // MARK: A program's read

    private func programBody(_ program: ProgramRead) -> some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: read.status.isFinished ? icon : "terminal.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(tint)
                VStack(spacing: 8) {
                    Text(programHeadline(program))
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    if let destination = program.destination {
                        // always whole: a cut path or command could hide
                        // where the values really go
                        Text("Into \(destination)")
                            .font(.system(.callout, design: .monospaced))
                            .fixedSize(horizontal: false, vertical: true)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                    }
                    Text("Approving sends the values to a program running on \(read.gatewayName), not to codemode-mcp itself.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                if let keep = program.keepSecs {
                    let minutes = keepMinutes(keep)
                    Label(
                        "Programs on \(read.gatewayName) may get these again\(program.destination == nil ? "" : " for the same destination") for \(minutes) \(minutes == 1 ? "minute" : "minutes") without asking.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.leading)
                }
                if let reason = program.reason {
                    VStack(spacing: 4) {
                        Text("The program says")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("“\(reason)”")
                            .italic()
                            .multilineTextAlignment(.center)
                    }
                }
                if program.items.isEmpty {
                    // opened from a push: only its summary is known yet
                    Text(read.reference)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                } else {
                    VStack(spacing: 10) {
                        ForEach(Array(program.items.enumerated()), id: \.offset) { index, item in
                            itemRow(index: index, item: item)
                        }
                    }
                }
                status
                programActions(program)
            }
            .padding(24)
        }
    }

    private func programHeadline(_ program: ProgramRead) -> String {
        switch program.items.count {
        case 0: "A program on \(read.gatewayName) wants values from 1Password"
        case 1: "A program on \(read.gatewayName) wants 1 value from 1Password"
        case let count: "A program on \(read.gatewayName) wants \(count) values from 1Password"
        }
    }

    private func itemRow(index: Int, item: ProgramItem) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            switch item {
            case let .reference(reference, sealed):
                Text(reference)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                if sealed && !replacing.contains(index) {
                    HStack {
                        Label("Opens with Face ID", systemImage: "faceid")
                            .foregroundStyle(.secondary)
                        Spacer()
                        if !read.status.isFinished {
                            Button("Enter a different value") { replacing.insert(index) }
                                .disabled(read.status != .waiting)
                        }
                    }
                    .font(.caption)
                } else {
                    if !sealed {
                        Text("No copy on this iPhone yet. Paste it, or fill it in from your password manager.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if !read.status.isFinished {
                        field(index: index)
                    }
                }
            case let .describe(description):
                Text("“\(description)”")
                    .italic()
                if let file = attached[index] {
                    attachedRow(index: index, file: file)
                } else {
                    Label("Pick in 1Password", systemImage: "hand.point.up.left")
                        .font(.caption)
                        .foregroundStyle(.orange)
                    if !read.status.isFinished {
                        field(index: index)
                        fileButton(index: index)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    /// One item's value field, filled through AutoFill or pasted
    private func field(index: Int) -> some View {
        HStack {
            SecureField("Value", text: Binding(
                get: { values[index] ?? "" },
                set: { values[index] = $0 }
            ))
            .textContentType(.password)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .privacySensitive()
            .textFieldStyle(.roundedBorder)
            PasteButton(payloadType: String.self) { strings in
                let pasted = strings.first ?? ""
                DispatchQueue.main.async { values[index] = pasted }
            }
            .labelStyle(.iconOnly)
        }
    }

    /// For a file: send the owner to 1Password's share sheet, and take what
    /// it shares when the app comes back
    @ViewBuilder
    private func fileButton(index: Int) -> some View {
        if fetching?.index == index {
            Text("In 1Password, open the item, tap the file, tap Share and choose CMCP Companion. Then come back here.")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            Button {
                fetching = (index, Date())
                attachError = nil
            } label: {
                Label("Attach a file from 1Password", systemImage: "paperclip")
            }
            .font(.caption)
            .disabled(read.status != .waiting)
        }
        if let attachError, fetching?.index == index {
            Text(attachError)
                .font(.caption)
                .foregroundStyle(.red)
        }
    }

    private func attachedRow(index: Int, file: SharedInbox.File) -> some View {
        HStack {
            Label(file.name, systemImage: "doc.fill")
                .lineLimit(1)
                .truncationMode(.middle)
            Text(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file))
                .foregroundStyle(.secondary)
            Spacer()
            if !read.status.isFinished {
                Button {
                    SharedInbox.remove(file)
                    attached[index] = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .accessibilityLabel("Remove the file")
            }
        }
        .font(.caption)
    }

    /// Attaches the newest shared file to the described item the owner went
    /// to fetch it for, or to the only described item still empty; a file
    /// shared before the read showed belongs to some other read
    private func attachShared() {
        guard let program = read.program, read.status == .waiting,
              let file = SharedInbox.latest(),
              !attached.values.contains(file)
        else { return }
        let open = program.items.indices.filter { index in
            if case .describe = program.items[index] {
                return attached[index] == nil && (values[index] ?? "").isEmpty
            }
            return false
        }
        let since = fetching?.since ?? Date(timeIntervalSince1970: Double(read.expiresAtMs) / 1000 - SharedInbox.lifetime)
        guard file.received >= since,
              let index = fetching.map(\.index).flatMap({ open.contains($0) ? $0 : nil })
              ?? (open.count == 1 ? open.first : nil)
        else { return }

        if file.size == 0 {
            SharedInbox.remove(file)
            attachError = "\(file.name) is empty; share the file again."
            return
        }
        if file.size > Int(maxFileBytes()) {
            SharedInbox.remove(file)
            attachError = "\(file.name) is \(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file)); at most \(ByteCountFormatter.string(fromByteCount: Int64(maxFileBytes()), countStyle: .file)) can be sent."
            return
        }
        attached[index] = file
        fetching = nil
        attachError = nil
    }

    /// Whether the owner enters item `index` rather than Face ID opening it
    private func entersValue(index: Int, item: ProgramItem) -> Bool {
        switch item {
        case let .reference(_, sealed): !sealed || replacing.contains(index)
        case .describe: true
        }
    }

    @ViewBuilder
    private func programActions(_ program: ProgramRead) -> some View {
        if read.status.isFinished {
            done
        } else {
            let entered = program.items.indices.filter { entersValue(index: $0, item: program.items[$0]) }
            let complete = entered.allSatisfy { !(values[$0] ?? "").isEmpty || attached[$0] != nil }
            let faceID = entered.count < program.items.count
            VStack(spacing: 12) {
                if !program.items.isEmpty {
                    Button {
                        sendProgram(entered: entered)
                    } label: {
                        Label(
                            faceID ? "Approve with Face ID and send" : "Send \(program.items.count == 1 ? "value" : "values")",
                            systemImage: faceID ? "faceid" : "paperplane"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(read.status != .waiting || !armed || !complete)
                }
                deny
            }
        }
    }

    private func sendProgram(entered: [Int]) {
        guard armed, read.status == .waiting else { return }
        var answer: [UInt32: EnteredValue] = [:]
        for index in entered {
            if let file = attached[index] {
                guard let bytes = SharedInbox.bytes(of: file) else {
                    attached[index] = nil
                    attachError = "\(file.name) is gone; share it again."
                    fetching = (index, Date())
                    return
                }
                answer[UInt32(index)] = .file(bytes: bytes)
            } else {
                answer[UInt32(index)] = .text(value: values[index] ?? "")
            }
        }
        manager.answerProgram(id: read.id, entered: answer)
        // the core holds the bytes now; the shared copies are not kept
        for file in attached.values { SharedInbox.remove(file) }
        attached = [:]
    }

    // MARK: Shared

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
            Text(read.program == nil ? "Sent to the gateway." : "Sent to the program on \(read.gatewayName).")
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

    private var done: some View {
        Button("Done") { manager.dispatch(.dismiss(id: read.id)) }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!armed)
    }

    private var deny: some View {
        Button(role: .destructive) {
            manager.dispatch(.deny(id: read.id))
        } label: {
            Text("Deny").frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
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
