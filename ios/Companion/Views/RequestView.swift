import CompanionCore
import SwiftUI

/// One read: what it is for, how long the gateway waits, and the answers:
/// Face ID opens the copy the gateway sealed to this phone, or the owner
/// pastes or fills in the value when there is no copy or it is stale. A
/// program read lists every item it asks for and sends them together
struct RequestView: View {
    @Environment(AppManager.self) private var manager
    let read: PendingRead
    @State private var entering = false
    @State private var value = ""
    /// A program read's entered values, by item index
    @State private var values: [Int: String] = [:]
    /// A program read's sealed items the owner enters instead
    @State private var replacing: Set<Int> = []
    /// Whether a long destination shows in full
    @State private var expanded = false
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
            expanded = false
            entering = false
            try? await Task.sleep(for: .seconds(1.5))
            armed = true
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
                        Text("Into \(destination)")
                            .font(.system(.callout, design: .monospaced))
                            .lineLimit(expanded ? nil : 2)
                            .truncationMode(.middle)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .onTapGesture { expanded.toggle() }
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
                Label("Pick in 1Password", systemImage: "hand.point.up.left")
                    .font(.caption)
                    .foregroundStyle(.orange)
                if !read.status.isFinished {
                    field(index: index)
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
            let complete = entered.allSatisfy { !(values[$0] ?? "").isEmpty }
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
        var answer: [UInt32: String] = [:]
        for index in entered {
            answer[UInt32(index)] = values[index] ?? ""
        }
        manager.answerProgram(id: read.id, entered: answer)
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
