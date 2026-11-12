import CompanionCore
import SwiftUI
import UIKit

/// A browser session on the gateway Mac, live on this phone: the page as an
/// image the owner taps, scrolls and types into, a key bar, Fill from
/// 1Password, and for a handoff Done or Cancel to hand the session back to
/// the agent.
/// Pinching zooms the picture on this phone only
struct TakeoverView: View {
    @Environment(AppManager.self) private var manager
    @Environment(\.displayScale) private var displayScale
    let takeover: TakeoverState

    /// The picture's zoom on this phone, from 1 (fit) up
    @State private var zoom: CGFloat = 1
    /// The zoomed picture's offset from the middle, in points
    @State private var pan: CGSize = .zero
    /// The image area's size, in points
    @State private var area: CGSize = .zero
    /// Whether the keyboard is up for the page's focused field
    @State private var keyboardUp = false
    /// The login field Fill from 1Password asks a value for, while its sheet
    /// is up
    @State private var filling: LoginField?
    /// The area's size waits a moment before it goes, so a keyboard sliding
    /// in lays the page out once
    @State private var resizing: Task<Void, Never>?

    /// Most the picture zooms
    private static let maxZoom: CGFloat = 5
    /// Most pixels per point the gateway draws at: a 3x screen's own, since
    /// page text at 2x reads as blurry
    private static let maxScale: CGFloat = 3

    var body: some View {
        VStack(spacing: 0) {
            header
            GeometryReader { geometry in
                ZStack {
                    Color(.secondarySystemBackground)
                    if let screen = manager.screen {
                        Image(uiImage: screen.image)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: geometry.size.width, height: geometry.size.height)
                            .scaleEffect(zoom)
                            .offset(pan)
                    }
                    TakeoverSurface(
                        onTap: { tap($0) },
                        onLongPress: { longPress($0) },
                        // in a text field a long press offers Paste, as it
                        // would on the phone, instead of a right click
                        pastes: { takeover.page?.focus?.editable == true },
                        onPaste: { manager.takeoverText($0) },
                        onScroll: { scroll(at: $0, by: $1) },
                        onZoom: { zoom(by: $0, moving: $1) }
                    )
                    linkOverlay
                }
                .clipped()
                .onChange(of: geometry.size, initial: true) { _, size in
                    area = size
                    resize()
                }
            }
            notice
            keyBar
            // Done and Cancel answer a handoff; a session taken over from
            // the list has none, and Sessions leaves it
            if !keyboardUp, takeover.handoff != nil {
                actions
            }
        }
        .background {
            // the page's keyboard: invisible, it only takes what is typed
            KeyCatcher(
                focus: takeover.page?.focus,
                active: keyboardUp && takeover.status == .live,
                onText: { manager.takeoverText($0) },
                onFill: { manager.takeoverFill(field: $0, value: $1, submit: false) },
                onKey: { manager.takeover(.key(key: $0)) }
            )
            .frame(width: 1, height: 1)
            .opacity(0.01)
            .allowsHitTesting(false)
        }
        .onChange(of: takeover.page?.focus, initial: true) { _, focus in
            // the keyboard follows the page's focus; the owner can still put
            // it away with the key bar
            keyboardUp = focus?.editable == true
        }
        .sheet(item: $filling) { field in
            FillSheet(field: field, site: takeover.page.flatMap { URL(string: $0.url)?.host() }) { value in
                manager.takeoverFill(field: field, value: value, submit: false)
            }
        }
        .navigationTitle(takeover.session)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                // leaves without ending anything, for the session list, where
                // this session or its handoff can be taken over again
                Button {
                    manager.dispatch(.closeTakeover)
                    manager.browse()
                } label: {
                    Label("Sessions", systemImage: "chevron.backward")
                        .labelStyle(.titleAndIcon)
                }
            }
        }
    }

    // MARK: Parts

    private var header: some View {
        VStack(spacing: 2) {
            if let page = takeover.page {
                Text(page.url)
                    .font(.system(.footnote, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                if let focus = page.focus, focus.crossSite {
                    Label("The focused field is in a frame from \(focus.origin)", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            } else {
                Text("Opening \(takeover.session)…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
    }

    /// What the link is doing, over the picture, while it is not live
    @ViewBuilder
    private var linkOverlay: some View {
        switch takeover.status {
        case .live:
            EmptyView()
        case .connecting:
            overlayCard {
                ProgressView()
                Text("Connecting to \(takeover.session)…")
            }
        case let .retrying(inSecs, error):
            overlayCard {
                ProgressView()
                Text("Reconnecting in \(inSecs) s")
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .paused:
            overlayCard {
                Text("Paused while the app was in the background")
            }
        case let .ended(reason, message):
            overlayCard {
                Image(systemName: "stop.circle")
                    .font(.largeTitle)
                Text(endText(reason))
                if let message {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button("Close") { manager.dispatch(.closeTakeover) }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private func overlayCard(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(spacing: 10, content: content)
            .multilineTextAlignment(.center)
            .padding(20)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
            .padding(24)
    }

    @ViewBuilder
    private var notice: some View {
        switch takeover.notice {
        case let .refused(message):
            Label(message, systemImage: "exclamationmark.circle.fill")
                .font(.footnote)
                .foregroundStyle(.red)
                .padding(.horizontal, 16)
                .padding(.top, 6)
        case let .filled(field):
            Label("Filled the \(field.label.lowercased())", systemImage: "checkmark.circle.fill")
                .font(.footnote)
                .foregroundStyle(.green)
                .padding(.horizontal, 16)
                .padding(.top, 6)
        case nil:
            EmptyView()
        }
    }

    /// Keys the phone's keyboard lacks, the page's history, Fill from
    /// 1Password, and the keyboard itself
    private var keyBar: some View {
        let live = takeover.status == .live
        return VStack(spacing: 8) {
            if let fill = fillAction {
                Button(action: fill.action) {
                    Label(fill.title, systemImage: "key.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(!live)
            }
            HStack(spacing: 6) {
                keyButton("chevron.backward", "Back") { manager.takeover(.back) }
                keyButton("arrow.clockwise", "Reload") { manager.takeover(.reload) }
                keyButton("escape", "Escape") { manager.takeover(.key(key: .escape)) }
                keyButton("arrow.left.to.line", "Shift-Tab") { manager.takeover(.key(key: .shiftTab)) }
                keyButton("arrow.right.to.line", "Tab") { manager.takeover(.key(key: .tab)) }
                keyButton("delete.left", "Backspace") { manager.takeover(.key(key: .backspace)) }
                keyButton("return", "Enter") { manager.takeover(.key(key: .enter)) }
                keyButton(keyboardUp ? "keyboard.chevron.compact.down" : "keyboard", keyboardUp ? "Hide keyboard" : "Show keyboard") {
                    keyboardUp.toggle()
                }
            }
            .disabled(!live)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func keyButton(_ symbol: String, _ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .frame(maxWidth: .infinity, minHeight: 28)
        }
        .buttonStyle(.bordered)
        .accessibilityLabel(label)
    }

    /// Fill from 1Password for a focused login field: the gateway's sealed
    /// copy when it sent one, opened with Face ID; otherwise a sheet whose
    /// field AutoFill fills from 1Password. Only a login field shows it, as
    /// the gateway fills no other
    private var fillAction: (title: String, action: () -> Void)? {
        guard let page = takeover.page, let focus = page.focus, focus.editable,
              let field = focus.field
        else { return nil }
        if let offer = page.offers.first(where: { $0.field == field }) {
            let account = offer.account.map { " (\($0))" } ?? ""
            return ("Fill \(field.label.lowercased()) from \(offer.item)\(account)", {
                manager.takeover(.fillOffer(reference: offer.reference))
            })
        }
        return ("Fill \(field.label.lowercased()) from 1Password", {
            // the sheet's field takes the keyboard; the page's comes back
            // with the next focus
            keyboardUp = false
            filling = field
        })
    }

    private var actions: some View {
        let live = takeover.status == .live
        return HStack(spacing: 12) {
            Button(role: .destructive) {
                manager.takeover(.cancel)
            } label: {
                Text("Cancel").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            Button {
                manager.takeover(.done)
            } label: {
                Label("Done", systemImage: "checkmark")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
        }
        .controlSize(.large)
        .disabled(!live)
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }

    private func endText(_ reason: TakeoverEnd) -> String {
        switch reason {
        case .done: "Done."
        case .cancelled: "Cancelled."
        case .handoffOver: "The handoff is over: another device answered, the agent stopped waiting, or it expired."
        case .browserGone: "The browser session closed or could not be reached."
        case .shutdown: "The gateway is stopping."
        case .failed: "This iPhone could not keep the takeover going."
        }
    }

    // MARK: Gestures

    /// The picture's size at zoom 1 and where it sits in the area
    private var fitted: CGRect? {
        guard let image = manager.screen?.image, image.size.width > 0, image.size.height > 0,
              area.width > 0, area.height > 0
        else { return nil }
        let fit = min(area.width / image.size.width, area.height / image.size.height)
        let size = CGSize(width: image.size.width * fit, height: image.size.height * fit)
        return CGRect(
            origin: CGPoint(x: (area.width - size.width) / 2, y: (area.height - size.height) / 2),
            size: size
        )
    }

    /// Where `point` in the area falls on the image, as fractions of its
    /// width and height, undoing the phone's own zoom; `nil` off the image
    private func fraction(_ point: CGPoint) -> CGPoint? {
        guard let fitted else { return nil }
        let center = CGPoint(x: area.width / 2, y: area.height / 2)
        let unzoomed = CGPoint(
            x: center.x + (point.x - center.x - pan.width) / zoom,
            y: center.y + (point.y - center.y - pan.height) / zoom
        )
        let x = (unzoomed.x - fitted.minX) / fitted.width
        let y = (unzoomed.y - fitted.minY) / fitted.height
        guard (0 ... 1).contains(x), (0 ... 1).contains(y) else { return nil }
        return CGPoint(x: x, y: y)
    }

    private func tap(_ point: CGPoint) {
        guard let seq = manager.screen?.seq, let at = fraction(point) else { return }
        manager.takeover(.tap(x: at.x, y: at.y, seq: seq))
    }

    private func longPress(_ point: CGPoint) {
        guard let seq = manager.screen?.seq, let at = fraction(point) else { return }
        manager.takeover(.longPress(x: at.x, y: at.y, seq: seq))
    }

    /// A one-finger drag scrolls the page under it: dragging up scrolls the
    /// page down, as a scroll view does
    private func scroll(at point: CGPoint, by drag: CGSize) {
        guard let seq = manager.screen?.seq, let fitted, let at = fraction(point) else { return }
        let dx = -drag.width / (fitted.width * zoom)
        let dy = -drag.height / (fitted.height * zoom)
        manager.takeover(.scroll(x: at.x, y: at.y, dx: dx, dy: dy, seq: seq))
    }

    /// Pinching and two-finger panning move the picture on this phone only
    private func zoom(by scale: CGFloat, moving drag: CGSize) {
        zoom = min(max(zoom * scale, 1), Self.maxZoom)
        // the picture may move only as far as its zoom lets it overhang
        let reach = CGSize(width: area.width * (zoom - 1) / 2, height: area.height * (zoom - 1) / 2)
        pan = CGSize(
            width: min(max(pan.width + drag.width, -reach.width), reach.width),
            height: min(max(pan.height + drag.height, -reach.height), reach.height)
        )
    }

    private func resize() {
        resizing?.cancel()
        let size = area
        let scale = Double(min(displayScale, Self.maxScale))
        resizing = Task {
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled, size.width >= 1, size.height >= 1 else { return }
            manager.takeover(.resize(
                width: UInt32(size.width.rounded()),
                height: UInt32(size.height.rounded()),
                scale: scale
            ))
        }
    }
}

/// The picture's touch surface, in UIKit for what SwiftUI's gestures do not
/// give: where a long press landed, a one-finger drag apart from a
/// two-finger one, and both at once with a pinch
struct TakeoverSurface: UIViewRepresentable {
    let onTap: (CGPoint) -> Void
    let onLongPress: (CGPoint) -> Void
    /// Whether a long press offers Paste rather than pressing the page
    let pastes: () -> Bool
    /// Text from the clipboard, for the page's focused field
    let onPaste: (String) -> Void
    /// Where the drag started, and how far it moved since the last call
    let onScroll: (CGPoint, CGSize) -> Void
    /// How much the pinch scaled and the two fingers moved since the last
    /// call
    let onZoom: (CGFloat, CGSize) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.backgroundColor = .clear
        let coordinator = context.coordinator

        let tap = UITapGestureRecognizer(target: coordinator, action: #selector(Coordinator.tapped(_:)))
        let press = UILongPressGestureRecognizer(target: coordinator, action: #selector(Coordinator.pressed(_:)))
        let drag = UIPanGestureRecognizer(target: coordinator, action: #selector(Coordinator.dragged(_:)))
        drag.maximumNumberOfTouches = 1
        let pinch = UIPinchGestureRecognizer(target: coordinator, action: #selector(Coordinator.pinched(_:)))
        let twoFingers = UIPanGestureRecognizer(target: coordinator, action: #selector(Coordinator.panned(_:)))
        twoFingers.minimumNumberOfTouches = 2
        for recognizer in [tap, press, drag, pinch, twoFingers] {
            recognizer.delegate = coordinator
            view.addGestureRecognizer(recognizer)
        }
        coordinator.zooming = [pinch, twoFingers]
        let menu = UIEditMenuInteraction(delegate: coordinator)
        view.addInteraction(menu)
        coordinator.menu = menu

        return view
    }

    func updateUIView(_: UIView, context: Context) {
        context.coordinator.parent = self
    }

    final class Coordinator: NSObject, UIGestureRecognizerDelegate, UIEditMenuInteractionDelegate {
        var parent: TakeoverSurface
        var zooming: [UIGestureRecognizer] = []
        var menu: UIEditMenuInteraction?
        /// Where the current drag started
        private var start: CGPoint = .zero
        /// Drag not yet sent; drags go at most this often, so a fast swipe
        /// does not flood the link
        private var pending: CGSize = .zero
        private var sentAt: CFTimeInterval = 0
        private static let interval: CFTimeInterval = 1.0 / 30

        init(_ parent: TakeoverSurface) {
            self.parent = parent
        }

        @objc func tapped(_ recognizer: UITapGestureRecognizer) {
            parent.onTap(recognizer.location(in: recognizer.view))
        }

        @objc func pressed(_ recognizer: UILongPressGestureRecognizer) {
            guard recognizer.state == .began else { return }
            let point = recognizer.location(in: recognizer.view)
            if parent.pastes(), let menu {
                menu.presentEditMenu(with: UIEditMenuConfiguration(identifier: nil, sourcePoint: point))
                return
            }
            parent.onLongPress(point)
        }

        func editMenuInteraction(
            _: UIEditMenuInteraction,
            menuFor _: UIEditMenuConfiguration,
            suggestedActions _: [UIMenuElement]
        ) -> UIMenu? {
            let paste = UIAction(title: "Paste", image: UIImage(systemName: "doc.on.clipboard")) { [weak self] _ in
                // read only when chosen, so iOS asks to allow it then
                guard let text = UIPasteboard.general.string, !text.isEmpty else { return }
                self?.parent.onPaste(text)
            }
            return UIMenu(children: [paste])
        }

        @objc func dragged(_ recognizer: UIPanGestureRecognizer) {
            switch recognizer.state {
            case .began:
                start = recognizer.location(in: recognizer.view)
                pending = .zero
                fallthrough
            case .changed, .ended:
                let moved = recognizer.translation(in: recognizer.view)
                recognizer.setTranslation(.zero, in: recognizer.view)
                pending.width += moved.x
                pending.height += moved.y
                let now = CACurrentMediaTime()
                let due = now - sentAt >= Self.interval || recognizer.state == .ended
                guard due, pending != .zero else { return }
                parent.onScroll(start, pending)
                pending = .zero
                sentAt = now
            default:
                pending = .zero
            }
        }

        @objc func pinched(_ recognizer: UIPinchGestureRecognizer) {
            guard recognizer.state == .changed else { return }
            parent.onZoom(recognizer.scale, .zero)
            recognizer.scale = 1
        }

        @objc func panned(_ recognizer: UIPanGestureRecognizer) {
            guard recognizer.state == .changed else { return }
            let moved = recognizer.translation(in: recognizer.view)
            recognizer.setTranslation(.zero, in: recognizer.view)
            parent.onZoom(1, CGSize(width: moved.x, height: moved.y))
        }

        /// A pinch and a two-finger pan go together; nothing else does
        func gestureRecognizer(
            _ recognizer: UIGestureRecognizer,
            shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer
        ) -> Bool {
            zooming.contains(recognizer) && zooming.contains(other)
        }
    }
}

/// An invisible text field that raises the keyboard for the page's focused
/// element and sends what is typed at once, keeping none of it: each
/// character goes as text, a whole value AutoFill puts in at once as a fill
/// of the login field the keyboard was set up for, and delete and return as
/// keys
struct KeyCatcher: UIViewRepresentable {
    let focus: TakeoverFocus?
    let active: Bool
    let onText: (String) -> Void
    let onFill: (LoginField, String) -> Void
    let onKey: (TakeoverKey) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> CatcherField {
        let field = CatcherField()
        field.delegate = context.coordinator
        field.autocorrectionType = .no
        field.autocapitalizationType = .none
        field.spellCheckingType = .no
        field.smartQuotesType = .no
        field.smartDashesType = .no
        field.smartInsertDeleteType = .no
        field.addTarget(context.coordinator, action: #selector(Coordinator.changed(_:)), for: .editingChanged)
        let coordinator = context.coordinator
        field.onBackspace = { [weak coordinator] in coordinator?.parent.onKey(.backspace) }
        return field
    }

    func updateUIView(_ field: CatcherField, context: Context) {
        context.coordinator.parent = self
        configure(field)
        if active, !field.isFirstResponder {
            DispatchQueue.main.async { field.becomeFirstResponder() }
        } else if !active, field.isFirstResponder {
            DispatchQueue.main.async { field.resignFirstResponder() }
        }
    }

    /// Matches the keyboard and AutoFill to the focused element
    private func configure(_ field: CatcherField) {
        let contentType: UITextContentType? = switch focus?.field {
        case .username: .username
        case .password: .password
        case .code: .oneTimeCode
        case nil: nil
        }
        let secure = focus?.secure == true
        let keyboard: UIKeyboardType = focus?.numeric == true || focus?.field == .code ? .numberPad : .default
        guard field.textContentType != contentType || field.isSecureTextEntry != secure
            || field.keyboardType != keyboard
        else { return }
        field.textContentType = contentType
        field.isSecureTextEntry = secure
        field.keyboardType = keyboard
        if field.isFirstResponder { field.reloadInputViews() }
    }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var parent: KeyCatcher

        init(_ parent: KeyCatcher) {
            self.parent = parent
        }

        func textField(
            _ field: UITextField,
            shouldChangeCharactersIn _: NSRange,
            replacementString string: String
        ) -> Bool {
            // the field is always empty, so deleting comes through
            // `deleteBackward` and return through `textFieldShouldReturn`
            if !string.isEmpty, string != "\n" { send(string, from: field) }
            return false
        }

        func textFieldShouldReturn(_: UITextField) -> Bool {
            parent.onKey(.enter)
            return false
        }

        /// AutoFill may set the whole value without asking the delegate
        @objc func changed(_ field: UITextField) {
            guard let text = field.text, !text.isEmpty else { return }
            field.text = ""
            send(text, from: field)
        }

        /// A whole value goes as a fill of the field the keyboard was set up
        /// for, which is what AutoFill picked it for. The page's focus can
        /// have moved on before the phone hears of it, and labelled by that
        /// a username could go into a password field; labelled this way,
        /// the gateway refuses it unless that field is still focused
        private func send(_ text: String, from field: UITextField) {
            if text.count > 1, let login = Self.login(field.textContentType) {
                parent.onFill(login, text)
            } else {
                parent.onText(text)
            }
        }

        private static func login(_ contentType: UITextContentType?) -> LoginField? {
            switch contentType {
            case .username?: .username
            case .password?: .password
            case .oneTimeCode?: .code
            default: nil
            }
        }
    }
}

/// A visible field for one login value, which AutoFill fills from 1Password
/// as it would a sign-in form: the key catcher is hidden, and AutoFill offers
/// less for a field it cannot see. Fill sends the value as a fill of the
/// page's focused field, which the gateway checks is still that kind
struct FillSheet: View {
    @Environment(\.dismiss) private var dismiss
    let field: LoginField
    let site: String?
    let onFill: (String) -> Void

    @State private var value = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ValueField(field: field, text: $value)
                        .focused($focused)
                        .onSubmit(fill)
                } footer: {
                    Text("Pick the login\(site.map { " for \($0)" } ?? "") from the AutoFill bar above the keyboard, or its key icon")
                }
            }
            .navigationTitle("Fill \(field.label.lowercased())")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Fill", action: fill)
                        .disabled(value.isEmpty)
                }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium])
    }

    private func fill() {
        guard !value.isEmpty else { return }
        onFill(value)
        value = ""
        dismiss()
    }
}

extension LoginField: @retroactive Identifiable {
    public var id: Self { self }
}

/// The key catcher's field, which also reports delete on an empty field
final class CatcherField: UITextField {
    var onBackspace: (() -> Void)?

    override func deleteBackward() {
        onBackspace?()
    }
}
